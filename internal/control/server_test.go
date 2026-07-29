package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type blockingMasterFrameSender struct {
	ctx     context.Context
	started chan struct{}
}

func (s *blockingMasterFrameSender) Context() context.Context {
	return s.ctx
}

func (s *blockingMasterFrameSender) Send(*controlv1.MasterFrame) error {
	select {
	case <-s.started:
	default:
		close(s.started)
	}
	<-s.ctx.Done()
	return s.ctx.Err()
}

func TestAuthorizedSendStopsWaitingImmediatelyAfterRevocation(t *testing.T) {
	streamContext, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()
	stream := &blockingMasterFrameSender{
		ctx:     streamContext,
		started: make(chan struct{}),
	}
	outgoing := make(chan *controlv1.MasterFrame)
	results := make(chan error, 1)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		sendMasterFrames(stream, outgoing, results)
	}()

	authorizationDone := make(chan struct{})
	sendResult := make(chan error, 1)
	go func() {
		sendResult <- sendAuthorizedMasterFrame(
			streamContext,
			authorizationDone,
			outgoing,
			results,
			&controlv1.MasterFrame{},
		)
	}()
	select {
	case <-stream.started:
	case <-time.After(time.Second):
		t.Fatal("writer did not begin the blocked send")
	}

	close(authorizationDone)
	select {
	case err := <-sendResult:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("send error = %v, want Unauthenticated", err)
		}
	case <-time.After(time.Second):
		t.Fatal("authorized send remained blocked after revocation")
	}
	cancelStream()
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("writer did not stop after stream cancellation")
	}
}

type recordingNotifier struct {
	events []deployment.Event
}

func (n *recordingNotifier) Notify(_ context.Context, event deployment.Event) error {
	n.events = append(n.events, event)
	return nil
}

func newTestServer(store deployment.Store, notifier deployment.Notifier) *Server {
	return NewServer(
		identity.NewRegistry(),
		store,
		nil,
		notifier,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

func TestQueueValidationRecordsOfflineDeliveryFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	notifier := &recordingNotifier{}
	server := newTestServer(store, notifier)

	record, err := server.QueueValidation(
		ctx,
		"offline-agent",
		"deployment-offline",
		"revision-1",
		[]byte(`{}`),
		time.Second,
	)
	if err == nil {
		t.Fatal("expected an offline delivery error")
	}
	if record.Status != deployment.StatusDeliveryFailed {
		t.Fatalf("got status %q", record.Status)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("got %d notifications", len(notifier.events))
	}
}

func TestLatestDeploymentExpiresMissingAgentReport(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	notifier := &recordingNotifier{}
	server := newTestServer(store, notifier)
	queuedAt := time.Date(2026, time.July, 27, 8, 0, 0, 0, time.UTC)
	server.Now = func() time.Time {
		return queuedAt.Add(DeploymentReportGrace)
	}
	record, err := deployment.New(
		"deployment-stale",
		"agent-stale",
		"revision-stale",
		[]byte(`{}`),
		queuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(
		ctx,
		record.ID,
		deployment.StatusDeploying,
		"",
		queuedAt,
	); err != nil {
		t.Fatal(err)
	}

	latest, err := server.LatestDeployment(ctx, record.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Status != deployment.StatusDeliveryFailed {
		t.Fatalf("LatestDeployment() status = %q, want delivery_failed", latest.Status)
	}
	if len(notifier.events) != 1 ||
		notifier.events[0].Deployment.Status != deployment.StatusDeliveryFailed {
		t.Fatalf("stale deployment notifications = %+v", notifier.events)
	}
}

func TestValidationReportCannotCrossAgentBoundary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	record, err := deployment.New(
		"deployment-1",
		"agent-owner",
		"revision-1",
		[]byte(`{}`),
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(
		ctx,
		record.ID,
		deployment.StatusValidating,
		"",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}

	err = server.handleValidationReport(ctx, "agent-attacker", &controlv1.ConfigValidationReport{
		DeploymentId: record.ID,
		RevisionId:   record.RevisionID,
		ConfigSha256: record.ConfigSHA256[:],
		Status:       controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_VALID,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got error %v", err)
	}
	stored, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != deployment.StatusValidating {
		t.Fatalf("forged report changed status to %q", stored.Status)
	}
}

func TestMasterBoundsAgentDiagnostic(t *testing.T) {
	t.Parallel()

	server := newTestServer(deployment.NewMemoryStore(), nil)
	err := server.handleValidationReport(
		context.Background(),
		"agent-1",
		&controlv1.ConfigValidationReport{
			DeploymentId: "deployment-1",
			Diagnostic:   strings.Repeat("x", MaxDiagnosticBytes*4+1),
		},
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got error %v", err)
	}
}

func TestQueueDeploymentRequiresCapabilityAndAppliesMatchingReport(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	notifier := &recordingNotifier{}
	server := newTestServer(store, notifier)
	const agentID = "edge-deploy"
	enrollTestIdentity(t, server.Identities, agentID)
	session := newSession(agentID)
	session.capabilities[ConfigDeployCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)

	record, err := server.QueueDeployment(
		ctx,
		agentID,
		"deployment-live",
		"revision-live",
		[]byte(`{"inbounds":[]}`),
		5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != deployment.StatusDeploying {
		t.Fatalf("queued deployment status = %q", record.Status)
	}
	command := <-session.commands
	if command.GetDeployConfig() == nil ||
		command.GetDeployConfig().GetDeploymentId() != record.ID {
		t.Fatalf("queued frame does not contain the deployment: %+v", command)
	}
	if _, err := server.QueueDeployment(
		ctx,
		agentID,
		"deployment-overlap",
		"revision-overlap",
		[]byte(`{}`),
		time.Second,
	); !errors.Is(err, deployment.ErrDeploymentInProgress) {
		t.Fatalf("overlapping QueueDeployment() error = %v", err)
	}

	err = server.handleDeploymentReport(ctx, agentID, &controlv1.ConfigDeploymentReport{
		DeploymentId: record.ID,
		RevisionId:   record.RevisionID,
		ConfigSha256: record.ConfigSHA256[:],
		Status:       controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != deployment.StatusApplied {
		t.Fatalf("reported deployment status = %q", stored.Status)
	}
	if len(notifier.events) != 1 ||
		notifier.events[0].Deployment.Status != deployment.StatusApplied {
		t.Fatalf("deployment notifications = %+v", notifier.events)
	}
}

func TestQueueAgentUpdateSendsExactVersionAndAcceptsMatchingReport(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server := newTestServer(deployment.NewMemoryStore(), nil)
	const agentID = "edge-update"
	const requestID = "update_0123456789abcdef"
	const targetVersion = "v1.14.0-beta.7"
	enrollTestIdentity(t, server.Identities, agentID)
	session := newSession(agentID)
	session.capabilities[AgentUpdateCapability] = struct{}{}
	session.info.Version = "v0.0.9"
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)

	if err := server.QueueAgentUpdate(
		ctx,
		agentID,
		requestID,
		targetVersion,
	); err != nil {
		t.Fatal(err)
	}
	command := <-session.commands
	if command.GetUpdateAgent().GetRequestId() != requestID ||
		command.GetUpdateAgent().GetTargetVersion() != targetVersion {
		t.Fatalf("queued update command = %+v", command.GetUpdateAgent())
	}
	if err := server.handleAgentUpdateReport(agentID, &controlv1.AgentUpdateReport{
		RequestId:      requestID,
		TargetVersion:  targetVersion,
		RunningVersion: targetVersion,
		Status:         controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_APPLIED,
		ObservedAtUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	state, exists := server.LatestAgentUpdate(agentID)
	if !exists || state.Status != "applied" ||
		state.TargetVersion != targetVersion ||
		state.RunningVersion != targetVersion {
		t.Fatalf("reported update state = %+v, exists=%v", state, exists)
	}
}

func TestQueueSingBoxUpdateSupportsExactPrerelease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server := newTestServer(deployment.NewMemoryStore(), nil)
	const agentID = "edge-sing-box-update"
	const requestID = "singbox_0123456789abcdef"
	const targetVersion = "v1.14.0-alpha.27"
	enrollTestIdentity(t, server.Identities, agentID)
	session := newSession(agentID)
	session.capabilities[SingBoxUpdateCapability] = struct{}{}
	session.info.SingBoxVersion = "v1.14.0-beta.2"
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)

	if err := server.QueueSingBoxUpdate(
		ctx,
		agentID,
		requestID,
		targetVersion,
	); err != nil {
		t.Fatal(err)
	}
	command := <-session.commands
	if command.GetUpdateSingBox().GetRequestId() != requestID ||
		command.GetUpdateSingBox().GetTargetVersion() != targetVersion {
		t.Fatalf(
			"queued sing-box update command = %+v",
			command.GetUpdateSingBox(),
		)
	}
	if err := server.handleSingBoxUpdateReport(
		agentID,
		&controlv1.SingBoxUpdateReport{
			RequestId:      requestID,
			TargetVersion:  targetVersion,
			RunningVersion: targetVersion,
			Status:         controlv1.SingBoxUpdateStatus_SING_BOX_UPDATE_STATUS_APPLIED,
			ObservedAtUnix: time.Now().Unix(),
		},
	); err != nil {
		t.Fatal(err)
	}
	state, exists := server.LatestSingBoxUpdate(agentID)
	if !exists || state.Status != "applied" ||
		state.RunningVersion != targetVersion {
		t.Fatalf(
			"reported sing-box update state = %+v, exists=%v",
			state,
			exists,
		)
	}
}

func TestDeploymentReportCannotCrossAgentBoundary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	record, err := deployment.New(
		"deployment-owner",
		"agent-owner",
		"revision-owner",
		[]byte(`{}`),
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(
		ctx,
		record.ID,
		deployment.StatusDeploying,
		"",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	err = server.handleDeploymentReport(
		ctx,
		"agent-attacker",
		&controlv1.ConfigDeploymentReport{
			DeploymentId: record.ID,
			RevisionId:   record.RevisionID,
			ConfigSha256: record.ConfigSHA256[:],
			Status:       controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED,
		},
	)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-agent deployment report error = %v", err)
	}
}

func TestRuntimeReportMarksFailureAndRecovery(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	record, err := deployment.New(
		"deployment-runtime",
		"agent-runtime",
		"revision-runtime",
		[]byte(`{}`),
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(
		ctx,
		record.ID,
		deployment.StatusDeploying,
		"",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(
		ctx,
		record.ID,
		deployment.StatusApplied,
		"",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}

	err = server.handleRuntimeReport(ctx, record.AgentID, &controlv1.ConfigRuntimeReport{
		ConfigSha256:   record.ConfigSHA256[:],
		Status:         controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RESTART_FAILED,
		Diagnostic:     "managed sing-box could not be restarted",
		ObservedAtUnix: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.Status != deployment.StatusRuntimeFailed {
		t.Fatalf("runtime failure status = %q", failed.Status)
	}

	err = server.handleRuntimeReport(ctx, record.AgentID, &controlv1.ConfigRuntimeReport{
		ConfigSha256:   record.ConfigSHA256[:],
		Status:         controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RUNNING,
		ObservedAtUnix: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != deployment.StatusApplied ||
		recovered.Diagnostic != "" {
		t.Fatalf("runtime recovery = %+v", recovered)
	}

	err = server.handleRuntimeReport(ctx, record.AgentID, &controlv1.ConfigRuntimeReport{
		ConfigSha256:   record.ConfigSHA256[:],
		Status:         controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_STOP_FAILED,
		Diagnostic:     "managed sing-box process termination could not be confirmed",
		ObservedAtUnix: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	stopFailed, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stopFailed.Status != deployment.StatusRuntimeFailed ||
		stopFailed.Diagnostic !=
			"managed sing-box process termination could not be confirmed" {
		t.Fatalf("stop failure runtime state = %+v", stopFailed)
	}
}

func TestRevokeAgentDurablyInvalidatesActiveSession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	identities := identity.NewRegistry()
	server := NewServer(
		identities,
		deployment.NewMemoryStore(),
		nil,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	token, err := identities.CreateEnrollment(ctx, "edge-revoke-active", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := identities.Enroll(
		ctx,
		"edge-revoke-active",
		token,
		publicKey,
		now,
	); err != nil {
		t.Fatal(err)
	}
	active := newSession("edge-revoke-active")
	if err := server.Sessions.Register(active); err != nil {
		t.Fatal(err)
	}

	if err := server.RevokeAgent(ctx, "edge-revoke-active"); err != nil {
		t.Fatal(err)
	}
	if server.Sessions.IsOnline("edge-revoke-active") {
		t.Fatal("revoked agent remained online")
	}
	select {
	case <-active.done:
	default:
		t.Fatal("revocation did not signal the active session")
	}
	if _, err := identities.PublicKey(
		ctx,
		"edge-revoke-active",
	); !errors.Is(err, identity.ErrAgentNotFound) {
		t.Fatalf("PublicKey() error = %v, want ErrAgentNotFound", err)
	}
	if err := server.Sessions.Send(
		ctx,
		"edge-revoke-active",
		&controlv1.MasterFrame{},
	); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("Send() error = %v, want ErrAgentOffline", err)
	}
	if server.Sessions.Disconnect("edge-revoke-active") {
		t.Fatal("Disconnect() reported a second active session")
	}
	// Connect's deferred cleanup may run after revocation; it must not disturb
	// a future session registered under the same ID.
	server.Sessions.Unregister(active)
	replacement := newSession("edge-revoke-active")
	if err := server.Sessions.Register(replacement); err != nil {
		t.Fatalf("register replacement session: %v", err)
	}
	server.Sessions.Unregister(active)
	if !server.Sessions.IsOnline("edge-revoke-active") {
		t.Fatal("stale cleanup removed the replacement session")
	}
	server.Sessions.Unregister(replacement)
}

func enrollTestIdentity(
	t *testing.T,
	registry *identity.Registry,
	agentID string,
) {
	t.Helper()
	now := time.Now().UTC()
	ctx := context.Background()
	token, err := registry.CreateEnrollment(ctx, agentID, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Enroll(
		ctx,
		agentID,
		token,
		publicKey,
		now,
	); err != nil {
		t.Fatal(err)
	}
}
