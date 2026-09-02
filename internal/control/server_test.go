package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/singbox"
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

func TestEnrollResolvesMasterRecordWithoutReturningItsID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	registry := identity.NewRegistry()
	server := NewServer(
		registry,
		deployment.NewMemoryStore(),
		nil,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	token, err := registry.CreateEnrollment(
		ctx,
		"master-assigned-agent",
		time.Now().Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := &controlv1.EnrollRequest{
		EnrollmentToken: token,
		PublicKey:       publicKey,
	}
	response, err := server.Enroll(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.GetEnrolledAtUnix() == 0 {
		t.Fatal("enrollment response omitted its timestamp")
	}
	resolved, err := registry.AgentIDForPublicKey(ctx, publicKey)
	if err != nil || resolved != "master-assigned-agent" {
		t.Fatalf("master-side record = %q, %v", resolved, err)
	}
}

func TestReplacementEnrollmentDisconnectsPreviousSession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	registry := identity.NewRegistry()
	server := NewServer(
		registry,
		deployment.NewMemoryStore(),
		nil,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	enrollTestIdentity(t, registry, "edge-replacement")
	previousSession := newSession("edge-replacement")
	if err := server.Sessions.Register(previousSession); err != nil {
		t.Fatal(err)
	}
	token, err := registry.CreateReplacementEnrollment(
		ctx,
		"edge-replacement",
		time.Now().Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Enroll(ctx, &controlv1.EnrollRequest{
		EnrollmentToken: token,
		PublicKey:       publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetEnrolledAtUnix() == 0 {
		t.Fatal("replacement response omitted its timestamp")
	}
	select {
	case <-previousSession.done:
	default:
		t.Fatal("replacement enrollment did not disconnect the previous session")
	}
	stored, err := registry.PublicKey(ctx, "edge-replacement")
	if err != nil || !bytes.Equal(stored, publicKey) {
		t.Fatalf("replacement public key = %x, %v", stored, err)
	}
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

func TestManagedUserTrafficReportRequiresCapabilityAndMapsAuthenticatedAgent(t *testing.T) {
	t.Parallel()
	server := newTestServer(deployment.NewMemoryStore(), nil)
	const agentID = "edge-traffic"
	session := newSession(agentID)
	session.capabilities[ManagedUserTrafficCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)

	called := false
	server.SetManagedUserTrafficHandler(func(gotAgent, epoch string, _ time.Time, users []ManagedUserTraffic, delta bool) (bool, error) {
		called = true
		if gotAgent != agentID || epoch != "process-1" || delta || len(users) != 1 ||
			users[0].InboundPath != "/tp-in-0123456789abcdef" || users[0].Username != "cinema-alice" ||
			users[0].UplinkBytes != 10 || users[0].DownlinkBytes != 20 {
			t.Fatalf("mapped traffic = agent=%q epoch=%q users=%#v", gotAgent, epoch, users)
		}
		return false, nil
	})
	err := server.handleAgentFrame(context.Background(), agentID, &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_ManagedUserTrafficReport{ManagedUserTrafficReport: &controlv1.ManagedUserTrafficReport{
			Epoch: "process-1", ObservedAtUnix: time.Now().Unix(),
			Users: []*controlv1.ManagedUserTraffic{{
				InboundPath: "/tp-in-0123456789abcdef", Username: "cinema-alice",
				UplinkBytes: 10, DownlinkBytes: 20,
			}},
		}},
	})
	if err != nil || !called {
		t.Fatalf("handleAgentFrame() error=%v called=%v", err, called)
	}
	select {
	case frame := <-session.commands:
		ack := frame.GetManagedUserTrafficAck()
		if ack.GetEpoch() != "process-1" || len(ack.GetUsers()) != 1 || ack.GetUsers()[0].GetUplinkBytes() != 10 {
			t.Fatalf("traffic acknowledgement = %#v", ack)
		}
	case <-time.After(time.Second):
		t.Fatal("master did not acknowledge persisted traffic")
	}
}

func TestManagedUserAuthorityUsesIndependentRequestReportPath(t *testing.T) {
	t.Parallel()
	server := newTestServer(deployment.NewMemoryStore(), nil)
	const agentID = "edge-users"
	session := newSession(agentID)
	session.capabilities[ManagedUserAuthorityCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)
	digest := sha256.Sum256([]byte("topology"))
	result := make(chan error, 1)
	go func() {
		result <- server.QueueManagedUserAuthority(context.Background(), agentID, 7, []singbox.ManagedUserAuthorityVariant{{
			TopologySHA256: digest,
		}})
	}()
	var request *controlv1.ManagedUserAuthorityCommand
	select {
	case frame := <-session.commands:
		request = frame.GetManagedUserAuthority()
		if request.GetUserRevision() != 7 || len(request.GetVariants()) != 1 ||
			!bytes.Equal(request.GetVariants()[0].GetTopologySha256(), digest[:]) {
			t.Fatalf("managed-user authority command = %#v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("managed-user authority command was not queued")
	}
	if err := server.handleAgentFrame(context.Background(), agentID, &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_ManagedUserAuthorityReport{
			ManagedUserAuthorityReport: &controlv1.ManagedUserAuthorityReport{
				RequestId: request.GetRequestId(), UserRevision: 7,
				Status:          controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_APPLIED,
				CompletedAtUnix: time.Now().Unix(),
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("managed-user authority request did not accept its report")
	}
}

func TestManagedUserAuthorityMismatchQueuesAuthoritativeProfileRepair(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	const agentID = "edge-stale-topology"
	enrollTestIdentity(t, server.Identities, agentID)
	authoritative := []byte(`{"inbounds":[],"outbounds":[{"type":"block","tag":"reject"}],"route":{"final":"reject"}}`)
	previous, err := deployment.New(
		"previous-stable", agentID, deployment.ProxyNodeTopologyRevisionPrefix+"stable",
		authoritative, time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, previous); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(ctx, previous.ID, deployment.StatusDeploying, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(ctx, previous.ID, deployment.StatusApplied, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	session := newSession(agentID)
	session.capabilities[ManagedUserAuthorityCapability] = struct{}{}
	session.capabilities[ProxyNodeDeployCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)
	digest := sha256.Sum256([]byte("stale-topology"))
	result := make(chan error, 1)
	go func() {
		result <- server.QueueManagedUserAuthority(ctx, agentID, 23, []singbox.ManagedUserAuthorityVariant{{
			TopologySHA256: digest,
		}})
	}()

	var request *controlv1.ManagedUserAuthorityCommand
	select {
	case frame := <-session.commands:
		request = frame.GetManagedUserAuthority()
		if request == nil {
			t.Fatalf("first recovery frame = %#v, want managed-user authority", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("managed-user authority command was not queued")
	}
	if err := server.handleAgentFrame(ctx, agentID, &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_ManagedUserAuthorityReport{
			ManagedUserAuthorityReport: &controlv1.ManagedUserAuthorityReport{
				RequestId: request.GetRequestId(), UserRevision: 23,
				Status:          controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_INTERNAL_ERROR,
				Diagnostic:      singbox.ManagedUserAuthorityTopologyMismatchDiagnostic,
				CompletedAtUnix: time.Now().Unix(),
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-session.commands:
		deploymentCommand := frame.GetDeployConfig()
		if deploymentCommand == nil || !bytes.Equal(deploymentCommand.GetConfigJson(), authoritative) {
			t.Fatalf("authoritative repair frame = %#v", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("topology mismatch did not queue authoritative profile repair")
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "authoritative profile repair queued") {
			t.Fatalf("authority mismatch result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("managed-user authority request did not finish")
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
	session.capabilities[ProxyNodeDeployCapability] = struct{}{}
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

func TestTopologyDeploymentRecordsAgentMaterializedDigest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	const agentID = "edge-materialized"
	enrollTestIdentity(t, server.Identities, agentID)
	session := newSession(agentID)
	session.capabilities[ProxyNodeDeployCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)
	record, err := server.QueueDeployment(
		ctx, agentID, "deployment-materialized",
		deployment.ProxyNodeTopologyRevisionPrefix+"revision", []byte(`{"inbounds":[]}`), time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	<-session.commands
	effective := sha256.Sum256([]byte(`{"inbounds":[],"filtered":true}`))
	if err := server.handleDeploymentReport(ctx, agentID, &controlv1.ConfigDeploymentReport{
		DeploymentId: record.ID, RevisionId: record.RevisionID, ConfigSha256: effective[:],
		Status: controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED,
	}); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != deployment.StatusApplied || stored.RenderedDigest() != effective ||
		stored.LastAppliedRenderedSHA256 != effective {
		t.Fatalf("materialized deployment = %#v", stored)
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

func TestQueueOnlineMasterMigrationTargetsOnlyCompatibleOnlineAgents(t *testing.T) {
	t.Parallel()
	server := newTestServer(deployment.NewMemoryStore(), nil)
	for _, agentID := range []string{"online-compatible", "online-old", "offline-compatible"} {
		enrollTestIdentity(t, server.Identities, agentID)
	}
	compatible := newSession("online-compatible")
	compatible.capabilities[MasterMigrationCapability] = struct{}{}
	if err := server.Sessions.Register(compatible); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(compatible)
	old := newSession("online-old")
	if err := server.Sessions.Register(old); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(old)

	queued, skipped, err := server.QueueOnlineMasterMigration(context.Background(), "migration_test", "new.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if queued != 1 || skipped != 2 {
		t.Fatalf("queued=%d skipped=%d", queued, skipped)
	}
	command := <-compatible.commands
	if got := command.GetMigrateMaster(); got.GetMigrationId() != "migration_test" || got.GetMasterAddress() != "new.example:443" {
		t.Fatalf("command = %#v", got)
	}
	select {
	case unexpected := <-old.commands:
		t.Fatalf("old Agent received command: %#v", unexpected)
	default:
	}
}

func TestAgentUpdateAcceptsStaleTerminalReportAfterMasterRestart(t *testing.T) {
	t.Parallel()

	server := newTestServer(deployment.NewMemoryStore(), nil)
	err := server.handleAgentUpdateReport("edge-update", &controlv1.AgentUpdateReport{
		RequestId:      "update_0123456789abcdef",
		TargetVersion:  "v1.14.0-beta.7",
		RunningVersion: "v0.0.9",
		Status:         controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_FAILED,
		Diagnostic:     "release asset was unavailable",
		ObservedAtUnix: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("stale terminal report was not acknowledged: %v", err)
	}
	if _, exists := server.LatestAgentUpdate("edge-update"); exists {
		t.Fatal("stale terminal report created a visible update record")
	}
}

func TestQueueSingBoxUpdateSupportsExactPrerelease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	server := newTestServer(deployment.NewMemoryStore(), nil)
	const agentID = "edge-sing-box-update"
	const requestID = "singbox_0123456789abcdef"
	const targetVersion = "v1.14.0-rc.1.theatropolis.1"
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
	if _, err := identities.EnrollByToken(
		ctx,
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

func TestRevokeAgentGuardFailsBeforeRevocation(t *testing.T) {
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
	token, err := identities.CreateEnrollment(ctx, "edge-referenced", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.EnrollByToken(ctx, token, publicKey, now); err != nil {
		t.Fatal(err)
	}
	active := newSession("edge-referenced")
	if err := server.Sessions.Register(active); err != nil {
		t.Fatal(err)
	}

	guardErr := errors.New("Agent is referenced")
	guardCalled := false
	server.SetAgentRevocationGuard(func(agentID string, revoke func() error) error {
		guardCalled = true
		if agentID != "edge-referenced" {
			t.Fatalf("guard Agent ID = %q", agentID)
		}
		if revoke == nil {
			t.Fatal("guard revocation callback is nil")
		}
		return guardErr
	})
	if err := server.RevokeAgent(ctx, "edge-referenced"); !errors.Is(err, guardErr) {
		t.Fatalf("RevokeAgent() error = %v, want guard error", err)
	}
	if !guardCalled || !server.Sessions.IsOnline("edge-referenced") {
		t.Fatalf("guard called=%v online=%v", guardCalled, server.Sessions.IsOnline("edge-referenced"))
	}
	select {
	case <-active.done:
		t.Fatal("guarded revocation disconnected the active Agent")
	default:
	}
	if got, err := identities.PublicKey(ctx, "edge-referenced"); err != nil || !bytes.Equal(got, publicKey) {
		t.Fatalf("guarded revocation changed identity: key=%x error=%v", got, err)
	}
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
	if enrolledAgentID, err := registry.EnrollByToken(
		ctx,
		token,
		publicKey,
		now,
	); err != nil {
		t.Fatal(err)
	} else if enrolledAgentID != agentID {
		t.Fatalf("enrolled Agent ID = %q, want %q", enrolledAgentID, agentID)
	}
}
