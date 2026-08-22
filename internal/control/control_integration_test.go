package control_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/agent"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const helperEnvironment = "THEATROPOLIS_SING_BOX_TEST_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnvironment) == "1" {
		runSingBoxTestHelper()
		os.Exit(97)
	}
	os.Exit(m.Run())
}

func runSingBoxTestHelper() {
	if len(os.Args) != 4 || os.Args[1] != "check" || os.Args[2] != "-c" {
		_, _ = fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(2)
	}
	config, err := os.ReadFile(os.Args[3])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "could not read candidate")
		os.Exit(2)
	}
	var document struct {
		Password string `json:"password"`
	}
	if json.Unmarshal(config, &document) != nil {
		_, _ = fmt.Fprintln(os.Stderr, "invalid json")
		os.Exit(2)
	}
	_, _ = fmt.Fprintf(
		os.Stderr,
		"configuration password %s rejected at %s",
		document.Password,
		os.Args[3],
	)
	os.Exit(1)
}

type channelNotifier struct {
	events chan deployment.Event
}

func (n *channelNotifier) Notify(_ context.Context, event deployment.Event) error {
	n.events <- event
	return nil
}

func TestInvalidConfigurationReachesMasterNotificationWithoutSecrets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener := bufconn.Listen(1 << 20)
	identities := identity.NewRegistry()
	deployments := deployment.NewMemoryStore()
	notifier := &channelNotifier{events: make(chan deployment.Event, 1)}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	controlServer := control.NewServer(identities, deployments, nil, notifier, logger)
	grpcServer := grpc.NewServer()
	controlv1.RegisterAgentControlServiceServer(grpcServer, controlServer)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	connection, err := grpc.NewClient(
		"passthrough:///theatropolis-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := controlv1.NewAgentControlServiceClient(connection)

	token, err := identities.CreateEnrollment(ctx, "edge-test-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runner := &agent.Runner{
		AgentID:      "edge-test-1",
		AgentVersion: "test",
		PrivateKey:   privateKey,
		Validator: singbox.Validator{
			BinaryPath:     os.Args[0],
			StateDirectory: filepath.Join(t.TempDir(), "agent-state"),
		},
		// Keep the test hermetic: a negative interval disables the agent's
		// periodic public-address probing, which would otherwise dial real
		// echo endpoints for families without a routable interface address.
		Prober: &agent.ProbeScheduler{Interval: -1},
	}
	if err := runner.Enroll(ctx, client, token); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(helperEnvironment, "1"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv(helperEnvironment)
	runnerResult := make(chan error, 1)
	go func() {
		runnerResult <- runner.Run(ctx, client)
	}()

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for !controlServer.Sessions.IsOnline(runner.AgentID) {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("agent did not establish its authenticated control session")
		}
	}

	const secret = "do-not-leak-this-password"
	config := []byte(`{"password":"` + secret + `"}`)
	queued, err := controlServer.QueueValidation(
		ctx,
		runner.AgentID,
		"deployment-1",
		"revision-1",
		config,
		5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if queued.Status != deployment.StatusValidating {
		t.Fatalf("got initial status %q", queued.Status)
	}

	select {
	case event := <-notifier.events:
		if event.Deployment.Status != deployment.StatusValidationFailed {
			t.Fatalf("got final status %q", event.Deployment.Status)
		}
		if !strings.Contains(event.Message, "rejected") {
			t.Fatalf("unexpected user notification %q", event.Message)
		}
		for _, forbidden := range []string{secret, runner.Validator.StateDirectory} {
			if strings.Contains(event.Deployment.Diagnostic, forbidden) {
				t.Fatalf("master notification leaked %q: %q", forbidden, event.Deployment.Diagnostic)
			}
		}
	case <-ctx.Done():
		t.Fatal("master did not receive the validation failure")
	}

	stored, err := deployments.Get(ctx, "deployment-1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != deployment.StatusValidationFailed {
		t.Fatalf("stored status is %q", stored.Status)
	}

	cancel()
	select {
	case <-runnerResult:
	case <-time.After(time.Second):
		t.Fatal("agent did not stop after context cancellation")
	}
}

func TestConnectTimesOutBeforeUnauthenticatedHello(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener := bufconn.Listen(1 << 20)
	controlServer := control.NewServer(
		identity.NewRegistry(),
		deployment.NewMemoryStore(),
		nil,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	controlServer.HelloTimeout = 25 * time.Millisecond
	grpcServer := grpc.NewServer()
	controlv1.RegisterAgentControlServiceServer(grpcServer, controlServer)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	connection, err := grpc.NewClient(
		"passthrough:///theatropolis-hello-timeout-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	stream, err := controlv1.NewAgentControlServiceClient(connection).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("Connect() without hello error = %v, want DeadlineExceeded", err)
	}
}

func TestRevocationDuringChallengeCannotRegisterSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener := bufconn.Listen(1 << 20)
	identities := identity.NewRegistry()
	controlServer := control.NewServer(
		identities,
		deployment.NewMemoryStore(),
		nil,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	grpcServer := grpc.NewServer()
	controlv1.RegisterAgentControlServiceServer(grpcServer, controlServer)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	connection, err := grpc.NewClient(
		"passthrough:///theatropolis-revocation-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := controlv1.NewAgentControlServiceClient(connection)

	const agentID = "edge-revoke-during-challenge"
	token, err := identities.CreateEnrollment(ctx, agentID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Enroll(ctx, &controlv1.EnrollRequest{
		AgentId:         agentID,
		EnrollmentToken: token,
		PublicKey:       publicKey,
	}); err != nil {
		t.Fatal(err)
	}

	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.CloseSend()
	if err := stream.Send(&controlv1.AgentFrame{
		Sequence: 1,
		Payload: &controlv1.AgentFrame_Hello{
			Hello: &controlv1.AgentHello{
				AgentId:         agentID,
				ProtocolVersion: control.ProtocolVersion,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	challengeFrame, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	challenge := challengeFrame.GetChallenge()
	if challenge == nil {
		t.Fatal("master did not send an authentication challenge")
	}

	// Connect has already cached the public key at this point. Revocation must
	// still prevent the subsequently valid proof from registering a session.
	if err := controlServer.RevokeAgent(ctx, agentID); err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(
		privateKey,
		identity.ChallengePayload(agentID, challenge.GetNonce()),
	)
	if err := stream.Send(&controlv1.AgentFrame{
		Sequence: 2,
		Payload: &controlv1.AgentFrame_Proof{
			Proof: &controlv1.AgentProof{Signature: signature},
		},
	}); err != nil {
		t.Fatal(err)
	}
	authFrame, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	authResult := authFrame.GetAuthenticationResult()
	if authResult == nil || authResult.GetAuthenticated() {
		t.Fatalf("revoked identity received authentication result %+v", authResult)
	}
	if authResult.GetErrorCode() != "authentication_failed" {
		t.Fatalf("authentication error code = %q", authResult.GetErrorCode())
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Connect() terminal error = %v, want Unauthenticated", err)
	}
	if controlServer.Sessions.IsOnline(agentID) {
		t.Fatal("revoked in-flight connection registered an active session")
	}
	if _, err := identities.PublicKey(ctx, agentID); !errors.Is(err, identity.ErrAgentNotFound) {
		t.Fatalf("PublicKey() error = %v, want ErrAgentNotFound", err)
	}
}

func TestRevocationDisconnectsAuthenticatedControlStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener := bufconn.Listen(1 << 20)
	identities := identity.NewRegistry()
	controlServer := control.NewServer(
		identities,
		deployment.NewMemoryStore(),
		nil,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	grpcServer := grpc.NewServer()
	controlv1.RegisterAgentControlServiceServer(grpcServer, controlServer)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	connection, err := grpc.NewClient(
		"passthrough:///theatropolis-live-revocation-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := controlv1.NewAgentControlServiceClient(connection)

	const agentID = "edge-revoke-live"
	token, err := identities.CreateEnrollment(ctx, agentID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runner := &agent.Runner{
		AgentID:         agentID,
		AgentVersion:    "test",
		PrivateKey:      privateKey,
		HeartbeatPeriod: 20 * time.Millisecond,
		Prober:          &agent.ProbeScheduler{Interval: -1}, // no real probe traffic
	}
	if err := runner.Enroll(ctx, client, token); err != nil {
		t.Fatal(err)
	}

	runResult := make(chan error, 1)
	go func() {
		runResult <- runner.Run(ctx, client)
	}()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for !controlServer.Sessions.IsOnline(agentID) {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("agent did not establish its authenticated control session")
		}
	}

	if err := controlServer.RevokeAgent(ctx, agentID); err != nil {
		t.Fatal(err)
	}
	if controlServer.Sessions.IsOnline(agentID) {
		t.Fatal("RevokeAgent() returned while the session was still logically online")
	}
	select {
	case err := <-runResult:
		t.Fatalf("revoked agent runner exited instead of preserving local service: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if controlServer.Sessions.IsOnline(agentID) {
		t.Fatal("revoked identity became online after reconnect")
	}
	cancel()
	select {
	case <-runResult:
	case <-time.After(time.Second):
		t.Fatal("agent runner did not stop after context cancellation")
	}
}

func TestAgentReconnectsAfterControlStreamDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	listener := bufconn.Listen(1 << 20)
	identities := identity.NewRegistry()
	controlServer := control.NewServer(
		identities,
		deployment.NewMemoryStore(),
		nil,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	controlServer.HeartbeatTimeout = 100 * time.Millisecond
	grpcServer := grpc.NewServer()
	controlv1.RegisterAgentControlServiceServer(grpcServer, controlServer)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	connection, err := grpc.NewClient(
		"passthrough:///theatropolis-reconnect-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := controlv1.NewAgentControlServiceClient(connection)

	const agentID = "edge-reconnect"
	token, err := identities.CreateEnrollment(
		ctx,
		agentID,
		time.Now().Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runner := &agent.Runner{
		AgentID:         agentID,
		AgentVersion:    "test",
		PrivateKey:      privateKey,
		HeartbeatPeriod: 20 * time.Millisecond,
		Prober:          &agent.ProbeScheduler{Interval: -1}, // no real probe traffic
	}
	if err := runner.Enroll(ctx, client, token); err != nil {
		t.Fatal(err)
	}

	runResult := make(chan error, 1)
	go func() {
		runResult <- runner.Run(ctx, client)
	}()
	waitForAgentState(t, controlServer, agentID, true, 2*time.Second)

	if !controlServer.Sessions.Disconnect(agentID) {
		t.Fatal("active control stream was not disconnected")
	}
	waitForAgentState(t, controlServer, agentID, true, 3*time.Second)
	time.Sleep(200 * time.Millisecond)
	if !controlServer.Sessions.IsOnline(agentID) {
		t.Fatal("active heartbeats did not preserve the reconnected session")
	}

	cancel()
	select {
	case <-runResult:
	case <-time.After(time.Second):
		t.Fatal("agent runner did not stop after context cancellation")
	}
}

func waitForAgentState(
	t *testing.T,
	server *control.Server,
	agentID string,
	online bool,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for server.Sessions.IsOnline(agentID) != online {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("agent online state did not become %v", online)
		}
	}
}

// rawAgent is a minimal hand-driven control-stream client used to observe
// the exact master frames an agent receives, without the agent runner or
// sing-box in between.
type rawAgent struct {
	stream   controlv1.AgentControlService_ConnectClient
	sequence uint64
}

func connectRawAgent(
	t *testing.T,
	ctx context.Context,
	client controlv1.AgentControlServiceClient,
	identities *identity.Registry,
	agentID string,
	reportedAddresses []string,
) *rawAgent {
	t.Helper()
	return connectRawAgentWithCapabilities(
		t,
		ctx,
		client,
		identities,
		agentID,
		reportedAddresses,
		[]string{control.ConfigDeployCapability},
	)
}

func connectRawAgentWithCapabilities(
	t *testing.T,
	ctx context.Context,
	client controlv1.AgentControlServiceClient,
	identities *identity.Registry,
	agentID string,
	reportedAddresses []string,
	capabilities []string,
) *rawAgent {
	t.Helper()
	token, err := identities.CreateEnrollment(ctx, agentID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Enroll(ctx, &controlv1.EnrollRequest{
		AgentId:         agentID,
		EnrollmentToken: token,
		PublicKey:       publicKey,
	}); err != nil {
		t.Fatal(err)
	}

	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	agent := &rawAgent{stream: stream, sequence: 1}
	agent.send(t, &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_Hello{
			Hello: &controlv1.AgentHello{
				AgentId:           agentID,
				ProtocolVersion:   control.ProtocolVersion,
				Capabilities:      capabilities,
				ReportedAddresses: reportedAddresses,
			},
		},
	})
	challengeFrame, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	challenge := challengeFrame.GetChallenge()
	if challenge == nil {
		t.Fatal("master did not send an authentication challenge")
	}
	agent.send(t, &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_Proof{
			Proof: &controlv1.AgentProof{
				Signature: ed25519.Sign(
					privateKey,
					identity.ChallengePayload(agentID, challenge.GetNonce()),
				),
			},
		},
	})
	authFrame, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if !authFrame.GetAuthenticationResult().GetAuthenticated() {
		t.Fatal("raw agent was not authenticated")
	}
	return agent
}

func (a *rawAgent) send(t *testing.T, frame *controlv1.AgentFrame) {
	t.Helper()
	frame.Sequence = a.sequence
	if err := a.stream.Send(frame); err != nil {
		t.Fatal(err)
	}
	a.sequence++
}

func (a *rawAgent) reportApplied(t *testing.T, command *controlv1.DeployConfigCommand) {
	t.Helper()
	a.send(t, &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_ConfigDeploymentReport{
			ConfigDeploymentReport: &controlv1.ConfigDeploymentReport{
				DeploymentId: command.GetDeploymentId(),
				RevisionId:   command.GetRevisionId(),
				ConfigSha256: command.GetConfigSha256(),
				Status:       controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED,
			},
		},
	})
}

func (a *rawAgent) receiveFrame(t *testing.T) *controlv1.MasterFrame {
	t.Helper()
	type received struct {
		frame *controlv1.MasterFrame
		err   error
	}
	result := make(chan received, 1)
	go func() {
		frame, err := a.stream.Recv()
		result <- received{frame: frame, err: err}
	}()
	select {
	case frame := <-result:
		if frame.err != nil {
			t.Fatal(frame.err)
		}
		return frame.frame
	case <-time.After(5 * time.Second):
		t.Fatal("master did not send a frame in time")
		return nil
	}
}

func (a *rawAgent) receiveDeployCommand(t *testing.T) *controlv1.DeployConfigCommand {
	t.Helper()
	frame := a.receiveFrame(t)
	command := frame.GetDeployConfig()
	if command == nil {
		t.Fatalf("master sent a non-deployment frame: %+v", frame)
	}
	return command
}

func renderedOutbound(
	t *testing.T,
	command *controlv1.DeployConfigCommand,
) map[string]any {
	t.Helper()
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(command.GetConfigJson(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Outbounds) != 1 {
		t.Fatalf("rendered configuration outbounds = %v", document.Outbounds)
	}
	return document.Outbounds[0]
}

// waitForDeploymentStatus polls the store until the agent's latest deployment
// reaches the wanted status. Stream reports are processed asynchronously by
// the master, so tests must synchronize on the store before queueing the
// next deployment for the same agent.
func waitForDeploymentStatus(
	t *testing.T,
	ctx context.Context,
	store *deployment.MemoryStore,
	agentID string,
	want deployment.Status,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		record, err := store.LatestForAgent(ctx, agentID)
		if err == nil && record.Status == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("deployment for %s did not reach status %q in time", agentID, want)
}

// rawPoolSourceConfig is a hysteria2 server config with one alice user, in
// the shape the pool renderer derives importable entries from.
func rawPoolSourceConfig(listenPort int) []byte {
	encoded, err := json.Marshal(map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        "hysteria2",
				"tag":         "hy2-in",
				"listen_port": listenPort,
				"users":       []any{map[string]any{"name": "alice", "password": "pw-alice"}},
				"tls":         map[string]any{"enabled": true, "certificate_provider": "acme-main"},
			},
		},
		"certificate_providers": []any{
			map[string]any{"tag": "acme-main", "type": "acme", "domain": []string{"hy2.example.com"}},
		},
	})
	if err != nil {
		panic(err)
	}
	return encoded
}

// TestPoolRefRenderedAndPropagatedEndToEnd drives the whole feature over one
// master: agent A connects reporting its addresses and applies a hysteria2
// config, agent B imports A's inbound through a pool ref and only ever
// receives rendered JSON, A's config change redeploys B, and revoking A
// degrades B's ref to a direct outbound.
func TestPoolRefRenderedAndPropagatedEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	listener := bufconn.Listen(1 << 20)
	identities := identity.NewRegistry()
	deployments := deployment.NewMemoryStore()
	poolRegistry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	controlServer := control.NewServer(identities, deployments, poolRegistry, nil, logger)
	defer controlServer.Close()
	grpcServer := grpc.NewServer()
	controlv1.RegisterAgentControlServiceServer(grpcServer, controlServer)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	connection, err := grpc.NewClient(
		"passthrough:///theatropolis-pool-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := controlv1.NewAgentControlServiceClient(connection)

	sourceConfig := rawPoolSourceConfig
	logicalDependent := []byte(
		`{"outbounds":[{"type":"theatropolis-pool-ref","tag":"via-a","ref":"agent/edge-a/hy2-in/alice"}]}`,
	)

	agentA := connectRawAgent(t, ctx, client, identities, "edge-a", []string{"203.0.113.10"})
	agentB := connectRawAgent(t, ctx, client, identities, "edge-b", nil)

	// A applies the hysteria2 config its hello addresses feed into the pool.
	if _, err := controlServer.QueueDeployment(
		ctx, "edge-a", "dep-a-1", "rev-a-1", sourceConfig(8443), 5*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	agentA.reportApplied(t, agentA.receiveDeployCommand(t))
	// reportApplied only sends the frame; wait until the master has
	// processed it, or the next QueueDeployment for edge-a races the
	// in-flight dep-a-1 and loses under load.
	waitForDeploymentStatus(t, ctx, deployments, "edge-a", deployment.StatusApplied)

	// B imports A's inbound; it must receive the rendered document.
	if _, err := controlServer.QueueDeployment(
		ctx, "edge-b", "dep-b-1", "rev-b-1", logicalDependent, 5*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	commandB := agentB.receiveDeployCommand(t)
	if bytes.Contains(commandB.GetConfigJson(), []byte("theatropolis-pool-ref")) {
		t.Fatal("agent B received a configuration containing a pool ref")
	}
	outbound := renderedOutbound(t, commandB)
	if outbound["type"] != "hysteria2" ||
		outbound["tag"] != "via-a" ||
		outbound["server"] != "203.0.113.10" ||
		outbound["server_port"] != float64(8443) ||
		outbound["password"] != "pw-alice" {
		t.Fatalf("rendered outbound = %v", outbound)
	}
	tlsBlock, ok := outbound["tls"].(map[string]any)
	if !ok || tlsBlock["enabled"] != true ||
		tlsBlock["server_name"] != "hy2.example.com" ||
		tlsBlock["insecure"] != false {
		t.Fatalf("rendered outbound TLS = %v", outbound["tls"])
	}
	renderedDigest := sha256.Sum256(commandB.GetConfigJson())
	if !bytes.Equal(renderedDigest[:], commandB.GetConfigSha256()) {
		t.Fatal("command digest does not match the rendered document")
	}
	// The stored record keeps B's logical config and the rendered digest.
	recordB, err := deployments.LatestForAgent(ctx, "edge-b")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recordB.ConfigJSON, logicalDependent) {
		t.Fatalf("stored config = %s, want the logical document", recordB.ConfigJSON)
	}
	if recordB.RenderedDigest() != renderedDigest ||
		recordB.RenderedSHA256 == recordB.ConfigSHA256 {
		t.Fatalf("stored rendered digest = %x", recordB.RenderedSHA256)
	}
	agentB.reportApplied(t, commandB)

	// A's config change propagates: B receives a fresh rendered deployment.
	if _, err := controlServer.QueueDeployment(
		ctx, "edge-a", "dep-a-2", "rev-a-2", sourceConfig(8444), 5*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	agentA.reportApplied(t, agentA.receiveDeployCommand(t))
	waitForDeploymentStatus(t, ctx, deployments, "edge-a", deployment.StatusApplied)
	followupB := agentB.receiveDeployCommand(t)
	if followupB.GetDeploymentId() == commandB.GetDeploymentId() ||
		!strings.HasPrefix(followupB.GetDeploymentId(), "dep_") {
		t.Fatalf("propagated deployment ID = %q", followupB.GetDeploymentId())
	}
	if outbound := renderedOutbound(t, followupB); outbound["server_port"] != float64(8444) {
		t.Fatalf("propagated outbound = %v", outbound)
	}
	agentB.reportApplied(t, followupB)

	// Revoking A removes it from the pool and degrades B's ref to direct.
	if err := controlServer.RevokeAgent(ctx, "edge-a"); err != nil {
		t.Fatal(err)
	}
	if _, exists := poolRegistry.AgentAddress("edge-a"); exists {
		t.Fatal("revoked agent kept its pool address")
	}
	revokedB := agentB.receiveDeployCommand(t)
	if outbound := renderedOutbound(t, revokedB); outbound["type"] != "direct" ||
		outbound["tag"] != "via-a" {
		t.Fatalf("post-revocation outbound = %v", outbound)
	}
}

// TestObservedAddressAndProbeReportEndToEnd drives the address hierarchy over
// one master: agent A connects with injected X-Forwarded-For metadata (what
// Caddy's reverse_proxy adds), so dependent B's pool import renders with the
// observed address even though A reports no interface addresses. A
// family-pinned IPv6 import then has no address until the master commands a
// probe and A reports back, which redeploys B with the probed address.
func TestObservedAddressAndProbeReportEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	listener := bufconn.Listen(1 << 20)
	identities := identity.NewRegistry()
	deployments := deployment.NewMemoryStore()
	poolRegistry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	controlServer := control.NewServer(identities, deployments, poolRegistry, nil, logger)
	defer controlServer.Close()
	grpcServer := grpc.NewServer()
	controlv1.RegisterAgentControlServiceServer(grpcServer, controlServer)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	connection, err := grpc.NewClient(
		"passthrough:///theatropolis-observed-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := controlv1.NewAgentControlServiceClient(connection)

	// The spoofed leading element must not win: Caddy appends the real peer.
	observedCtx := metadata.AppendToOutgoingContext(
		ctx,
		"x-forwarded-for",
		"9.9.9.9, 203.0.113.10",
	)
	agentA := connectRawAgentWithCapabilities(
		t,
		observedCtx,
		client,
		identities,
		"edge-a",
		nil,
		[]string{control.ConfigDeployCapability, control.CapabilityAddressProbe},
	)
	agentB := connectRawAgent(t, ctx, client, identities, "edge-b", nil)

	// The observed address is on the session and wins pool resolution.
	info, exists := controlServer.Sessions.AgentInfo("edge-a")
	if !exists || info.ObservedAddress != "203.0.113.10" {
		t.Fatalf("ObservedAddress = %q, exists=%v", info.ObservedAddress, exists)
	}
	addr, source, ok := poolRegistry.AddressSourceForFamily("edge-a", pool.FamilyIPv4)
	if !ok || source != pool.SourceObserved || addr != "203.0.113.10" {
		t.Fatalf("pool v4 resolution = %q, %v, %v, want observed 203.0.113.10", addr, source, ok)
	}

	// A applies the hysteria2 config its observed address feeds into the pool.
	if _, err := controlServer.QueueDeployment(
		ctx, "edge-a", "dep-a-1", "rev-a-1", rawPoolSourceConfig(8443), 5*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	agentA.reportApplied(t, agentA.receiveDeployCommand(t))
	waitForDeploymentStatus(t, ctx, deployments, "edge-a", deployment.StatusApplied)

	// B imports A's inbound with auto family: it renders with the observed
	// address.
	logicalAuto := []byte(
		`{"outbounds":[{"type":"theatropolis-pool-ref","tag":"via-a","ref":"agent/edge-a/hy2-in/alice"}]}`,
	)
	if _, err := controlServer.QueueDeployment(
		ctx, "edge-b", "dep-b-1", "rev-b-1", logicalAuto, 5*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	commandB := agentB.receiveDeployCommand(t)
	if outbound := renderedOutbound(t, commandB); outbound["type"] != "hysteria2" ||
		outbound["server"] != "203.0.113.10" {
		t.Fatalf("auto-family outbound = %v, want the observed address", outbound)
	}
	agentB.reportApplied(t, commandB)
	waitForDeploymentStatus(t, ctx, deployments, "edge-b", deployment.StatusApplied)

	// B re-imports pinned to IPv6: A has no v6 address, so the ref is dead.
	logicalV6 := []byte(
		`{"outbounds":[{"type":"theatropolis-pool-ref","tag":"via-a6","ref":"agent/edge-a/hy2-in/alice","family":"ipv6"}]}`,
	)
	if _, err := controlServer.QueueDeployment(
		ctx, "edge-b", "dep-b-2", "rev-b-2", logicalV6, 5*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	commandV6 := agentB.receiveDeployCommand(t)
	if outbound := renderedOutbound(t, commandV6); outbound["type"] != "direct" ||
		outbound["tag"] != "via-a6" {
		t.Fatalf("v6 import without an address = %v, want a direct fallback", outbound)
	}
	agentB.reportApplied(t, commandV6)
	waitForDeploymentStatus(t, ctx, deployments, "edge-b", deployment.StatusApplied)

	// The master commands an IPv6 probe; A answers with a public v6 address.
	if err := controlServer.RequestAddressProbe("edge-a", "ipv6"); err != nil {
		t.Fatal(err)
	}
	probeFrame := agentA.receiveFrame(t)
	probe := probeFrame.GetProbeAddresses()
	if probe == nil || probe.GetFamily() != "ipv6" {
		t.Fatalf("master frame = %+v, want an ipv6 probe command", probeFrame)
	}
	if probeFrame.GetSequence() == 0 {
		t.Fatal("probe command carried no master sequence")
	}
	agentA.send(t, &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_AddressProbeReport{
			AddressProbeReport: &controlv1.AddressProbeReport{
				Family:  "ipv6",
				Address: "2001:db8::50",
			},
		},
	})

	// B is redeployed with the probed v6 address.
	redeployB := agentB.receiveDeployCommand(t)
	if outbound := renderedOutbound(t, redeployB); outbound["type"] != "hysteria2" ||
		outbound["server"] != "2001:db8::50" {
		t.Fatalf("post-probe outbound = %v, want the probed v6 address", outbound)
	}
	agentB.reportApplied(t, redeployB)
}
