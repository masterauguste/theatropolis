package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type testConfigurationManager struct {
	result singbox.ApplyResult
	err    error
}

func (*testConfigurationManager) Start(
	context.Context,
) (singbox.StartupResult, error) {
	return singbox.StartupResult{}, nil
}

func (m *testConfigurationManager) Apply(
	context.Context,
	[]byte,
	[]byte,
) (singbox.ApplyResult, error) {
	return m.result, m.err
}

func (*testConfigurationManager) Stop(context.Context) error {
	return nil
}

func (*testConfigurationManager) Events() <-chan singbox.RuntimeEvent {
	return nil
}

func TestDeployConfigurationMapsManagerResult(t *testing.T) {
	t.Parallel()

	config := []byte(`{"inbounds":[]}`)
	digest := sha256.Sum256(config)
	now := time.Now().UTC()
	runner := &Runner{
		Manager: &testConfigurationManager{
			result: singbox.ApplyResult{
				Status:       singbox.ApplyStatusApplied,
				ConfigSHA256: digest,
			},
		},
		Now: func() time.Time { return now },
	}
	report := runner.deployConfiguration(
		context.Background(),
		&controlv1.DeployConfigCommand{
			DeploymentId:   "deployment-1",
			RevisionId:     "revision-1",
			ConfigSha256:   digest[:],
			ConfigJson:     config,
			TimeoutSeconds: 5,
		},
	)
	if report.GetStatus() !=
		controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED {
		t.Fatalf("deployment status = %s", report.GetStatus())
	}
	if report.GetDeploymentId() != "deployment-1" ||
		report.GetRevisionId() != "revision-1" ||
		string(report.GetConfigSha256()) != string(digest[:]) {
		t.Fatalf("deployment report lost request identity: %+v", report)
	}
}

func TestDeployConfigurationReportsInternalManagerFailure(t *testing.T) {
	t.Parallel()

	config := []byte(`{}`)
	digest := sha256.Sum256(config)
	runner := &Runner{
		Manager: &testConfigurationManager{
			err: errors.New("private internal failure"),
		},
	}
	report := runner.deployConfiguration(
		context.Background(),
		&controlv1.DeployConfigCommand{
			DeploymentId:   "deployment-2",
			RevisionId:     "revision-2",
			ConfigSha256:   digest[:],
			ConfigJson:     config,
			TimeoutSeconds: 5,
		},
	)
	if report.GetStatus() !=
		controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_INTERNAL_ERROR {
		t.Fatalf("deployment status = %s", report.GetStatus())
	}
	if report.GetDiagnostic() !=
		"agent could not complete the configuration deployment" {
		t.Fatalf("deployment diagnostic leaked internals: %q", report.GetDiagnostic())
	}
}

func TestRuntimeReportContainsOnlyRuntimeMetadata(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte(`{"password":"secret"}`))
	observed := time.Now().UTC()
	report := runtimeReport(singbox.RuntimeEvent{
		Status:       singbox.RuntimeStatusRestartFailed,
		ConfigSHA256: digest,
		ObservedAt:   observed,
		Diagnostic:   "managed sing-box could not be restarted",
	})
	if report.GetStatus() !=
		controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RESTART_FAILED ||
		report.GetObservedAtUnix() != observed.Unix() ||
		string(report.GetConfigSha256()) != string(digest[:]) {
		t.Fatalf("runtime report = %+v", report)
	}
	if report.GetDiagnostic() != "managed sing-box could not be restarted" {
		t.Fatalf("runtime diagnostic = %q", report.GetDiagnostic())
	}
}

func TestRuntimeReportMapsEveryManagerStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		manager singbox.RuntimeStatus
		wire    controlv1.ConfigRuntimeStatus
	}{
		{singbox.RuntimeStatusRunning, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RUNNING},
		{singbox.RuntimeStatusExited, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_EXITED},
		{singbox.RuntimeStatusRestartFailed, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RESTART_FAILED},
		{singbox.RuntimeStatusValidationFailed, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_VALIDATION_FAILED},
		{singbox.RuntimeStatusActivationFailed, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_ACTIVATION_FAILED},
		{singbox.RuntimeStatusStopFailed, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_STOP_FAILED},
		{singbox.RuntimeStatusStopped, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_STOPPED},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.manager), func(t *testing.T) {
			t.Parallel()
			report := runtimeReport(singbox.RuntimeEvent{
				Status:     test.manager,
				ObservedAt: time.Now().UTC(),
			})
			if report.GetStatus() != test.wire {
				t.Fatalf(
					"runtimeReport(%q) status = %s, want %s",
					test.manager,
					report.GetStatus(),
					test.wire,
				)
			}
			if report.GetStatus() ==
				controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_UNSPECIFIED {
				t.Fatalf("runtimeReport(%q) produced unspecified status", test.manager)
			}
		})
	}
}

// probeCommandServer is a minimal fake master: it runs the handshake, then
// forwards command payloads from the test to the stream and agent frames
// back to the test. Master sequence numbers are assigned on send.
type probeCommandServer struct {
	controlv1.UnimplementedAgentControlServiceServer

	hello       chan *controlv1.AgentHello
	agentFrames chan *controlv1.AgentFrame
	commands    chan *controlv1.ProbeAddresses
}

func (s *probeCommandServer) Connect(
	stream controlv1.AgentControlService_ConnectServer,
) error {
	helloFrame, err := stream.Recv()
	if err != nil {
		return err
	}
	select {
	case s.hello <- helloFrame.GetHello():
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	nonce := make([]byte, identity.ChallengeNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	var masterSequence uint64 = 1
	if err := stream.Send(&controlv1.MasterFrame{
		Sequence: masterSequence,
		Payload: &controlv1.MasterFrame_Challenge{
			Challenge: &controlv1.AgentChallenge{
				Nonce:         nonce,
				ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
			},
		},
	}); err != nil {
		return err
	}
	if _, err := stream.Recv(); err != nil { // proof
		return err
	}
	masterSequence++
	if err := stream.Send(&controlv1.MasterFrame{
		Sequence: masterSequence,
		Payload: &controlv1.MasterFrame_AuthenticationResult{
			AuthenticationResult: &controlv1.AuthenticationResult{
				Authenticated: true,
			},
		},
	}); err != nil {
		return err
	}

	recvDone := make(chan error, 1)
	go func() {
		for {
			frame, err := stream.Recv()
			if err != nil {
				recvDone <- err
				return
			}
			select {
			case s.agentFrames <- frame:
			case <-stream.Context().Done():
				recvDone <- stream.Context().Err()
				return
			}
		}
	}()
	for {
		select {
		case command := <-s.commands:
			masterSequence++
			if err := stream.Send(&controlv1.MasterFrame{
				Sequence: masterSequence,
				Payload: &controlv1.MasterFrame_ProbeAddresses{
					ProbeAddresses: command,
				},
			}); err != nil {
				return err
			}
		case err := <-recvDone:
			return err
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func TestRunnerAnswersAddressProbeCommand(t *testing.T) {
	// Not parallel: the test swaps the process-wide reportedAddresses.
	var hits atomic.Int32
	echo := echoServer(t, "203.0.113.50", &hits)
	previous := reportedAddresses
	reportedAddresses = &AddressReporter{
		Source:      interfaceSource("10.0.0.8"),
		EndpointsV4: []string{echo.URL},
	}
	t.Cleanup(func() { reportedAddresses = previous })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	listener := bufconn.Listen(1 << 20)
	fake := &probeCommandServer{
		hello:       make(chan *controlv1.AgentHello, 1),
		agentFrames: make(chan *controlv1.AgentFrame, 64),
		commands:    make(chan *controlv1.ProbeAddresses),
	}
	grpcServer := grpc.NewServer()
	controlv1.RegisterAgentControlServiceServer(grpcServer, fake)
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

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runner := &Runner{
		AgentID:         "edge-probe-1",
		AgentVersion:    "test",
		PrivateKey:      privateKey,
		HeartbeatPeriod: 10 * time.Millisecond, // interleave with probe reports
	}
	runnerResult := make(chan error, 1)
	go func() {
		runnerResult <- runner.Run(ctx, client)
	}()

	var hello *controlv1.AgentHello
	select {
	case hello = <-fake.hello:
	case <-ctx.Done():
		t.Fatal("agent did not send its hello")
	}
	if !slices.Contains(hello.GetCapabilities(), control.CapabilityAddressProbe) {
		t.Fatalf("hello capabilities %v lack %q", hello.GetCapabilities(), control.CapabilityAddressProbe)
	}

	// nextFrame returns the next post-auth agent frame, asserting the agent
	// sequence is strictly monotonic even while heartbeats race the
	// asynchronous probe report (run with -race to cover the data race).
	var lastAgentSequence uint64 = 2 // hello=1, proof=2
	nextFrame := func() *controlv1.AgentFrame {
		t.Helper()
		select {
		case frame := <-fake.agentFrames:
			if frame.GetSequence() <= lastAgentSequence {
				t.Fatalf(
					"agent sequence %d not monotonic after %d",
					frame.GetSequence(),
					lastAgentSequence,
				)
			}
			lastAgentSequence = frame.GetSequence()
			return frame
		case <-ctx.Done():
			t.Fatal("timed out waiting for an agent frame")
			return nil
		}
	}
	nextProbeReport := func() *controlv1.AddressProbeReport {
		t.Helper()
		for {
			if report := nextFrame().GetAddressProbeReport(); report != nil {
				return report
			}
		}
	}

	fake.commands <- &controlv1.ProbeAddresses{Family: "ipv4"}
	report := nextProbeReport()
	if report.GetFamily() != "ipv4" ||
		report.GetAddress() != "203.0.113.50" ||
		report.GetError() != "" {
		t.Fatalf("probe report = %+v, want probed echo address", report)
	}
	if hits.Load() == 0 {
		t.Fatal("echo endpoint was never queried")
	}

	fake.commands <- &controlv1.ProbeAddresses{Family: "ipx"}
	report = nextProbeReport()
	if report.GetFamily() != "ipx" ||
		report.GetError() != "unsupported family" ||
		report.GetAddress() != "" {
		t.Fatalf("unsupported-family report = %+v", report)
	}

	cancel()
	if err := <-runnerResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("runner.Run returned %v, want context.Canceled", err)
	}
}

func TestSanitizeProbeErrorCapsLength(t *testing.T) {
	long := fmt.Sprintf("%0*d", maxProbeErrorBytes*2, 0)
	if got := sanitizeProbeError(errors.New(long)); len(got) != maxProbeErrorBytes {
		t.Fatalf("sanitizeProbeError length = %d, want %d", len(got), maxProbeErrorBytes)
	}
	if got := sanitizeProbeError(errors.New("short")); got != "short" {
		t.Fatalf("sanitizeProbeError = %q, want unchanged", got)
	}
}
