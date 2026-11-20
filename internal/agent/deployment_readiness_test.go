package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type waitingConfigurationManager struct {
	*testConfigurationManager
	started chan struct{}
	release chan struct{}
}

func (m *waitingConfigurationManager) Apply(ctx context.Context, _, _ []byte) (singbox.ApplyResult, error) {
	m.started <- struct{}{}
	select {
	case <-m.release:
		return singbox.ApplyResult{Status: singbox.ApplyStatusApplied, Active: true}, nil
	case <-ctx.Done():
		return singbox.ApplyResult{}, ctx.Err()
	}
}

func TestDeploymentWaitKeepsHeartbeatsAndSerializesCommands(t *testing.T) {
	testActivationWait(t, false)
}

func TestAuthorityRepairWaitKeepsHeartbeatsAndSerializesCommands(t *testing.T) {
	testActivationWait(t, true)
}

func (m *waitingConfigurationManager) ApplyManagedUserAuthority(ctx context.Context, _ uint64, _ []singbox.ManagedUserAuthorityVariant) (singbox.ApplyResult, error) {
	return m.Apply(ctx, nil, nil)
}

func testActivationWait(t *testing.T, authority bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener := bufconn.Listen(1 << 20)
	master := &probeCommandServer{
		hello: make(chan *controlv1.AgentHello, 1), agentFrames: make(chan *controlv1.AgentFrame, 128),
		deploymentCommands: make(chan *controlv1.DeployConfigCommand, 2),
		authorityCommands:  make(chan *controlv1.ManagedUserAuthorityCommand, 2),
	}
	server := grpc.NewServer()
	controlv1.RegisterAgentControlServiceServer(server, master)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	connection, err := grpc.NewClient("passthrough:///readiness-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manager := &waitingConfigurationManager{
		testConfigurationManager: &testConfigurationManager{},
		started:                  make(chan struct{}, 2), release: make(chan struct{}),
	}
	runner := &Runner{PrivateKey: key, Manager: manager, HeartbeatPeriod: 5 * time.Millisecond, Prober: &ProbeScheduler{Interval: -1}}
	done := make(chan error, 1)
	go func() { done <- runner.runControlSession(ctx, controlv1.NewAgentControlServiceClient(connection)) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("session did not stop")
		}
	}()
	config := []byte(`{"inbounds":[]}`)
	digest := sha256.Sum256(config)
	for _, id := range []string{"first", "second"} {
		if authority {
			master.authorityCommands <- &controlv1.ManagedUserAuthorityCommand{
				RequestId: id, UserRevision: 1,
				Variants: []*controlv1.ManagedUserAuthorityVariant{{TopologySha256: digest[:]}},
			}
		} else {
			master.deploymentCommands <- &controlv1.DeployConfigCommand{
				DeploymentId: id, RevisionId: id, ConfigJson: config, ConfigSha256: digest[:],
			}
		}
	}
	select {
	case <-manager.started:
	case <-ctx.Done():
		t.Fatal("deployment did not start")
	}
	lastSequence := uint64(2)
	heartbeats := 0
	for heartbeats < 3 {
		select {
		case frame := <-master.agentFrames:
			if frame.Sequence <= lastSequence {
				t.Fatal("non-monotonic frame sequence")
			}
			lastSequence = frame.Sequence
			if frame.GetConfigDeploymentReport() != nil || frame.GetManagedUserAuthorityReport() != nil {
				t.Fatal("deployment reported before readiness")
			}
			if frame.GetHeartbeat() != nil {
				heartbeats++
			}
		case <-ctx.Done():
			t.Fatal("heartbeats blocked during deployment")
		}
	}
	select {
	case <-manager.started:
		t.Fatal("second deployment overlapped the first")
	default:
	}
	close(manager.release)
	reports := 0
	for reports < 2 {
		select {
		case frame := <-master.agentFrames:
			if frame.Sequence <= lastSequence {
				t.Fatal("non-monotonic frame sequence after deployment")
			}
			lastSequence = frame.Sequence
			if report := frame.GetConfigDeploymentReport(); report != nil {
				wantID := []string{"first", "second"}[reports]
				if report.DeploymentId != wantID || report.Status != controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED {
					t.Fatalf("report = %v", report)
				}
				reports++
			}
			if report := frame.GetManagedUserAuthorityReport(); report != nil {
				wantID := []string{"first", "second"}[reports]
				if report.RequestId != wantID || report.Status != controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_APPLIED {
					t.Fatalf("authority report = %v", report)
				}
				reports++
			}
		case <-ctx.Done():
			t.Fatal("deployment reports did not arrive")
		}
	}
}
