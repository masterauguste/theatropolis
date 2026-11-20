package control

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
)

func TestReverseTunnelProbeBoundToAuthenticatedAgent(t *testing.T) {
	server := newTestServer(deployment.NewMemoryStore(), nil)
	session := newSession("parent")
	session.capabilities[ReverseWireGuardCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Sessions.Unregister(session) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	digest := sha256.Sum256([]byte("active"))
	go func() { result <- server.CheckReverseTunnels(ctx, "parent", digest[:]) }()
	command := <-session.commands
	probe := command.GetReverseTunnelProbe()
	if probe == nil || len(probe.GetTopologySha256()) != sha256.Size || probe.GetRequestId() == "" {
		t.Fatal("invalid probe")
	}
	if err := server.handleReverseTunnelProbeReport("other", &controlv1.ReverseTunnelProbeReport{RequestId: probe.GetRequestId(), Ready: true}); err == nil {
		t.Fatal("unauthenticated report accepted")
	}
	select {
	case <-result:
		t.Fatal("wrong Agent completed probe")
	default:
	}
	if err := server.handleReverseTunnelProbeReport("parent", &controlv1.ReverseTunnelProbeReport{RequestId: probe.GetRequestId(), Ready: true}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	server.reverseProbeMu.Lock()
	remaining := len(server.reverseProbeWaiters)
	server.reverseProbeMu.Unlock()
	if remaining != 0 {
		t.Fatal("probe waiter retained")
	}
}
