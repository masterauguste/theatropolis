package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
)

func TestRequestManagedUserTrafficWaitsForPersistedReport(t *testing.T) {
	t.Parallel()

	server := newTestServer(deployment.NewMemoryStore(), nil)
	t.Cleanup(server.Close)
	session := registerTrafficSession(t, server, "edge-traffic")

	var handled bool
	server.SetManagedUserTrafficHandler(func(agentID, epoch string, _ time.Time, users []ManagedUserTraffic, delta bool) (bool, error) {
		handled = true
		if agentID != "edge-traffic" || epoch != "ledger-1" || delta || len(users) != 1 || users[0].Username != "member-1" {
			t.Fatalf("unexpected persisted report: agent=%q epoch=%q delta=%v users=%+v", agentID, epoch, delta, users)
		}
		return false, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- server.RequestManagedUserTraffic(ctx, "edge-traffic") }()

	requestFrame := <-session.commands
	request := requestFrame.GetManagedUserTrafficRequest()
	if request == nil || strings.TrimSpace(request.GetRequestId()) == "" {
		t.Fatalf("traffic request command = %+v", requestFrame.GetPayload())
	}
	if err := server.handleAgentFrame(ctx, "edge-traffic", &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_ManagedUserTrafficReport{
			ManagedUserTrafficReport: &controlv1.ManagedUserTrafficReport{
				Epoch: "ledger-1", ObservedAtUnix: time.Now().Unix(), RequestId: request.GetRequestId(),
				Users: []*controlv1.ManagedUserTraffic{{InboundPath: "inbound/1", Username: "member-1", UplinkBytes: 5}},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("RequestManagedUserTraffic() error = %v", err)
	}
	if !handled {
		t.Fatal("request completed before the traffic report was persisted")
	}
	if ack := (<-session.commands).GetManagedUserTrafficAck(); ack == nil || ack.GetEpoch() != "ledger-1" {
		t.Fatalf("traffic acknowledgement = %+v", ack)
	}
}

func TestManagedUserTrafficFailureWaitsForNextPeriodicSample(t *testing.T) {
	t.Parallel()

	server := newTestServer(deployment.NewMemoryStore(), nil)
	t.Cleanup(server.Close)
	session := registerTrafficSession(t, server, "edge-retry")
	server.SetManagedUserTrafficHandler(func(string, string, time.Time, []ManagedUserTraffic, bool) (bool, error) {
		return false, nil
	})
	failures := make(chan string, 1)
	server.SetManagedUserTrafficFailureHandler(func(agentID, reason string, _ time.Time) error {
		failures <- agentID + ":" + reason
		return nil
	})

	if err := server.handleAgentFrame(context.Background(), "edge-retry", &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_ManagedUserTrafficReport{
			ManagedUserTrafficReport: &controlv1.ManagedUserTrafficReport{
				ObservedAtUnix: time.Now().Unix(), Diagnostic: "managed-user traffic collection failed",
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if failure := <-failures; failure != "edge-retry:collection_failed" {
		t.Fatalf("accounting failure history entry = %q", failure)
	}
	select {
	case frame := <-session.commands:
		t.Fatalf("master unexpectedly retried destructive traffic sample: %+v", frame.GetPayload())
	case <-time.After(25 * time.Millisecond):
	}
}

func TestManagedUserTrafficDeltaAppliesOnceWithoutAcknowledgement(t *testing.T) {
	t.Parallel()

	server := newTestServer(deployment.NewMemoryStore(), nil)
	t.Cleanup(server.Close)
	session := newSession("edge-delta")
	session.capabilities[ManagedUserTrafficDeltaCapability] = struct{}{}
	session.capabilities[ManagedUserTrafficRequestCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Sessions.Unregister(session) })

	calls := 0
	server.SetManagedUserTrafficHandler(func(agentID, batchID string, _ time.Time, users []ManagedUserTraffic, delta bool) (bool, error) {
		calls++
		if agentID != "edge-delta" || batchID != "reset-batch-1" || !delta ||
			len(users) != 1 || users[0].UplinkBytes != 25 {
			t.Fatalf("delta report: agent=%q batch=%q delta=%v users=%+v", agentID, batchID, delta, users)
		}
		return false, nil
	})
	if err := server.handleAgentFrame(context.Background(), "edge-delta", &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_ManagedUserTrafficReport{
			ManagedUserTrafficReport: &controlv1.ManagedUserTrafficReport{
				Epoch: "reset-batch-1", ObservedAtUnix: time.Now().Unix(),
				Users: []*controlv1.ManagedUserTraffic{{
					InboundPath: "inbound/1", Username: "member-1", UplinkBytes: 25,
				}},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("delta handler calls = %d, want 1", calls)
	}
	assertNoCommand(t, session)
}

func TestRequestManagedUserTrafficRequiresRequestCapability(t *testing.T) {
	t.Parallel()

	server := newTestServer(deployment.NewMemoryStore(), nil)
	t.Cleanup(server.Close)
	server.SetManagedUserTrafficHandler(func(string, string, time.Time, []ManagedUserTraffic, bool) (bool, error) {
		return false, nil
	})
	session := newSession("edge-old")
	session.capabilities[ManagedUserTrafficCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Sessions.Unregister(session) })

	err := server.RequestManagedUserTraffic(context.Background(), "edge-old")
	if !errors.Is(err, ErrAgentTrafficRequestUnsupported) {
		t.Fatalf("request error = %v, want ErrAgentTrafficRequestUnsupported", err)
	}
	assertNoCommand(t, session)
}

func registerTrafficSession(t *testing.T, server *Server, agentID string) *session {
	t.Helper()
	session := newSession(agentID)
	session.capabilities[ManagedUserTrafficCapability] = struct{}{}
	session.capabilities[ManagedUserTrafficRequestCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Sessions.Unregister(session) })
	return session
}
