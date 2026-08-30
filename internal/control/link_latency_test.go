package control

import (
	"context"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
)

func TestLinkLatencyReportReplacesAgentSnapshot(t *testing.T) {
	server := newTestServer(deployment.NewMemoryStore(), nil)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	server.Now = func() time.Time { return now }
	session := newSession("edge-a")
	session.capabilities[LinkLatencyCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Sessions.Unregister(session) })

	var persisted []LinkLatencyObservation
	server.SetLinkLatencyHandler(func(agentID string, observedAt time.Time, samples []LinkLatencyObservation) error {
		if agentID != "edge-a" || !observedAt.Equal(now) {
			t.Fatalf("handler agent=%q time=%v", agentID, observedAt)
		}
		persisted = append(persisted, samples...)
		return nil
	})
	err := server.handleLinkLatencyReport("edge-a", &controlv1.LinkLatencyReport{
		ObservedAtUnix: now.Unix(),
		Samples: []*controlv1.LinkLatencySample{{
			OutboundTag: "tp-out-example", OutboundTags: []string{"tp-out-example", "tp-out-shared"},
			TargetId: "0123456789abcdef0123456789abcdef", Status: controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REACHABLE,
			DurationMilliseconds: 42,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, exists := server.LinkLatency("edge-a", "tp-out-example")
	if !exists || !got.Responded || !got.Connected || got.Duration != 42*time.Millisecond || !got.ObservedAt.Equal(now) {
		t.Fatalf("LinkLatency() = %+v, %v", got, exists)
	}
	if shared, exists := server.LinkLatency("edge-a", "tp-out-shared"); !exists || shared.TargetID != got.TargetID || len(persisted) != 1 {
		t.Fatalf("shared=%+v exists=%v persisted=%#v", shared, exists, persisted)
	}

	if err := server.handleLinkLatencyReport("edge-a", &controlv1.LinkLatencyReport{ObservedAtUnix: now.Unix()}); err != nil {
		t.Fatal(err)
	}
	if _, exists := server.LinkLatency("edge-a", "tp-out-example"); exists {
		t.Fatal("empty report did not clear removed Link sample")
	}
}

func TestRequestLinkLatencyProbeCorrelatesAgentReport(t *testing.T) {
	server := newTestServer(deployment.NewMemoryStore(), nil)
	session := newSession("edge-a")
	session.capabilities[LinkLatencyProbeCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Sessions.Unregister(session) })
	type result struct {
		state LinkLatencyState
		err   error
	}
	resultChannel := make(chan result, 1)
	go func() {
		state, err := server.RequestLinkLatencyProbe(context.Background(), "edge-a", LinkLatencyProbeTarget{Address: "203.0.113.20", Port: 443, ProbeType: "quic", ServerName: "edge.example"})
		resultChannel <- result{state: state, err: err}
	}()
	command := <-session.commands
	probe := command.GetLinkLatencyProbe()
	if probe == nil || probe.GetAddress() != "203.0.113.20" || probe.GetPort() != 443 || probe.GetRequestId() == "" ||
		probe.GetProbeType() != controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_QUIC || probe.GetServerName() != "edge.example" {
		t.Fatalf("probe command = %#v", probe)
	}
	if err := server.handleLinkLatencyProbeReport("edge-a", &controlv1.LinkLatencyProbeReport{
		RequestId: probe.GetRequestId(), Status: controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REFUSED,
		DurationMilliseconds: 9,
	}); err != nil {
		t.Fatal(err)
	}
	got := <-resultChannel
	if got.err != nil || !got.state.Responded || got.state.Connected || got.state.ProbeType != "quic" || got.state.Duration != 9*time.Millisecond {
		t.Fatalf("probe result = %+v, %v", got.state, got.err)
	}
}
