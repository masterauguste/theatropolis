package control

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/pool"
)

func TestSweepPeerLatenciesProbesAllEligiblePairsOverTCP20045(t *testing.T) {
	poolRegistry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := poolRegistry.SetReported("edge-a", []string{"203.0.113.10"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := poolRegistry.SetReported("edge-b", []string{"203.0.113.20"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := poolRegistry.SetReported("edge-cgnat", []string{"203.0.113.30"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := poolRegistry.SetReported("edge-legacy", []string{"203.0.113.40"}, nil); err != nil {
		t.Fatal(err)
	}

	server := newTestServer(deployment.NewMemoryStore(), nil)
	server.poolRegistry = poolRegistry
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	server.Now = func() time.Time { return now }
	server.SetAgentReverseOnlyLookup(func(id string) bool { return id == "edge-cgnat" })

	register := func(id string, caps ...string) *session {
		s := newSession(id)
		for _, cap := range caps {
			s.capabilities[cap] = struct{}{}
		}
		if err := server.Sessions.Register(s); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Sessions.Unregister(s) })
		return s
	}

	sessA := register("edge-a", LinkLatencyProbeCapability, PeerLatencyListenerCapability)
	sessB := register("edge-b", LinkLatencyProbeCapability, PeerLatencyListenerCapability)
	sessCGNAT := register("edge-cgnat", LinkLatencyProbeCapability, PeerLatencyListenerCapability)
	sessLegacy := register("edge-legacy", LinkLatencyProbeCapability)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Respond to every probe command on each agent session.
	reply := func(agentID string, s *session, rttMs uint64) {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case frame := <-s.commands:
					probe := frame.GetLinkLatencyProbe()
					if probe == nil {
						continue
					}
					if probe.GetPort() != PeerLatencyListenPort || probe.GetProbeType() != controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP {
						t.Errorf("unexpected probe on %s: port=%d type=%v", agentID, probe.GetPort(), probe.GetProbeType())
					}
					_ = server.handleLinkLatencyProbeReport(agentID, &controlv1.LinkLatencyProbeReport{
						RequestId:            probe.GetRequestId(),
						Status:               controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REACHABLE,
						DurationMilliseconds: rttMs,
					})
				}
			}
		}()
	}
	reply("edge-a", sessA, 15)
	reply("edge-b", sessB, 22)
	reply("edge-cgnat", sessCGNAT, 37)
	reply("edge-legacy", sessLegacy, 44)

	server.SweepPeerLatencies(ctx)

	check := func(source, target string, wantExists bool, wantMs int64) {
		t.Helper()
		got, exists := server.PeerLatency(source, target)
		if exists != wantExists {
			t.Fatalf("PeerLatency(%q -> %q) exists = %v, want %v (got=%+v)", source, target, exists, wantExists, got)
		}
		if wantExists && (!got.Connected || got.ProbeType != "tcp" || got.Duration != time.Duration(wantMs)*time.Millisecond) {
			t.Fatalf("PeerLatency(%q -> %q) = %+v, want connected tcp %dms", source, target, got, wantMs)
		}
	}

	// Normal public <-> public pairs are measured in both directions.
	check("edge-a", "edge-b", true, 15)
	check("edge-b", "edge-a", true, 22)
	// Reverse-only agent is NOT probed inbound, but DOES probe public peers outbound.
	check("edge-a", "edge-cgnat", false, 0)
	check("edge-cgnat", "edge-a", true, 37)
	check("edge-cgnat", "edge-b", true, 37)
	// Legacy agent without PeerLatencyListenerCapability is not probed inbound,
	// but can still probe upgraded peers outbound.
	check("edge-a", "edge-legacy", false, 0)
	check("edge-legacy", "edge-a", true, 44)

	// Disconnecting an agent prunes its peer entries on the next sweep.
	server.Sessions.Unregister(sessB)
	server.SweepPeerLatencies(ctx)
	check("edge-a", "edge-b", false, 0)
	check("edge-b", "edge-a", false, 0)
}
