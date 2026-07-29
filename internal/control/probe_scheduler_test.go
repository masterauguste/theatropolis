package control

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/pool"
)

// probeRefConfig builds a logical config carrying one pool ref to agentID;
// extra is appended to the ref object (e.g. `"family":"ipv6"`).
func probeRefConfig(agentID, extra string) []byte {
	config := `{"outbounds":[{"type":"theatropolis-pool-ref","tag":"via","ref":"agent/` +
		agentID + `/hy2-in/alice"`
	if extra != "" {
		config += "," + extra
	}
	return []byte(config + `}]}`)
}

// TestProbedPairsInUse covers the scheduler's consumption rule: only
// (agent, family) pairs whose CURRENT resolution falls to a probed address
// are re-probed.
func TestProbedPairsInUse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, store := newPoolTestServer(t)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := registry.SetProbed("agent-explicit", nil, []string{"2001:db8::60"})
	must(err)
	_, err = registry.SetProbed("agent-override", nil, []string{"2001:db8::61"})
	must(err)
	must(registry.SetOverride("agent-override", "2001:db8::99"))
	_, err = registry.SetProbed("agent-auto", []string{"203.0.113.62"}, nil)
	must(err)
	_, err = registry.SetProbed("agent-observed", []string{"203.0.113.63"}, nil)
	must(err)
	_, err = registry.SetObserved("agent-observed", "198.51.100.7")
	must(err)
	_, err = registry.SetProbed("agent-unused", []string{"203.0.113.64"}, nil)
	must(err)
	_, err = registry.SetReported("agent-reported", []string{"203.0.113.65"}, nil)
	must(err)
	_, err = registry.SetProbed("agent-v4only", []string{"203.0.113.66"}, nil)
	must(err)
	_, err = registry.SetProbed("agent-deadfamily", []string{"203.0.113.67"}, nil)
	must(err)

	storeAppliedConfig(t, ctx, store, "dep-explicit", probeRefConfig("agent-explicit", `"family":"ipv6"`))
	storeAppliedConfig(t, ctx, store, "dep-override", probeRefConfig("agent-override", `"family":"ipv6"`))
	storeAppliedConfig(t, ctx, store, "dep-auto", probeRefConfig("agent-auto", ""))
	storeAppliedConfig(t, ctx, store, "dep-observed", probeRefConfig("agent-observed", ""))
	storeAppliedConfig(t, ctx, store, "dep-reported", probeRefConfig("agent-reported", ""))
	storeAppliedConfig(t, ctx, store, "dep-wrongfamily", probeRefConfig("agent-v4only", `"family":"ipv6"`))
	storeAppliedConfig(t, ctx, store, "dep-deadfamily", probeRefConfig("agent-deadfamily", `"family":"bogus"`))
	// agent-unused is probed but nothing references it.

	pairs := server.probedPairsInUse()
	want := []probePair{
		{agentID: "agent-auto", family: pool.FamilyIPv4},
		{agentID: "agent-explicit", family: pool.FamilyIPv6},
	}
	if !slices.Equal(pairs, want) {
		t.Fatalf("probedPairsInUse() = %v, want %v", pairs, want)
	}
}

func TestRunProbeTickSendsProbes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, store := newPoolTestServer(t)
	if _, err := registry.SetProbed("agent-src", nil, []string{"2001:db8::60"}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.SetProbed("agent-nocap", nil, []string{"2001:db8::61"}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.SetProbed("agent-unused", nil, []string{"2001:db8::62"}); err != nil {
		t.Fatal(err)
	}
	storeAppliedConfig(t, ctx, store, "dep-1", probeRefConfig("agent-src", `"family":"ipv6"`))
	storeAppliedConfig(t, ctx, store, "dep-2", probeRefConfig("agent-nocap", `"family":"ipv6"`))

	register := func(agentID string, capable bool) *session {
		t.Helper()
		session := newSession(agentID)
		session.capabilities[ConfigDeployCapability] = struct{}{}
		if capable {
			session.capabilities[CapabilityAddressProbe] = struct{}{}
		}
		if err := server.Sessions.Register(session); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Sessions.Unregister(session) })
		return session
	}
	src := register("agent-src", true)
	nocap := register("agent-nocap", false)
	unused := register("agent-unused", true)

	server.runProbeTick()

	frame := <-src.commands
	if probe := frame.GetProbeAddresses(); probe == nil || probe.GetFamily() != "ipv6" {
		t.Fatalf("agent-src frame = %+v, want an ipv6 probe command", frame.GetPayload())
	}
	assertNoCommand(t, nocap)
	assertNoCommand(t, unused)
}

func TestProbeSchedulerLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, store := newPoolTestServer(t)
	server.SetProbeInterval(10 * time.Millisecond)
	if _, err := registry.SetProbed("agent-src", nil, []string{"2001:db8::60"}); err != nil {
		t.Fatal(err)
	}
	storeAppliedConfig(t, ctx, store, "dep-1", probeRefConfig("agent-src", `"family":"ipv6"`))
	session := newSession("agent-src")
	session.capabilities[CapabilityAddressProbe] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Sessions.Unregister(session) })

	// The ticker goroutine started by NewServer fires on the tiny interval.
	select {
	case frame := <-session.commands:
		if frame.GetProbeAddresses() == nil {
			t.Fatalf("scheduler frame = %+v, want a probe command", frame.GetPayload())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("probe scheduler did not fire in time")
	}

	server.Close()
	server.Close() // idempotent

	// After Close the goroutine is gone: drain in-flight frames, then the
	// channel stays silent across many intervals.
	for drained := true; drained; {
		select {
		case <-session.commands:
		default:
			drained = false
		}
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case frame := <-session.commands:
		t.Fatalf("frame sent after Close: %+v", frame.GetPayload())
	default:
	}
}

func TestProbeSchedulerNilRegistry(t *testing.T) {
	t.Parallel()

	// No registry: NewServer starts no goroutine and Close is a no-op.
	server := newTestServer(deployment.NewMemoryStore(), nil)
	server.Close()
	if pairs := server.probedPairsInUse(); pairs != nil {
		t.Fatalf("probedPairsInUse() = %v, want nil without a registry", pairs)
	}
}
