package control

import (
	"context"
	"errors"
	"fmt"
	"testing"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/pool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRequestAddressProbeGating(t *testing.T) {
	t.Parallel()

	server := newTestServer(deployment.NewMemoryStore(), nil)

	if err := server.RequestAddressProbe("ghost", "ipv4"); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("offline agent probe error = %v, want ErrAgentOffline", err)
	}

	plain := newSession("edge-plain")
	plain.capabilities[ProxyNodeDeployCapability] = struct{}{}
	if err := server.Sessions.Register(plain); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Sessions.Unregister(plain) })

	for _, family := range []string{"", "auto", "ipv5", "IPv4"} {
		if err := server.RequestAddressProbe("edge-plain", family); !errors.Is(err, ErrProbeFamilyInvalid) {
			t.Fatalf("family %q probe error = %v, want ErrProbeFamilyInvalid", family, err)
		}
	}
	if err := server.RequestAddressProbe("edge-plain", "ipv4"); !errors.Is(err, ErrAgentProbeUnsupported) {
		t.Fatalf("incapable agent probe error = %v, want ErrAgentProbeUnsupported", err)
	}
	assertNoCommand(t, plain)
}

func TestRequestAddressProbeSendsCommand(t *testing.T) {
	t.Parallel()

	server := newTestServer(deployment.NewMemoryStore(), nil)
	session := newSession("edge-probe")
	session.capabilities[CapabilityAddressProbe] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Sessions.Unregister(session) })

	for _, family := range []string{"ipv6", "ipv4"} {
		if err := server.RequestAddressProbe("edge-probe", family); err != nil {
			t.Fatalf("RequestAddressProbe(%q) error = %v", family, err)
		}
		frame := <-session.commands
		probe := frame.GetProbeAddresses()
		if probe == nil || probe.GetFamily() != family {
			t.Fatalf("probe command = %+v, want family %q", frame.GetPayload(), family)
		}
		// The sequence stays unset on the queued frame: the Connect stream
		// loop assigns it when the frame is dequeued.
		if frame.GetSequence() != 0 {
			t.Fatalf("queued probe command sequence = %d, want unset", frame.GetSequence())
		}
	}
}

func TestAddressProbeReportMergesAndPropagates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, store := newPoolTestServer(t)
	storeAppliedConfig(t, ctx, store, "agent-a", poolSourceConfig(8443))
	sessionB := registerPoolSession(t, server, "agent-b")

	// agent-a has no address yet: the dependent renders a direct fallback.
	command := deployThroughServer(t, ctx, server, sessionB, "agent-b", poolDependentConfig())
	if outbound := firstOutbound(t, command); outbound["type"] != "direct" {
		t.Fatalf("initial outbound = %v, want direct fallback", outbound)
	}

	report := &controlv1.AddressProbeReport{Family: "ipv4", Address: "203.0.113.60"}
	if err := server.handleAddressProbeReport(ctx, "agent-a", report); err != nil {
		t.Fatal(err)
	}
	addr, source, ok := registry.AddressSourceForFamily("agent-a", pool.FamilyIPv4)
	if !ok || source != pool.SourceProbed || addr != "203.0.113.60" {
		t.Fatalf("pool resolution = %q, %v, %v, want probed 203.0.113.60", addr, source, ok)
	}
	frame := <-sessionB.commands
	redeploy := frame.GetDeployConfig()
	if redeploy == nil {
		t.Fatal("dependent was not redeployed after the probe report")
	}
	if outbound := firstOutbound(t, redeploy); outbound["type"] != "hysteria2" ||
		outbound["server"] != "203.0.113.60" {
		t.Fatalf("redeployed outbound = %v", outbound)
	}
	// Leave no deployment in flight so the next propagation can queue.
	if err := server.handleDeploymentReport(ctx, "agent-b", &controlv1.ConfigDeploymentReport{
		DeploymentId: redeploy.GetDeploymentId(),
		RevisionId:   redeploy.GetRevisionId(),
		ConfigSha256: redeploy.GetConfigSha256(),
		Status:       controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED,
	}); err != nil {
		t.Fatal(err)
	}

	// A different result becomes the new head and redeploys again.
	if err := server.handleAddressProbeReport(ctx, "agent-a", &controlv1.AddressProbeReport{
		Family:  "ipv4",
		Address: "203.0.113.61",
	}); err != nil {
		t.Fatal(err)
	}
	if addr, _, _ := registry.AddressSourceForFamily("agent-a", pool.FamilyIPv4); addr != "203.0.113.61" {
		t.Fatalf("pool head = %q, want 203.0.113.61", addr)
	}
	frame = <-sessionB.commands
	if redeploy := frame.GetDeployConfig(); redeploy == nil {
		t.Fatal("dependent was not redeployed after the second probe report")
	} else if outbound := firstOutbound(t, redeploy); outbound["server"] != "203.0.113.61" {
		t.Fatalf("second redeploy outbound = %v", outbound)
	}

	// The same result again changes nothing and triggers no propagation.
	if err := server.handleAddressProbeReport(ctx, "agent-a", &controlv1.AddressProbeReport{
		Family:  "ipv4",
		Address: "203.0.113.61",
	}); err != nil {
		t.Fatal(err)
	}
	assertNoCommand(t, sessionB)
}

func TestAddressProbeReportIPv6(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, _ := newPoolTestServer(t)
	if err := server.handleAddressProbeReport(ctx, "agent-a", &controlv1.AddressProbeReport{
		Family:  "ipv6",
		Address: "2001:db8::60",
	}); err != nil {
		t.Fatal(err)
	}
	addr, source, ok := registry.AddressSourceForFamily("agent-a", pool.FamilyIPv6)
	if !ok || source != pool.SourceProbed || addr != "2001:db8::60" {
		t.Fatalf("pool v6 resolution = %q, %v, %v, want probed 2001:db8::60", addr, source, ok)
	}
	if _, _, ok := registry.AddressSourceForFamily("agent-a", pool.FamilyIPv4); ok {
		t.Fatal("a v6 report created a v4 address")
	}
}

func TestAddressProbeReportIgnored(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, store := newPoolTestServer(t)
	storeAppliedConfig(t, ctx, store, "agent-a", poolSourceConfig(8443))
	sessionB := registerPoolSession(t, server, "agent-b")
	deployThroughServer(t, ctx, server, sessionB, "agent-b", poolDependentConfig())

	reports := map[string]*controlv1.AddressProbeReport{
		"auto family":      {Family: "auto", Address: "203.0.113.60"},
		"empty family":     {Family: "", Address: "203.0.113.60"},
		"unknown family":   {Family: "ipv5", Address: "203.0.113.60"},
		"private v4":       {Family: "ipv4", Address: "10.0.0.8"},
		"cgnat v4":         {Family: "ipv4", Address: "100.64.0.1"},
		"reserved v4":      {Family: "ipv4", Address: "240.0.0.9"},
		"loopback v4":      {Family: "ipv4", Address: "127.0.0.1"},
		"ula v6":           {Family: "ipv6", Address: "fd12:3456::1"},
		"family mismatch":  {Family: "ipv6", Address: "203.0.113.60"},
		"unparseable":      {Family: "ipv4", Address: "not-an-address"},
		"agent-side error": {Family: "ipv4", Error: "all probe endpoints failed"},
	}
	for name, report := range reports {
		if err := server.handleAddressProbeReport(ctx, "agent-a", report); err != nil {
			t.Fatalf("%s: handleAddressProbeReport() error = %v, want ignored", name, err)
		}
		if _, _, ok := registry.AddressSourceForFamily("agent-a", pool.FamilyAuto); ok {
			t.Fatalf("%s: report mutated the pool", name)
		}
		assertNoCommand(t, sessionB)
	}

	if err := server.handleAddressProbeReport(ctx, "agent-a", nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil report error = %v, want InvalidArgument", err)
	}
}

func TestMergeProbedAddressCapAndOrder(t *testing.T) {
	t.Parallel()

	server, registry, _ := newPoolTestServer(t)
	for i := 1; i <= pool.MaxAddressesPerFamily+1; i++ {
		if _, err := server.mergeProbedAddress(
			"agent-x",
			pool.FamilyIPv4,
			fmt.Sprintf("203.0.113.%d", i),
		); err != nil {
			t.Fatal(err)
		}
	}
	state := server.probedShadow["agent-x"]
	if len(state.v4) != pool.MaxAddressesPerFamily {
		t.Fatalf("probed v4 list = %v, want capped at %d", state.v4, pool.MaxAddressesPerFamily)
	}
	if state.v4[0] != "203.0.113.9" || state.v4[1] != "203.0.113.8" {
		t.Fatalf("probed v4 head = %v, want newest first", state.v4)
	}

	// Re-reporting a tail address moves it to the head without duplicating.
	if _, err := server.mergeProbedAddress("agent-x", pool.FamilyIPv4, "203.0.113.3"); err != nil {
		t.Fatal(err)
	}
	state = server.probedShadow["agent-x"]
	if state.v4[0] != "203.0.113.3" || len(state.v4) != pool.MaxAddressesPerFamily {
		t.Fatalf("probed v4 list after re-report = %v", state.v4)
	}
	seen := make(map[string]struct{}, len(state.v4))
	for _, addr := range state.v4 {
		if _, duplicate := seen[addr]; duplicate {
			t.Fatalf("probed v4 list contains a duplicate: %v", state.v4)
		}
		seen[addr] = struct{}{}
	}

	addr, source, ok := registry.AddressSourceForFamily("agent-x", pool.FamilyIPv4)
	if !ok || source != pool.SourceProbed || addr != "203.0.113.3" {
		t.Fatalf("pool head = %q, %v, %v, want probed 203.0.113.3", addr, source, ok)
	}
	if len(state.v6) != 0 {
		t.Fatalf("v4 merges touched the v6 list: %v", state.v6)
	}
}

// TestMergeProbedAddressSeedsFromRegistry simulates a master restart: the
// registry already holds probed addresses (written directly, bypassing the
// shadow), and the first merge must preserve the other family and demote —
// not drop — the existing head of the merged family.
func TestMergeProbedAddressSeedsFromRegistry(t *testing.T) {
	t.Parallel()

	server, registry, _ := newPoolTestServer(t)
	if _, err := registry.SetProbed("agent-x", []string{"203.0.113.20"}, []string{"2001:db8::20"}); err != nil {
		t.Fatal(err)
	}

	changed, err := server.mergeProbedAddress("agent-x", pool.FamilyIPv4, "203.0.113.21")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("merge over seeded state reported no change")
	}
	state := server.probedShadow["agent-x"]
	if len(state.v4) != 2 || state.v4[0] != "203.0.113.21" || state.v4[1] != "203.0.113.20" {
		t.Fatalf("seeded v4 list = %v, want [203.0.113.21 203.0.113.20]", state.v4)
	}
	if addr, _, ok := registry.AddressSourceForFamily("agent-x", pool.FamilyIPv6); !ok || addr != "2001:db8::20" {
		t.Fatalf("v6 resolution after v4 merge = %q, %v, want the seeded head preserved", addr, ok)
	}
}
