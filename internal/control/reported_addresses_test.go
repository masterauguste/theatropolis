package control

import (
	"fmt"
	"reflect"
	"testing"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
)

func TestSanitizeReportedAddresses(t *testing.T) {
	v4, v6 := sanitizeReportedAddresses([]string{
		"192.0.2.10",
		"192.0.2.2",
		"192.0.2.10",       // duplicate
		"::ffff:192.0.2.9", // IPv4-in-IPv6, lands in the v4 family
		"2001:db8::20",
		"2001:db8::1",
		"not-an-address",
		"",
		"192.0.2.1/24", // prefixes are not accepted
		"999.1.2.3",
		"10.0.0.8",     // RFC 1918: dropped
		"100.64.0.9",   // CGNAT: dropped
		"240.0.0.9",    // reserved: dropped
		"127.0.0.1",    // loopback: dropped
		"fd12:3456::1", // ULA: dropped
	})
	// First-seen order is preserved and non-routable entries are dropped:
	// the pool's first-entry selection relies on the agent's order.
	wantV4 := []string{"192.0.2.10", "192.0.2.2", "192.0.2.9"}
	wantV6 := []string{"2001:db8::20", "2001:db8::1"}
	if !reflect.DeepEqual(v4, wantV4) {
		t.Errorf("v4 = %v, want %v", v4, wantV4)
	}
	if !reflect.DeepEqual(v6, wantV6) {
		t.Errorf("v6 = %v, want %v", v6, wantV6)
	}
}

func TestSanitizeReportedAddressesEmpty(t *testing.T) {
	v4, v6 := sanitizeReportedAddresses(nil)
	if len(v4) != 0 || len(v6) != 0 {
		t.Errorf("got v4=%v v6=%v, want both empty", v4, v6)
	}
}

func TestSanitizeReportedAddressesCapsPerFamily(t *testing.T) {
	reported := make([]string, 0, 2*maxReportedAddressesPerFamily)
	for i := range 2 * maxReportedAddressesPerFamily {
		reported = append(reported, fmt.Sprintf("192.0.2.%d", i+1))
	}
	v4, v6 := sanitizeReportedAddresses(reported)
	if len(v4) != maxReportedAddressesPerFamily {
		t.Errorf("len(v4) = %d, want %d", len(v4), maxReportedAddressesPerFamily)
	}
	if len(v6) != 0 {
		t.Errorf("v6 = %v, want empty", v6)
	}
}

func TestSetReportedAddresses(t *testing.T) {
	registry := NewSessionRegistry()
	if changed := registry.SetReportedAddresses(
		"offline-agent",
		[]string{"192.0.2.1"},
		nil,
	); changed {
		t.Error("unknown agent reported a change")
	}

	session := newSession("agent-one")
	if err := registry.Register(session); err != nil {
		t.Fatal(err)
	}

	v4, v6 := sanitizeReportedAddresses([]string{"2001:db8::1", "192.0.2.1"})
	if changed := registry.SetReportedAddresses("agent-one", v4, v6); !changed {
		t.Error("initial store did not report a change")
	}
	info, exists := registry.AgentInfo("agent-one")
	if !exists {
		t.Fatal("session missing after register")
	}
	if !reflect.DeepEqual(info.ReportedIPv4, []string{"192.0.2.1"}) ||
		!reflect.DeepEqual(info.ReportedIPv6, []string{"2001:db8::1"}) {
		t.Errorf(
			"stored addresses = %v / %v, want [192.0.2.1] / [2001:db8::1]",
			info.ReportedIPv4,
			info.ReportedIPv6,
		)
	}

	// Same addresses in the same order: no change.
	sameV4, sameV6 := sanitizeReportedAddresses([]string{"2001:db8::1", "192.0.2.1"})
	if changed := registry.SetReportedAddresses("agent-one", sameV4, sameV6); changed {
		t.Error("identical report reported a change")
	}

	newV4, newV6 := sanitizeReportedAddresses([]string{"192.0.2.2"})
	if changed := registry.SetReportedAddresses("agent-one", newV4, newV6); !changed {
		t.Error("differing set did not report a change")
	}
	info, _ = registry.AgentInfo("agent-one")
	if !reflect.DeepEqual(info.ReportedIPv4, []string{"192.0.2.2"}) ||
		len(info.ReportedIPv6) != 0 {
		t.Errorf(
			"stored addresses = %v / %v, want [192.0.2.2] / []",
			info.ReportedIPv4,
			info.ReportedIPv6,
		)
	}

	// Mutating the caller's slices or the returned AgentInfo must not alias
	// registry state.
	newV4[0] = "192.0.2.99"
	info.ReportedIPv4[0] = "192.0.2.100"
	info, _ = registry.AgentInfo("agent-one")
	if !reflect.DeepEqual(info.ReportedIPv4, []string{"192.0.2.2"}) {
		t.Errorf("registry state aliased caller slices: %v", info.ReportedIPv4)
	}
}

func TestNewSessionFromHelloSanitizesAddresses(t *testing.T) {
	session := newSessionFromHello(&controlv1.AgentHello{
		AgentId: "agent-one",
		ReportedAddresses: []string{
			"garbage",
			"2001:db8::1",
			"192.0.2.1",
			"172.16.0.5", // dropped: not globally routable
		},
	})
	if !reflect.DeepEqual(session.info.ReportedIPv4, []string{"192.0.2.1"}) ||
		!reflect.DeepEqual(session.info.ReportedIPv6, []string{"2001:db8::1"}) {
		t.Errorf(
			"hello addresses = %v / %v, want [192.0.2.1] / [2001:db8::1]",
			session.info.ReportedIPv4,
			session.info.ReportedIPv6,
		)
	}
}
