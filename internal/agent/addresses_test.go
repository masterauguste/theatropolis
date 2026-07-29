package agent

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
)

// hostAddr builds an interface address with the exact host IP (net.ParseCIDR
// would mask the host bits off, which is not what a real interface reports).
func hostAddr(t *testing.T, value string) *net.IPNet {
	t.Helper()
	parsed, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatalf("parse test address %q: %v", value, err)
	}
	return &net.IPNet{IP: net.IP(parsed.Addr().AsSlice())}
}

func staticAddrs(addrs ...net.Addr) func() ([]net.Addr, error) {
	return func() ([]net.Addr, error) {
		return addrs, nil
	}
}

func TestCollectAddressesFiltersAndSorts(t *testing.T) {
	v4, v6, err := CollectAddresses(staticAddrs(
		hostAddr(t, "192.0.2.10/24"),
		hostAddr(t, "192.0.2.2/24"),
		hostAddr(t, "192.0.2.10/24"), // duplicate
		hostAddr(t, "2001:db8::20/64"),
		hostAddr(t, "2001:db8::1/64"),
		hostAddr(t, "127.0.0.1/8"),    // loopback
		hostAddr(t, "::1/128"),        // loopback
		hostAddr(t, "169.254.1.1/16"), // link-local
		hostAddr(t, "fe80::1/64"),     // link-local
		hostAddr(t, "10.0.0.8/8"),     // RFC 1918: dropped, see globallyRoutable
		hostAddr(t, "192.168.1.2/24"), // RFC 1918: dropped
		hostAddr(t, "100.64.0.9/10"),  // CGNAT: dropped
		hostAddr(t, "240.0.0.9/4"),    // reserved: dropped
		hostAddr(t, "fd00::9/64"),     // ULA: dropped
		hostAddr(t, "224.0.0.1/32"),   // multicast
		&net.IPAddr{IP: net.ParseIP("203.0.113.7")},
	))
	if err != nil {
		t.Fatalf("CollectAddresses: %v", err)
	}
	wantV4 := []string{"192.0.2.2", "192.0.2.10", "203.0.113.7"}
	wantV6 := []string{"2001:db8::1", "2001:db8::20"}
	if !reflect.DeepEqual(v4, wantV4) {
		t.Errorf("v4 = %v, want %v", v4, wantV4)
	}
	if !reflect.DeepEqual(v6, wantV6) {
		t.Errorf("v6 = %v, want %v", v6, wantV6)
	}
}

func TestCollectAddressesUnmapsIPv4InIPv6(t *testing.T) {
	v4, v6, err := CollectAddresses(staticAddrs(
		hostAddr(t, "::ffff:192.0.2.1/128"),
	))
	if err != nil {
		t.Fatalf("CollectAddresses: %v", err)
	}
	if !reflect.DeepEqual(v4, []string{"192.0.2.1"}) {
		t.Errorf("v4 = %v, want [192.0.2.1]", v4)
	}
	if len(v6) != 0 {
		t.Errorf("v6 = %v, want empty", v6)
	}
}

func TestCollectAddressesEmpty(t *testing.T) {
	v4, v6, err := CollectAddresses(staticAddrs())
	if err != nil {
		t.Fatalf("CollectAddresses: %v", err)
	}
	if len(v4) != 0 || len(v6) != 0 {
		t.Errorf("got v4=%v v6=%v, want both empty", v4, v6)
	}
}

func TestCollectAddressesError(t *testing.T) {
	wantErr := errors.New("interfaces unavailable")
	_, _, err := CollectAddresses(func() ([]net.Addr, error) {
		return nil, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want wrapped %v", err, wantErr)
	}
}

func TestSystemAddressesDoesNotFail(t *testing.T) {
	// The host configuration is out of the test's control; only require the
	// convenience wrapper to return without panicking.
	SystemAddresses()
}
