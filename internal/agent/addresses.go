package agent

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
)

// cgnatPrefix is the shared carrier-grade NAT space (RFC 6598) and
// reserved240Prefix the reserved former class-E space (RFC 1112). netip's
// IsGlobalUnicast/IsPrivate cover neither, but both are never publicly
// routable, so globallyRoutable excludes them explicitly.
var (
	cgnatPrefix       = netip.MustParsePrefix("100.64.0.0/10")
	reserved240Prefix = netip.MustParsePrefix("240.0.0.0/4")
)

// globallyRoutable reports whether addr may be used as a pool outbound
// server address: globally reachable, never private/NAT/reserved space.
// TEST-NET/documentation ranges are NOT excluded — they stand in for public
// addresses throughout the test suites.
func globallyRoutable(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() && // drops loopback, link-local, multicast, unspecified
		!addr.IsPrivate() && // RFC 1918 v4 + ULA fc00::/7
		!cgnatPrefix.Contains(addr) && // 100.64.0.0/10
		!reserved240Prefix.Contains(addr) // 240.0.0.0/4
}

// CollectAddresses returns the globally routable IPv4 and IPv6 addresses
// reported by src (net.InterfaceAddrs in production, injected in tests).
//
// Only globallyRoutable addresses are kept: pool outbound server addresses
// must be reachable by other fleet members, so private (RFC 1918/ULA),
// CGNAT, reserved, loopback, link-local, multicast, and unspecified
// addresses are all dropped at collection. The same rule is re-applied at
// master-side sanitization and in the pool registry.
//
// The output is sorted and deduplicated so heartbeats produce a stable value
// the master can compare cheaply.
func CollectAddresses(src func() ([]net.Addr, error)) (v4, v6 []string, err error) {
	addrs, err := src()
	if err != nil {
		return nil, nil, fmt.Errorf("list interface addresses: %w", err)
	}
	seen4 := make(map[netip.Addr]struct{})
	seen6 := make(map[netip.Addr]struct{})
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			continue
		}
		parsed, parseErr := netip.ParseAddr(ip.String())
		if parseErr != nil {
			continue
		}
		// Unmap IPv4-in-IPv6 forms so each address lands in exactly one
		// family bucket.
		parsed = parsed.Unmap()
		if !globallyRoutable(parsed) {
			continue
		}
		if parsed.Is4() {
			seen4[parsed] = struct{}{}
		} else {
			seen6[parsed] = struct{}{}
		}
	}
	return sortedAddrs(seen4), sortedAddrs(seen6), nil
}

// SystemAddresses collects addresses from the host's network interfaces.
func SystemAddresses() (v4, v6 []string) {
	v4, v6, err := CollectAddresses(net.InterfaceAddrs)
	if err != nil {
		return nil, nil
	}
	return v4, v6
}

func sortedAddrs(set map[netip.Addr]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	addrs := make([]netip.Addr, 0, len(set))
	for addr := range set {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].Compare(addrs[j]) < 0
	})
	out := make([]string, len(addrs))
	for i, addr := range addrs {
		out[i] = addr.String()
	}
	return out
}
