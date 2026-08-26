package control

import (
	"context"
	"net/netip"
	"strings"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// observedAddress extracts the address the agent's control connection
// arrives from. The gRPC listener sits behind Caddy, whose reverse_proxy
// appends the real client peer to any client-supplied X-Forwarded-For and
// folds the result into a single header; gRPC-Go maps that HTTP/2 header
// into incoming-call metadata. Only the LAST comma-separated element of the
// last value is trusted: it is the peer Caddy itself saw, while every
// earlier element came from the client and is spoofable. Without the header
// (direct connections in dev setups) the transport peer address is the
// fallback. Only globally routable addresses are returned: in production the
// observed address is the agent's public egress IP, and a non-routable
// candidate (including the loopback addresses dev setups produce) is dropped
// by design — the pool has no use for an address other fleet members cannot
// reach. Returns "" when nothing usable is present.
func observedAddress(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get("x-forwarded-for"); len(values) > 0 {
			parts := strings.Split(values[len(values)-1], ",")
			candidate := strings.TrimSpace(parts[len(parts)-1])
			if addr, err := netip.ParseAddr(candidate); err == nil && globallyRoutable(addr) {
				return addr.String()
			}
		}
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if addrPort, err := netip.ParseAddrPort(p.Addr.String()); err == nil && globallyRoutable(addrPort.Addr()) {
			return addrPort.Addr().String()
		}
		if addr, err := netip.ParseAddr(p.Addr.String()); err == nil && globallyRoutable(addr) {
			return addr.String()
		}
	}
	return ""
}

// syncObservedAddress stores the control-connection address on the session
// and persists it into the pool registry, propagating to dependents when it
// changed. Called from Connect after the session is registered. An empty
// addr (no X-Forwarded-For, unusable peer) clears any previously stored
// observation for the agent.
func (s *Server) syncObservedAddress(ctx context.Context, agentID, addr string) {
	s.Sessions.SetObservedAddress(agentID, addr)
	if s.poolRegistry == nil {
		return
	}
	changed, err := s.poolRegistry.SetObserved(agentID, addr)
	if err != nil {
		s.Logger.Error(
			"outbound pool observed-address persistence failed",
			"agent_id", agentID,
			"error", err,
		)
		return
	}
	if changed {
		s.propagatePoolChange(ctx, "observed address changed", agentID)
		s.notifyProxyNodeAddressChange()
	}
}
