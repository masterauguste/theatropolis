package control

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/pool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// ErrProbeFamilyInvalid rejects probe requests that do not pin an
	// explicit IPv4 or IPv6 family (empty, "auto", or unknown selectors).
	ErrProbeFamilyInvalid = errors.New("address probe requires an explicit ipv4 or ipv6 family")
	// ErrAgentProbeUnsupported marks agents whose hello did not advertise
	// CapabilityAddressProbe.
	ErrAgentProbeUnsupported = errors.New("agent does not support address probes")
)

// cgnatPrefix is the shared carrier-grade NAT space (RFC 6598) and
// reserved240Prefix the reserved former class-E space (RFC 1112). netip's
// IsGlobalUnicast/IsPrivate cover neither, but both are never publicly
// routable, so globallyRoutable excludes them explicitly. This mirrors the
// agent-side rule in internal/agent, which cannot be imported here.
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

// RequestAddressProbe asks a connected, probe-capable agent to resolve its
// public address for one explicit IP family; the agent answers with an
// address_probe_report frame on its control stream. The command frame
// carries no sequence number: the Connect stream loop assigns the next
// monotonic master sequence when it dequeues the frame from the session
// command channel, exactly like the validate/deploy/update commands.
func (s *Server) RequestAddressProbe(agentID, family string) error {
	parsed, err := pool.ParseFamily(family)
	if err != nil || parsed == pool.FamilyAuto {
		return ErrProbeFamilyInvalid
	}
	if !s.Sessions.IsOnline(agentID) {
		return ErrAgentOffline
	}
	if !s.Sessions.Supports(agentID, CapabilityAddressProbe) {
		return ErrAgentProbeUnsupported
	}
	return s.Sessions.Send(context.Background(), agentID, &controlv1.MasterFrame{
		Payload: &controlv1.MasterFrame_ProbeAddresses{
			ProbeAddresses: &controlv1.ProbeAddresses{Family: parsed.String()},
		},
	})
}

// handleAddressProbeReport merges one probe result into the agent's probed
// address list and propagates the change to pool dependents. Malformed
// reports (bad family, family/address mismatch, non-routable address) and
// agent-reported probe failures are logged and ignored rather than tearing
// the control stream down: a probe response is advisory, and an agent that
// garbles one must not lose its session over it.
func (s *Server) handleAddressProbeReport(
	ctx context.Context,
	agentID string,
	report *controlv1.AddressProbeReport,
) error {
	if report == nil {
		return status.Error(codes.InvalidArgument, "missing address probe report")
	}
	family, err := pool.ParseFamily(report.GetFamily())
	if err != nil || family == pool.FamilyAuto {
		s.Logger.Warn(
			"address probe report ignored",
			"agent_id", agentID,
			"family", report.GetFamily(),
			"reason", "invalid family",
		)
		return nil
	}
	if report.GetError() != "" {
		s.Logger.Warn(
			"agent address probe failed",
			"agent_id", agentID,
			"family", family.String(),
			"error", sanitizeAgentDiagnostic(report.GetError()),
		)
		return nil
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(report.GetAddress()))
	if err != nil {
		s.Logger.Warn(
			"address probe report ignored",
			"agent_id", agentID,
			"family", family.String(),
			"reason", "unparseable address",
		)
		return nil
	}
	addr = addr.Unmap()
	if addr.Is4() != (family == pool.FamilyIPv4) {
		s.Logger.Warn(
			"address probe report ignored",
			"agent_id", agentID,
			"family", family.String(),
			"address", addr.String(),
			"reason", "family mismatch",
		)
		return nil
	}
	if !globallyRoutable(addr) {
		s.Logger.Warn(
			"address probe report ignored",
			"agent_id", agentID,
			"family", family.String(),
			"address", addr.String(),
			"reason", "address is not publicly routable",
		)
		return nil
	}
	if s.poolRegistry == nil {
		return nil
	}
	changed, err := s.mergeProbedAddress(agentID, family, addr.String())
	if err != nil {
		s.Logger.Error(
			"outbound pool probed-address persistence failed",
			"agent_id", agentID,
			"error", err,
		)
		return nil
	}
	if changed {
		s.propagatePoolChange(ctx, "probed address changed", agentID)
		s.notifyProxyNodeAddressChange()
	}
	return nil
}

// probedAddressState shadows the probed address lists the control plane has
// written for one agent. See mergeProbedAddress.
type probedAddressState struct {
	seeded bool
	v4     []string
	v6     []string
}

// mergeProbedAddress makes addr the head of the agent's probed list for
// family (deduplicated, capped per family) and persists both families
// through pool.SetProbed, which replaces them atomically.
//
// The registry exposes no read accessor for the stored probed lists, so the
// merge reads from probedShadow; the control plane is the only SetProbed
// writer, which keeps the shadow accurate for the life of the process. The
// first merge for an agent seeds the shadow from the registry's resolution:
// the probed head of each family — the only element address resolution ever
// consumes — survives a master restart, older tail entries do not.
func (s *Server) mergeProbedAddress(
	agentID string,
	family pool.Family,
	addr string,
) (bool, error) {
	s.probedMu.Lock()
	defer s.probedMu.Unlock()

	state := s.probedShadow[agentID]
	if state == nil {
		state = &probedAddressState{}
		s.probedShadow[agentID] = state
	}
	if !state.seeded {
		state.seeded = true
		if head, source, ok := s.poolRegistry.AddressSourceForFamily(
			agentID,
			pool.FamilyIPv4,
		); ok && source == pool.SourceProbed {
			state.v4 = []string{head}
		}
		if head, source, ok := s.poolRegistry.AddressSourceForFamily(
			agentID,
			pool.FamilyIPv6,
		); ok && source == pool.SourceProbed {
			state.v6 = []string{head}
		}
	}

	v4 := slices.Clone(state.v4)
	v6 := slices.Clone(state.v6)
	target := &v4
	if family == pool.FamilyIPv6 {
		target = &v6
	}
	merged := []string{addr}
	for _, existing := range *target {
		if len(merged) >= pool.MaxAddressesPerFamily {
			break
		}
		if existing != addr {
			merged = append(merged, existing)
		}
	}
	*target = merged

	changed, err := s.poolRegistry.SetProbed(agentID, v4, v6)
	if err != nil {
		// The write did not happen; keep the shadow at the last persisted
		// state so the next merge builds on what the registry actually holds.
		return false, err
	}
	state.v4 = v4
	state.v6 = v6
	return changed, nil
}
