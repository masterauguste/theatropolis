package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/masterauguste/theatropolis/internal/pool"
)

// DefaultProbeRefreshInterval is how often the control plane re-sends probe
// commands for (agent, family) pairs whose rendered address currently comes
// from an on-demand probe, keeping those addresses fresh.
const DefaultProbeRefreshInterval = 5 * time.Minute

// probePair is one (agent, family) combination that pool dependents
// currently render from a probed address.
type probePair struct {
	agentID string
	family  pool.Family
}

// SetProbeInterval overrides the re-probe interval; values <= 0 restore the
// default. It exists so tests can shrink the interval while the scheduler
// goroutine is already running.
func (s *Server) SetProbeInterval(interval time.Duration) {
	if interval <= 0 {
		interval = DefaultProbeRefreshInterval
	}
	s.probeIntervalNanos.Store(int64(interval))
}

// Close stops the probe scheduler goroutine and waits for it to exit. It is
// idempotent and a no-op for servers without a pool registry (no goroutine
// ever started). Production mirrors the other master components and lets
// process exit reap the goroutine; tests call Close so no scheduler
// outlives its test.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		if s.probeStop == nil {
			return
		}
		close(s.probeStop)
		s.probeWG.Wait()
	})
}

// probeLoop re-probes in-use probed addresses on the configured interval.
// The interval is re-read every cycle so SetProbeInterval takes effect on
// the next tick.
func (s *Server) probeLoop() {
	defer s.probeWG.Done()
	for {
		timer := time.NewTimer(time.Duration(s.probeIntervalNanos.Load()))
		select {
		case <-s.probeStop:
			timer.Stop()
			return
		case <-timer.C:
		}
		s.runProbeTick()
	}
}

// runProbeTick sends one probe command per in-use probed (agent, family)
// pair, sequentially: Sessions.Send is a buffered-channel write, so a burst
// stays cheap. Offline or probe-incapable agents are skipped — probing is
// strictly best-effort and the pairs recompute every tick.
func (s *Server) runProbeTick() {
	for _, pair := range s.probedPairsInUse() {
		if err := s.RequestAddressProbe(pair.agentID, pair.family.String()); err != nil {
			s.Logger.Debug(
				"scheduled address probe not sent",
				"agent_id", pair.agentID,
				"family", pair.family.String(),
				"error", err,
			)
		}
	}
}

// probedPairsInUse computes the (agent, family) pairs that are actively
// consumed with source == probed, from every agent's latest stored logical
// config. An explicit-family ref counts only when that family's resolution
// currently falls to a probed address (no point probing when an override or
// observed address wins anyway); an auto ref counts only when auto
// resolution currently resolves to a probed address, and the pair then
// carries the resolved address's family. Agents nothing references are never
// probed. The result is sorted for deterministic sends.
func (s *Server) probedPairsInUse() []probePair {
	if s.poolRegistry == nil {
		return nil
	}
	records, err := s.Deployments.List(context.Background())
	if err != nil {
		s.Logger.Error("address probe scheduler scan failed", "error", err)
		return nil
	}
	seen := make(map[probePair]struct{})
	for _, record := range records {
		for _, use := range scanPoolRefUses(record.ConfigJSON) {
			addr, source, ok := s.poolRegistry.AddressSourceForFamily(
				use.agentID,
				use.family,
			)
			if !ok || source != pool.SourceProbed {
				continue
			}
			family := use.family
			if family == pool.FamilyAuto {
				parsed, err := netip.ParseAddr(addr)
				if err != nil {
					continue
				}
				family = pool.FamilyIPv6
				if parsed.Is4() {
					family = pool.FamilyIPv4
				}
			}
			seen[probePair{agentID: use.agentID, family: family}] = struct{}{}
		}
	}
	pairs := make([]probePair, 0, len(seen))
	for pair := range seen {
		pairs = append(pairs, pair)
	}
	slices.SortFunc(pairs, func(left, right probePair) int {
		if left.agentID != right.agentID {
			return strings.Compare(left.agentID, right.agentID)
		}
		return int(left.family - right.family)
	})
	return pairs
}

// poolRefUse is one agent pool reference in a logical config together with
// its family selector (FamilyAuto when the selector is absent).
type poolRefUse struct {
	agentID string
	family  pool.Family
}

// scanPoolRefUses walks a logical config the way pool.Render/pool.Refs do
// (pool keeps its own walk private, and pool.Refs drops the family selector)
// and returns every agent ref with its family. Refs that render dead —
// malformed objects, unparsable family values — resolve nothing, so they are
// skipped rather than probed. The scan is best-effort: configs that do not
// parse yield nil.
func scanPoolRefUses(logical []byte) []poolRefUse {
	if !bytes.Contains(logical, []byte(pool.PoolRefType)) {
		return nil
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(logical, &document); err != nil {
		return nil
	}
	rawOutbounds, exists := document["outbounds"]
	if !exists {
		return nil
	}
	var outbounds []json.RawMessage
	if err := json.Unmarshal(rawOutbounds, &outbounds); err != nil {
		return nil
	}
	var uses []poolRefUse
	for _, rawOutbound := range outbounds {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(rawOutbound, &object); err != nil || object == nil {
			continue
		}
		var outboundType string
		if err := json.Unmarshal(object["type"], &outboundType); err != nil ||
			outboundType != pool.PoolRefType {
			continue
		}
		var ref string
		if err := json.Unmarshal(object["ref"], &ref); err != nil {
			continue
		}
		agentID, ok := refSourceAgent(ref)
		if !ok {
			continue
		}
		family := pool.FamilyAuto
		if familyRaw, exists := object["family"]; exists {
			var familyValue string
			if err := json.Unmarshal(familyRaw, &familyValue); err != nil {
				continue
			}
			parsed, err := pool.ParseFamily(familyValue)
			if err != nil {
				continue
			}
			family = parsed
		}
		uses = append(uses, poolRefUse{agentID: agentID, family: family})
	}
	return uses
}

// refSourceAgent extracts the source agent ID from an
// agent/<id>/<inbound>/<user> ref; manual and malformed refs report false.
func refSourceAgent(ref string) (string, bool) {
	rest, found := strings.CutPrefix(ref, "agent/")
	if !found {
		return "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[0] == "" {
		return "", false
	}
	return parts[0], true
}
