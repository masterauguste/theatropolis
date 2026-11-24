package control

import (
	"context"
	"sync"
	"time"

	"github.com/masterauguste/theatropolis/internal/pool"
)

const (
	defaultPeerLatencyPeriod        = 60 * time.Second
	peerLatencyTriggerDebounce      = 2 * time.Second
	peerLatencyProbeTimeout         = 4 * time.Second
	peerLatencyGlobalConcurrency    = 24
	peerLatencyPerSourceConcurrency = 4
)

// PeerLatencyKey identifies one directed inter-server TCP probe path.
type PeerLatencyKey struct {
	SourceAgentID string
	TargetAgentID string
}

// SetAgentReverseOnlyLookup informs the peer latency monitor which Agents are
// reverse-only (CGNAT) and therefore cannot accept inbound TCP probes.
func (s *Server) SetAgentReverseOnlyLookup(lookup func(string) bool) {
	s.agentReverseOnly = lookup
}

func (s *Server) isAgentReverseOnly(agentID string) bool {
	return s.agentReverseOnly != nil && s.agentReverseOnly(agentID)
}

func (s *Server) peerLatencyPort() uint16 {
	if s.peerLatencyPortOverride != 0 {
		return s.peerLatencyPortOverride
	}
	return PeerLatencyListenPort
}

func (s *Server) peerLatencyInterval() time.Duration {
	if s.peerLatencyPeriod > 0 {
		return s.peerLatencyPeriod
	}
	return defaultPeerLatencyPeriod
}

// PeerLatency returns the newest TCP probe sample between sourceAgentID and
// targetAgentID measured over the dedicated peer latency port.
func (s *Server) PeerLatency(sourceAgentID, targetAgentID string) (LinkLatencyState, bool) {
	s.peerLatencyMu.RLock()
	defer s.peerLatencyMu.RUnlock()
	state, exists := s.peerLatency[PeerLatencyKey{
		SourceAgentID: sourceAgentID,
		TargetAgentID: targetAgentID,
	}]
	return state, exists
}

// RecordPeerLatency stores one fresh TCP probe sample for a directed pair.
func (s *Server) RecordPeerLatency(sourceAgentID, targetAgentID string, state LinkLatencyState) {
	if sourceAgentID == "" || targetAgentID == "" || sourceAgentID == targetAgentID {
		return
	}
	if state.ProbeType == "" {
		state.ProbeType = "tcp"
	}
	s.peerLatencyMu.Lock()
	s.peerLatency[PeerLatencyKey{
		SourceAgentID: sourceAgentID,
		TargetAgentID: targetAgentID,
	}] = state
	s.peerLatencyMu.Unlock()
}

// TriggerPeerLatencySweep coalesces a prompt all-to-all TCP latency sweep
// after Agent connects or address changes.
func (s *Server) TriggerPeerLatencySweep() {
	if s == nil || s.peerLatencyTrigger == nil {
		return
	}
	select {
	case s.peerLatencyTrigger <- struct{}{}:
	default:
	}
}

// StartPeerLatencyMonitor runs periodic and event-driven all-to-all TCP
// latency sweeps across online Agents until ctx is cancelled.
func (s *Server) StartPeerLatencyMonitor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.peerLatencyInterval())
		defer ticker.Stop()
		var debounce *time.Timer
		var debounceCh <-chan time.Time
		defer func() {
			if debounce != nil {
				debounce.Stop()
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.peerLatencyTrigger:
				if debounce == nil {
					debounce = time.NewTimer(peerLatencyTriggerDebounce)
					debounceCh = debounce.C
				}
			case <-debounceCh:
				debounce = nil
				debounceCh = nil
				s.SweepPeerLatencies(ctx)
			case <-ticker.C:
				if debounce != nil {
					if !debounce.Stop() {
						select {
						case <-debounce.C:
						default:
						}
					}
					debounce = nil
					debounceCh = nil
				}
				s.SweepPeerLatencies(ctx)
			}
		}
	}()
}

// SweepPeerLatencies probes every eligible directed pair of online Agents over
// TCP using PeerLatencyListenPort (20045). Reverse-only targets are skipped as
// inbound destinations; their outbound reverse paths to public peers are probed
// naturally as normal directed pairs.
func (s *Server) SweepPeerLatencies(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	online := s.Sessions.OnlineAgentIDs()
	onlineSet := make(map[string]struct{}, len(online))
	for _, id := range online {
		onlineSet[id] = struct{}{}
	}
	s.peerLatencyMu.Lock()
	for key := range s.peerLatency {
		if _, sourceOK := onlineSet[key.SourceAgentID]; !sourceOK {
			delete(s.peerLatency, key)
			continue
		}
		if _, targetOK := onlineSet[key.TargetAgentID]; !targetOK {
			delete(s.peerLatency, key)
		}
	}
	s.peerLatencyMu.Unlock()

	if len(online) < 2 || s.poolRegistry == nil {
		return
	}

	type peerJob struct {
		source    string
		target    string
		addresses []string
	}
	jobs := make([]peerJob, 0, len(online)*(len(online)-1))
	for _, source := range online {
		if !s.Sessions.Supports(source, LinkLatencyProbeCapability) {
			continue
		}
		_, hasSourceV4 := s.poolRegistry.AgentAddressForFamily(source, pool.FamilyIPv4)
		_, hasSourceV6 := s.poolRegistry.AgentAddressForFamily(source, pool.FamilyIPv6)
		for _, target := range online {
			if target == source || s.isAgentReverseOnly(target) {
				continue
			}
			if !s.Sessions.Supports(target, PeerLatencyListenerCapability) {
				continue
			}
			addresses := s.peerProbeAddresses(hasSourceV4, hasSourceV6, target)
			if len(addresses) == 0 {
				continue
			}
			jobs = append(jobs, peerJob{source: source, target: target, addresses: addresses})
		}
	}
	if len(jobs) == 0 {
		return
	}

	globalSem := make(chan struct{}, peerLatencyGlobalConcurrency)
	sourceSems := make(map[string]chan struct{}, len(online))
	for _, id := range online {
		sourceSems[id] = make(chan struct{}, peerLatencyPerSourceConcurrency)
	}
	port := s.peerLatencyPort()
	var wg sync.WaitGroup
	for _, job := range jobs {
		wg.Add(1)
		go func(job peerJob) {
			defer wg.Done()
			sourceSem := sourceSems[job.source]
			select {
			case sourceSem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sourceSem }()
			select {
			case globalSem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-globalSem }()

			var best LinkLatencyState
			haveBest := false
			for _, address := range job.addresses {
				probeCtx, cancel := context.WithTimeout(ctx, peerLatencyProbeTimeout)
				sample, err := s.RequestLinkLatencyProbe(probeCtx, job.source, LinkLatencyProbeTarget{
					Address:   address,
					Port:      port,
					ProbeType: "tcp",
				})
				cancel()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				if !haveBest || (!best.Connected && sample.Connected) || (!best.Responded && sample.Responded) {
					best = sample
					haveBest = true
				}
				if sample.Connected {
					break
				}
			}
			if haveBest {
				s.RecordPeerLatency(job.source, job.target, best)
			}
		}(job)
	}
	wg.Wait()
}

func (s *Server) peerProbeAddresses(hasSourceV4, hasSourceV6 bool, target string) []string {
	targetV4, hasTargetV4 := s.poolRegistry.AgentAddressForFamily(target, pool.FamilyIPv4)
	targetV6, hasTargetV6 := s.poolRegistry.AgentAddressForFamily(target, pool.FamilyIPv6)
	addresses := make([]string, 0, 2)
	if hasTargetV4 && (hasSourceV4 || !hasTargetV6) {
		addresses = append(addresses, targetV4)
		if hasSourceV6 && hasTargetV6 {
			addresses = append(addresses, targetV6)
		}
		return addresses
	}
	if hasTargetV6 {
		addresses = append(addresses, targetV6)
		if hasTargetV4 {
			addresses = append(addresses, targetV4)
		}
	}
	return addresses
}
