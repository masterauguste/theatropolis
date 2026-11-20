package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	managedLinkOutboundTagPrefix = "tp-out-"
	maxLinkLatencySamples        = 256
	maxLinkLatencyTags           = 4096
	maxLinkLatencyDuration       = 30 * time.Second
)

var (
	ErrLinkLatencyProbeUnsupported = errors.New("agent does not support on-demand Link latency probes")
	ErrLinkLatencyProbeInvalid     = errors.New("invalid Link latency probe target")
)

func (s *Server) handleLinkLatencyReport(agentID string, report *controlv1.LinkLatencyReport) error {
	if !s.Sessions.Supports(agentID, LinkLatencyCapability) {
		return status.Error(codes.FailedPrecondition, "Link latency monitoring is unavailable")
	}
	if report == nil || report.GetObservedAtUnix() == 0 || len(report.GetSamples()) > maxLinkLatencySamples {
		return status.Error(codes.InvalidArgument, "invalid Link latency report")
	}
	now := s.now()
	latest := make(map[string]LinkLatencyState)
	observations := make([]LinkLatencyObservation, 0, len(report.GetSamples()))
	totalTags := 0
	for _, sample := range report.GetSamples() {
		if sample == nil {
			return status.Error(codes.InvalidArgument, "invalid Link latency sample")
		}
		tags := append([]string(nil), sample.GetOutboundTags()...)
		if len(tags) == 0 && strings.TrimSpace(sample.GetOutboundTag()) != "" {
			tags = []string{sample.GetOutboundTag()}
		}
		totalTags += len(tags)
		if len(tags) == 0 || totalTags > maxLinkLatencyTags {
			return status.Error(codes.InvalidArgument, "invalid Link latency tags")
		}
		slices.Sort(tags)
		tags = slices.Compact(tags)
		for _, tag := range tags {
			if !validLinkLatencyTag(tag) {
				return status.Error(codes.InvalidArgument, "invalid Link latency tag")
			}
		}
		targetID := strings.TrimSpace(sample.GetTargetId())
		if targetID == "" {
			digest := sha256.Sum256([]byte("legacy-link-latency\x00" + agentID + "\x00" + tags[0]))
			targetID = hex.EncodeToString(digest[:16])
		}
		if !validLinkLatencyTargetID(targetID) {
			return status.Error(codes.InvalidArgument, "invalid Link latency target")
		}
		probeType, err := linkLatencyProbeType(sample.GetProbeType())
		if err != nil {
			return err
		}
		state, err := linkLatencyState(targetID, probeType, sample.GetStatus(), sample.GetDurationMilliseconds(), now)
		if err != nil {
			return err
		}
		for _, tag := range tags {
			latest[tag] = state
		}
		observations = append(observations, LinkLatencyObservation{
			TargetID: targetID, ProbeType: state.ProbeType, OutboundTags: tags, Responded: state.Responded,
			Connected: state.Connected, Duration: state.Duration,
		})
	}
	s.linkLatencyMu.Lock()
	s.linkLatency[agentID] = latest
	s.linkLatencyMu.Unlock()
	if s.linkLatencyHandler != nil {
		if err := s.linkLatencyHandler(agentID, now, observations); err != nil {
			s.Logger.Error("persist Link latency history", "agent_id", agentID, "error", err)
		}
	}
	return nil
}

func validLinkLatencyTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	return strings.HasPrefix(tag, managedLinkOutboundTagPrefix) && len(tag) <= 128
}

func validLinkLatencyTargetID(value string) bool {
	if len(value) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func linkLatencyProbeType(value controlv1.LinkLatencyProbeType) (string, error) {
	switch value {
	case controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_UNSPECIFIED,
		controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP:
		return "tcp", nil
	case controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_QUIC:
		return "quic", nil
	default:
		return "", status.Error(codes.InvalidArgument, "invalid Link latency probe type")
	}
}

func linkLatencyProbeTypeValue(value string) (controlv1.LinkLatencyProbeType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "tcp":
		return controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP, nil
	case "quic":
		return controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_QUIC, nil
	default:
		return controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_UNSPECIFIED, ErrLinkLatencyProbeInvalid
	}
}

func linkLatencyState(targetID, probeType string, value controlv1.LinkLatencyStatus, durationMilliseconds uint64, observedAt time.Time) (LinkLatencyState, error) {
	duration := time.Duration(durationMilliseconds) * time.Millisecond
	if duration > maxLinkLatencyDuration {
		return LinkLatencyState{}, status.Error(codes.InvalidArgument, "invalid Link latency duration")
	}
	state := LinkLatencyState{TargetID: targetID, ProbeType: probeType, Duration: duration, ObservedAt: observedAt}
	switch value {
	case controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REACHABLE:
		state.Responded = true
		state.Connected = true
	case controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REFUSED:
		state.Responded = true
	case controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_UNREACHABLE:
	default:
		return LinkLatencyState{}, status.Error(codes.InvalidArgument, "invalid Link latency status")
	}
	return state, nil
}

// LinkLatency returns the newest advisory sample for one generated outbound.
func (s *Server) LinkLatency(agentID, outboundTag string) (LinkLatencyState, bool) {
	s.linkLatencyMu.RLock()
	defer s.linkLatencyMu.RUnlock()
	state, exists := s.linkLatency[agentID][outboundTag]
	return state, exists
}

func (s *Server) RequestLinkLatencyProbe(ctx context.Context, agentID string, target LinkLatencyProbeTarget) (LinkLatencyState, error) {
	parsed, err := netip.ParseAddr(strings.TrimSpace(target.Address))
	probeType, probeTypeErr := linkLatencyProbeTypeValue(target.ProbeType)
	if err != nil || probeTypeErr != nil || !globallyRoutable(parsed) || target.Port == 0 ||
		len(target.ServerName) > 253 || len(target.ObfsType) > 32 || len(target.ObfsSecret) > 1024 {
		return LinkLatencyState{}, ErrLinkLatencyProbeInvalid
	}
	if !s.Sessions.IsOnline(agentID) {
		return LinkLatencyState{}, ErrAgentOffline
	}
	if !s.Sessions.Supports(agentID, LinkLatencyProbeCapability) {
		return LinkLatencyState{}, ErrLinkLatencyProbeUnsupported
	}
	requestID, err := randomOpaqueID("latency")
	if err != nil {
		return LinkLatencyState{}, err
	}
	waiter := make(chan LinkLatencyState, 1)
	key := linkLatencyProbeWaiterKey(agentID, requestID)
	s.linkLatencyProbeMu.Lock()
	if len(s.linkLatencyProbeWaiters) >= 256 {
		s.linkLatencyProbeMu.Unlock()
		return LinkLatencyState{}, errors.New("too many Link latency probes are pending")
	}
	s.linkLatencyProbeWaiters[key] = waiter
	s.linkLatencyProbeMu.Unlock()
	defer func() {
		s.linkLatencyProbeMu.Lock()
		delete(s.linkLatencyProbeWaiters, key)
		s.linkLatencyProbeMu.Unlock()
	}()
	if err := s.Sessions.Send(ctx, agentID, &controlv1.MasterFrame{
		Payload: &controlv1.MasterFrame_LinkLatencyProbe{LinkLatencyProbe: &controlv1.LinkLatencyProbeCommand{
			RequestId: requestID, Address: parsed.String(), Port: uint32(target.Port), ProbeType: probeType,
			ServerName: strings.TrimSpace(target.ServerName), ObfsType: strings.TrimSpace(target.ObfsType), ObfsSecret: target.ObfsSecret,
		}},
	}); err != nil {
		return LinkLatencyState{}, err
	}
	select {
	case result := <-waiter:
		result.ProbeType = strings.ToLower(strings.TrimSpace(target.ProbeType))
		if result.ProbeType == "" {
			result.ProbeType = "tcp"
		}
		return result, nil
	case <-ctx.Done():
		return LinkLatencyState{}, ctx.Err()
	}
}

func (s *Server) handleLinkLatencyProbeReport(agentID string, report *controlv1.LinkLatencyProbeReport) error {
	if !s.Sessions.Supports(agentID, LinkLatencyProbeCapability) || report == nil {
		return status.Error(codes.FailedPrecondition, "on-demand Link latency is unavailable")
	}
	requestID := strings.TrimSpace(report.GetRequestId())
	if requestID == "" || len(requestID) > 128 || strings.ContainsRune(requestID, '\x00') {
		return status.Error(codes.InvalidArgument, "invalid Link latency probe report")
	}
	state, err := linkLatencyState("", "", report.GetStatus(), report.GetDurationMilliseconds(), s.now())
	if err != nil {
		return err
	}
	key := linkLatencyProbeWaiterKey(agentID, requestID)
	s.linkLatencyProbeMu.Lock()
	waiter := s.linkLatencyProbeWaiters[key]
	s.linkLatencyProbeMu.Unlock()
	if waiter != nil {
		select {
		case waiter <- state:
		default:
		}
	}
	return nil
}

func linkLatencyProbeWaiterKey(agentID, requestID string) string {
	return agentID + "\x00" + requestID
}
