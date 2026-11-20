package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const ReverseWireGuardCapability = "reverse-wireguard-socks-v1"

func (s *Server) CanDeployReverseWireGuard(agentID string) bool {
	return s.Sessions.SupportsReady(agentID, ReverseWireGuardCapability)
}

func (s *Server) CheckReverseTunnels(ctx context.Context, agentID string, digest []byte) error {
	if len(digest) != sha256.Size || !s.CanDeployReverseWireGuard(agentID) {
		return errors.New("Agent lacks reverse WireGuard support")
	}
	id, err := randomOpaqueID("wgprobe")
	if err != nil {
		return err
	}
	key := agentID + "\x00" + id
	waiter := make(chan bool, 1)
	s.reverseProbeMu.Lock()
	s.reverseProbeWaiters[key] = waiter
	s.reverseProbeMu.Unlock()
	defer func() { s.reverseProbeMu.Lock(); delete(s.reverseProbeWaiters, key); s.reverseProbeMu.Unlock() }()
	if err := s.Sessions.Send(ctx, agentID, &controlv1.MasterFrame{Payload: &controlv1.MasterFrame_ReverseTunnelProbe{ReverseTunnelProbe: &controlv1.ReverseTunnelProbeCommand{RequestId: id, TopologySha256: append([]byte(nil), digest...)}}}); err != nil {
		return err
	}
	select {
	case ready := <-waiter:
		if ready {
			return nil
		}
		return errors.New("reverse WireGuard tunnel is not ready; check parent UDP reachability")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) handleReverseTunnelProbeReport(agentID string, report *controlv1.ReverseTunnelProbeReport) error {
	if report == nil || !s.Sessions.Supports(agentID, ReverseWireGuardCapability) || report.GetRequestId() == "" || len(report.GetRequestId()) > 128 || strings.ContainsRune(report.GetRequestId(), '\x00') {
		return status.Error(codes.InvalidArgument, "invalid reverse tunnel probe report")
	}
	s.reverseProbeMu.Lock()
	waiter := s.reverseProbeWaiters[agentID+"\x00"+report.GetRequestId()]
	s.reverseProbeMu.Unlock()
	if waiter != nil {
		select {
		case waiter <- report.GetReady():
		default:
		}
	}
	return nil
}
