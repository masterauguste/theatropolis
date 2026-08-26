package control

import (
	"context"
	"errors"
	"fmt"
	"strings"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrAgentTrafficRequestUnsupported = errors.New("agent does not support on-demand traffic reports")
	ErrManagedUserTrafficUnavailable  = errors.New("managed-user traffic accounting is unavailable")
)

// RequestManagedUserTraffic asks one connected Agent to read and clear its
// current traffic interval immediately. It returns only after the master has
// persisted the response, so topology deployment never replaces an entrance
// before its final successful sample is durable.
func (s *Server) RequestManagedUserTraffic(ctx context.Context, agentID string) error {
	if ctx == nil || s.managedUserTrafficHandler == nil {
		return ErrManagedUserTrafficUnavailable
	}
	if !s.Sessions.IsOnline(agentID) {
		return ErrAgentOffline
	}
	if (!s.Sessions.Supports(agentID, ManagedUserTrafficCapability) &&
		!s.Sessions.Supports(agentID, ManagedUserTrafficDeltaCapability)) ||
		!s.Sessions.Supports(agentID, ManagedUserTrafficRequestCapability) {
		return ErrAgentTrafficRequestUnsupported
	}
	requestID, err := randomOpaqueID("traffic")
	if err != nil {
		return err
	}
	waiter := make(chan error, 1)
	key := managedUserTrafficWaiterKey(agentID, requestID)
	s.managedUserTrafficMu.Lock()
	s.managedUserTrafficWaiters[key] = waiter
	s.managedUserTrafficMu.Unlock()
	defer func() {
		s.managedUserTrafficMu.Lock()
		delete(s.managedUserTrafficWaiters, key)
		s.managedUserTrafficMu.Unlock()
	}()

	if err := s.Sessions.Send(ctx, agentID, &controlv1.MasterFrame{
		Payload: &controlv1.MasterFrame_ManagedUserTrafficRequest{
			ManagedUserTrafficRequest: &controlv1.ManagedUserTrafficRequest{RequestId: requestID},
		},
	}); err != nil {
		return err
	}
	select {
	case err := <-waiter:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) handleManagedUserTrafficReport(
	ctx context.Context,
	agentID string,
	report *controlv1.ManagedUserTrafficReport,
) error {
	deltaReport := s.Sessions.Supports(agentID, ManagedUserTrafficDeltaCapability)
	legacyCumulativeReport := s.Sessions.Supports(agentID, ManagedUserTrafficCapability)
	if s.managedUserTrafficHandler == nil || (!deltaReport && !legacyCumulativeReport) {
		return status.Error(codes.FailedPrecondition, "managed-user traffic reporting is unavailable")
	}
	if report == nil || report.GetObservedAtUnix() == 0 ||
		len(report.GetUsers()) > 100000 || !validTrafficRequestID(report.GetRequestId()) ||
		len(report.GetDiagnostic()) > MaxDiagnosticBytes {
		return status.Error(codes.InvalidArgument, "invalid managed-user traffic report")
	}
	requestID := strings.TrimSpace(report.GetRequestId())
	if requestID != "" && !s.Sessions.Supports(agentID, ManagedUserTrafficRequestCapability) {
		return status.Error(codes.FailedPrecondition, "on-demand traffic reporting is unavailable")
	}
	if diagnostic := sanitizeAgentDiagnostic(report.GetDiagnostic()); diagnostic != "" {
		if strings.TrimSpace(report.GetEpoch()) != "" || len(report.GetUsers()) != 0 {
			return status.Error(codes.InvalidArgument, "invalid managed-user traffic failure report")
		}
		reportErr := fmt.Errorf("Agent could not collect managed-user traffic: %s", diagnostic)
		s.Logger.Warn("managed-user traffic collection failed", "agent_id", agentID, "error", diagnostic)
		s.recordManagedUserTrafficFailure(agentID, "collection_failed")
		s.deliverManagedUserTrafficResult(agentID, requestID, reportErr)
		return nil
	}
	if strings.TrimSpace(report.GetEpoch()) == "" {
		return status.Error(codes.InvalidArgument, "invalid managed-user traffic report")
	}

	users := make([]ManagedUserTraffic, 0, len(report.GetUsers()))
	for _, usage := range report.GetUsers() {
		if usage == nil {
			return status.Error(codes.InvalidArgument, "invalid managed-user traffic report")
		}
		users = append(users, ManagedUserTraffic{
			InboundPath: usage.GetInboundPath(), Username: usage.GetUsername(),
			UplinkBytes: usage.GetUplinkBytes(), DownlinkBytes: usage.GetDownlinkBytes(),
		})
	}
	if _, err := s.managedUserTrafficHandler(agentID, report.GetEpoch(), s.now(), users, deltaReport); err != nil {
		s.Logger.Error("persist managed-user traffic", "agent_id", agentID, "error", err)
		s.recordManagedUserTrafficFailure(agentID, "persistence_failed")
		s.deliverManagedUserTrafficResult(agentID, requestID, ErrManagedUserTrafficUnavailable)
		return status.Error(codes.Internal, "could not persist managed-user traffic")
	}

	if !deltaReport {
		ackUsers := make([]*controlv1.ManagedUserTraffic, 0, len(report.GetUsers()))
		for _, usage := range report.GetUsers() {
			ackUsers = append(ackUsers, &controlv1.ManagedUserTraffic{
				InboundPath: usage.GetInboundPath(), Username: usage.GetUsername(),
				UplinkBytes: usage.GetUplinkBytes(), DownlinkBytes: usage.GetDownlinkBytes(),
			})
		}
		if err := s.Sessions.Send(ctx, agentID, &controlv1.MasterFrame{
			Payload: &controlv1.MasterFrame_ManagedUserTrafficAck{
				ManagedUserTrafficAck: &controlv1.ManagedUserTrafficAck{
					Epoch: report.GetEpoch(), Users: ackUsers,
				},
			},
		}); err != nil {
			s.Logger.Warn("acknowledge managed-user traffic", "agent_id", agentID, "error", err)
		}
	}
	s.deliverManagedUserTrafficResult(agentID, requestID, nil)
	return nil
}

func (s *Server) recordManagedUserTrafficFailure(agentID, reason string) {
	if s.managedUserTrafficFailureHandler == nil {
		return
	}
	if err := s.managedUserTrafficFailureHandler(agentID, reason, s.now()); err != nil {
		s.Logger.Error("persist managed-user traffic failure history", "agent_id", agentID, "error", err)
	}
}

func validTrafficRequestID(requestID string) bool {
	requestID = strings.TrimSpace(requestID)
	return len(requestID) <= 128 && !strings.ContainsRune(requestID, '\x00')
}

func managedUserTrafficWaiterKey(agentID, requestID string) string {
	return agentID + "\x00" + requestID
}

func (s *Server) deliverManagedUserTrafficResult(agentID, requestID string, result error) bool {
	if requestID == "" {
		return false
	}
	key := managedUserTrafficWaiterKey(agentID, requestID)
	s.managedUserTrafficMu.Lock()
	waiter := s.managedUserTrafficWaiters[key]
	s.managedUserTrafficMu.Unlock()
	if waiter == nil {
		return false
	}
	select {
	case waiter <- result:
		return true
	default:
		return false
	}
}
