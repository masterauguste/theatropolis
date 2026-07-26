package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	ProtocolVersion        = 1
	DefaultChallengeTTL    = 30 * time.Second
	DefaultCommandQueue    = 16
	DefaultMaxConfigBytes  = 4 << 20
	DefaultValidationLimit = 60 * time.Second
	MaxDiagnosticBytes     = 8 << 10
)

var (
	ErrAgentOffline = errors.New("agent is not connected")
	ErrAgentOnline  = errors.New("agent is already connected")
)

type Server struct {
	controlv1.UnimplementedAgentControlServiceServer

	Identities  *identity.Registry
	Deployments deployment.Store
	Notifier    deployment.Notifier
	Sessions    *SessionRegistry
	Logger      *slog.Logger
	Now         func() time.Time
}

func NewServer(
	identities *identity.Registry,
	deployments deployment.Store,
	notifier deployment.Notifier,
	logger *slog.Logger,
) *Server {
	if notifier == nil {
		notifier = deployment.NopNotifier{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		Identities:  identities,
		Deployments: deployments,
		Notifier:    notifier,
		Sessions:    NewSessionRegistry(),
		Logger:      logger,
		Now:         time.Now,
	}
}

func (s *Server) Enroll(
	ctx context.Context,
	request *controlv1.EnrollRequest,
) (*controlv1.EnrollResponse, error) {
	if request == nil ||
		request.GetAgentId() == "" ||
		len(request.GetEnrollmentToken()) != identity.EnrollmentTokenBytes ||
		len(request.GetPublicKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid enrollment request")
	}

	now := s.now()
	if err := s.Identities.Enroll(
		ctx,
		request.GetAgentId(),
		request.GetEnrollmentToken(),
		request.GetPublicKey(),
		now,
	); err != nil {
		if errors.Is(err, identity.ErrInvalidAgentID) ||
			errors.Is(err, identity.ErrInvalidPublicKey) {
			return nil, status.Error(codes.InvalidArgument, "invalid enrollment request")
		}
		return nil, status.Error(codes.PermissionDenied, "enrollment was not accepted")
	}

	s.Logger.Info("agent enrolled", "agent_id", request.GetAgentId())
	return &controlv1.EnrollResponse{
		AgentId:        request.GetAgentId(),
		EnrolledAtUnix: now.Unix(),
	}, nil
}

func (s *Server) Connect(stream controlv1.AgentControlService_ConnectServer) error {
	ctx := stream.Context()
	firstFrame, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := firstFrame.GetHello()
	if hello == nil ||
		firstFrame.GetSequence() == 0 ||
		hello.GetAgentId() == "" ||
		hello.GetProtocolVersion() != ProtocolVersion {
		return status.Error(codes.InvalidArgument, "expected a compatible agent hello")
	}

	publicKey, err := s.Identities.PublicKey(ctx, hello.GetAgentId())
	if err != nil {
		return status.Error(codes.Unauthenticated, "agent authentication failed")
	}
	nonce, err := identity.NewChallenge()
	if err != nil {
		return status.Error(codes.Internal, "could not create authentication challenge")
	}
	expiresAt := s.now().Add(DefaultChallengeTTL)
	var masterSequence uint64 = 1
	if err := stream.Send(&controlv1.MasterFrame{
		Sequence: masterSequence,
		Payload: &controlv1.MasterFrame_Challenge{
			Challenge: &controlv1.AgentChallenge{
				Nonce:         nonce,
				ExpiresAtUnix: expiresAt.Unix(),
			},
		},
	}); err != nil {
		return err
	}

	proofFrame, err := receiveWithTimeout(stream, DefaultChallengeTTL)
	if err != nil {
		return err
	}
	proof := proofFrame.GetProof()
	authenticated := proof != nil &&
		proofFrame.GetSequence() > firstFrame.GetSequence() &&
		!s.now().After(expiresAt) &&
		identity.VerifyProof(publicKey, hello.GetAgentId(), nonce, proof.GetSignature())

	masterSequence++
	authResult := &controlv1.MasterFrame{
		Sequence: masterSequence,
		Payload: &controlv1.MasterFrame_AuthenticationResult{
			AuthenticationResult: &controlv1.AuthenticationResult{
				Authenticated: authenticated,
			},
		},
	}
	if !authenticated {
		authResult.GetAuthenticationResult().ErrorCode = "authentication_failed"
		_ = stream.Send(authResult)
		return status.Error(codes.Unauthenticated, "agent authentication failed")
	}
	if err := stream.Send(authResult); err != nil {
		return err
	}

	session := newSession(hello.GetAgentId())
	if err := s.Sessions.Register(session); err != nil {
		return status.Error(codes.AlreadyExists, "agent already has an active session")
	}
	defer s.Sessions.Unregister(session)
	s.Logger.Info("agent connected", "agent_id", hello.GetAgentId())
	defer s.Logger.Info("agent disconnected", "agent_id", hello.GetAgentId())

	incoming := make(chan receivedFrame, 1)
	go receiveFrames(stream, incoming)
	lastAgentSequence := proofFrame.GetSequence()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame := <-session.commands:
			masterSequence++
			frame.Sequence = masterSequence
			if err := stream.Send(frame); err != nil {
				return err
			}
		case received := <-incoming:
			if received.err != nil {
				return received.err
			}
			if received.frame.GetSequence() <= lastAgentSequence {
				return status.Error(codes.InvalidArgument, "agent sequence is not monotonic")
			}
			lastAgentSequence = received.frame.GetSequence()
			if err := s.handleAgentFrame(ctx, hello.GetAgentId(), received.frame); err != nil {
				return err
			}
		}
	}
}

func (s *Server) QueueValidation(
	ctx context.Context,
	agentID string,
	deploymentID string,
	revisionID string,
	config []byte,
	timeout time.Duration,
) (deployment.Record, error) {
	if len(config) == 0 || len(config) > DefaultMaxConfigBytes {
		return deployment.Record{}, errors.New("candidate configuration is empty or exceeds the size limit")
	}
	now := s.now()
	record, err := deployment.New(deploymentID, agentID, revisionID, config, now)
	if err != nil {
		return deployment.Record{}, err
	}
	if err := s.Deployments.Create(ctx, record); err != nil {
		return deployment.Record{}, err
	}

	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if timeout > DefaultValidationLimit {
		timeout = DefaultValidationLimit
	}
	validating, err := s.Deployments.Transition(
		ctx,
		record.ID,
		deployment.StatusValidating,
		"",
		s.now(),
	)
	if err != nil {
		return deployment.Record{}, err
	}
	command := &controlv1.MasterFrame{
		Payload: &controlv1.MasterFrame_ValidateConfig{
			ValidateConfig: &controlv1.ValidateConfigCommand{
				DeploymentId:   record.ID,
				RevisionId:     record.RevisionID,
				ConfigSha256:   record.ConfigSHA256[:],
				ConfigJson:     append([]byte(nil), config...),
				TimeoutSeconds: uint32(max(1, int(timeout/time.Second))),
			},
		},
	}
	if err := s.Sessions.Send(ctx, agentID, command); err != nil {
		failed, transitionErr := s.Deployments.Transition(
			ctx,
			record.ID,
			deployment.StatusDeliveryFailed,
			"agent is not connected",
			s.now(),
		)
		if transitionErr == nil {
			_ = s.Notifier.Notify(ctx, deployment.Event{
				Deployment: failed,
				Message:    "Configuration could not be delivered because the agent is offline.",
			})
			record = failed
		}
		return record, err
	}
	return validating, nil
}

func (s *Server) handleAgentFrame(
	ctx context.Context,
	agentID string,
	frame *controlv1.AgentFrame,
) error {
	switch payload := frame.GetPayload().(type) {
	case *controlv1.AgentFrame_Heartbeat:
		if payload.Heartbeat.GetObservedAtUnix() == 0 {
			return status.Error(codes.InvalidArgument, "invalid heartbeat")
		}
		return nil
	case *controlv1.AgentFrame_ConfigValidationReport:
		return s.handleValidationReport(ctx, agentID, payload.ConfigValidationReport)
	default:
		return status.Error(codes.InvalidArgument, "unexpected agent frame")
	}
}

func (s *Server) handleValidationReport(
	ctx context.Context,
	agentID string,
	report *controlv1.ConfigValidationReport,
) error {
	if report == nil {
		return status.Error(codes.InvalidArgument, "missing validation report")
	}
	if len(report.GetDiagnostic()) > MaxDiagnosticBytes*4 {
		return status.Error(codes.InvalidArgument, "validation diagnostic exceeds the wire limit")
	}
	record, err := s.Deployments.Get(ctx, report.GetDeploymentId())
	if err != nil {
		return status.Error(codes.NotFound, "deployment not found")
	}
	if record.AgentID != agentID ||
		record.RevisionID != report.GetRevisionId() ||
		!bytes.Equal(record.ConfigSHA256[:], report.GetConfigSha256()) {
		return status.Error(codes.PermissionDenied, "validation report does not match its deployment")
	}

	var next deployment.Status
	var userMessage string
	switch report.GetStatus() {
	case controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_VALID:
		next = deployment.StatusValidated
		userMessage = "Agent accepted the candidate configuration."
	case controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_INVALID:
		next = deployment.StatusValidationFailed
		userMessage = "Agent rejected the candidate configuration. Review the validation diagnostic."
	case controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_INTERNAL_ERROR:
		next = deployment.StatusInternalError
		userMessage = "Agent could not run sing-box validation."
	default:
		return status.Error(codes.InvalidArgument, "unknown validation status")
	}

	diagnostic := sanitizeAgentDiagnostic(report.GetDiagnostic())
	updated, err := s.Deployments.Transition(ctx, record.ID, next, diagnostic, s.now())
	if err != nil {
		return status.Error(codes.FailedPrecondition, "deployment is not awaiting validation")
	}
	if err := s.Notifier.Notify(ctx, deployment.Event{
		Deployment: updated,
		Message:    userMessage,
	}); err != nil {
		s.Logger.Error(
			"deployment notification failed",
			"deployment_id", record.ID,
			"agent_id", agentID,
			"error", err,
		)
	}

	level := slog.LevelInfo
	if next != deployment.StatusValidated {
		level = slog.LevelWarn
	}
	s.Logger.Log(
		ctx,
		level,
		"agent configuration validation completed",
		"agent_id", agentID,
		"deployment_id", record.ID,
		"status", next,
		"diagnostic", diagnostic,
	)
	return nil
}

func sanitizeAgentDiagnostic(diagnostic string) string {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, diagnostic)
	clean = strings.TrimSpace(clean)
	if len(clean) > MaxDiagnosticBytes {
		clean = clean[:MaxDiagnosticBytes] + "\n<diagnostic truncated by master>"
	}
	return clean
}

func (s *Server) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

type session struct {
	agentID  string
	commands chan *controlv1.MasterFrame
}

func newSession(agentID string) *session {
	return &session{
		agentID:  agentID,
		commands: make(chan *controlv1.MasterFrame, DefaultCommandQueue),
	}
}

type SessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{sessions: make(map[string]*session)}
}

func (r *SessionRegistry) Register(session *session) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sessions[session.agentID]; exists {
		return ErrAgentOnline
	}
	r.sessions[session.agentID] = session
	return nil
}

func (r *SessionRegistry) Unregister(session *session) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing := r.sessions[session.agentID]; existing == session {
		delete(r.sessions, session.agentID)
	}
}

func (r *SessionRegistry) Send(
	ctx context.Context,
	agentID string,
	frame *controlv1.MasterFrame,
) error {
	r.mu.RLock()
	session, exists := r.sessions[agentID]
	r.mu.RUnlock()
	if !exists {
		return ErrAgentOffline
	}

	select {
	case session.commands <- frame:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *SessionRegistry) IsOnline(agentID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.sessions[agentID]
	return exists
}

type receivedFrame struct {
	frame *controlv1.AgentFrame
	err   error
}

func receiveFrames(
	stream controlv1.AgentControlService_ConnectServer,
	output chan<- receivedFrame,
) {
	for {
		frame, err := stream.Recv()
		select {
		case output <- receivedFrame{frame: frame, err: err}:
		case <-stream.Context().Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func receiveWithTimeout(
	stream controlv1.AgentControlService_ConnectServer,
	timeout time.Duration,
) (*controlv1.AgentFrame, error) {
	result := make(chan receivedFrame, 1)
	go func() {
		frame, err := stream.Recv()
		result <- receivedFrame{frame: frame, err: err}
	}()

	select {
	case received := <-result:
		return received.frame, received.err
	case <-time.After(timeout):
		return nil, status.Error(codes.DeadlineExceeded, "agent authentication timed out")
	case <-stream.Context().Done():
		return nil, stream.Context().Err()
	}
}

func ValidationStatusFromResult(value string) (controlv1.ConfigValidationStatus, error) {
	switch value {
	case "valid":
		return controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_VALID, nil
	case "invalid":
		return controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_INVALID, nil
	case "internal_error":
		return controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_INTERNAL_ERROR, nil
	default:
		return controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_UNSPECIFIED,
			fmt.Errorf("unknown validation result %q", value)
	}
}

func ConfigDigest(config []byte) [sha256.Size]byte {
	return sha256.Sum256(config)
}
