package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"github.com/masterauguste/theatropolis/internal/singboxupdate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	ProtocolVersion                     = 2
	ConfigDeployCapability              = "config-deploy-v1"
	ProxyNodeDeployCapability           = "proxy-node-config-v1"
	AgentUpdateCapability               = "agent-update-v1"
	SingBoxUpdateCapability             = "sing-box-update-v1"
	HeartbeatCapability                 = "heartbeat-v1"
	CapabilityAddressReport             = "address-report-v1"
	CapabilityAddressProbe              = "address-probe-v1"
	ManagedUserTrafficCapability        = "managed-user-traffic-v1"
	ManagedUserTrafficDeltaCapability   = "managed-user-traffic-delta-v1"
	ManagedUserTrafficRequestCapability = "managed-user-traffic-request-v1"
	ManagedUserAuthorityCapability      = "managed-user-authority-v1"
	MasterMigrationCapability           = "master-migration-v1"
	DefaultChallengeTTL                 = 30 * time.Second
	DefaultHelloTimeout                 = 10 * time.Second
	DefaultCommandQueue                 = 16
	DefaultMaxConfigBytes               = 4 << 20
	DefaultValidationLimit              = 60 * time.Second
	DeploymentReportGrace               = 2 * time.Minute
	MaxDiagnosticBytes                  = 8 << 10
	DefaultHeartbeatTimeout             = 75 * time.Second
)

var (
	ErrAgentOffline = errors.New("agent is not connected")
	ErrAgentOnline  = errors.New("agent is already connected")
)

type Server struct {
	controlv1.UnimplementedAgentControlServiceServer

	Identities       *identity.Registry
	Deployments      deployment.Store
	Notifier         deployment.Notifier
	Sessions         *SessionRegistry
	Logger           *slog.Logger
	Now              func() time.Time
	HeartbeatTimeout time.Duration
	HelloTimeout     time.Duration

	// poolRegistry is the fleet-wide outbound pool. It may be nil (unit
	// tests); every pool code path degrades to a no-op in that case, which
	// leaves configurations passing through unrendered.
	poolRegistry *pool.Registry

	// probedMu guards probedShadow, the control plane's copy of the probed
	// address lists it wrote via pool.SetProbed. See mergeProbedAddress.
	probedMu     sync.Mutex
	probedShadow map[string]*probedAddressState

	// authorizationMu linearizes enrollment, the final Connect authorization
	// check/session registration, and revocation. Without this barrier a
	// Connect call could authenticate with a public key fetched just before
	// that key was revoked, then register a live session afterward.
	authorizationMu                  sync.Mutex
	updateMu                         sync.RWMutex
	updates                          map[string]AgentUpdateState
	singBoxUpdates                   map[string]SingBoxUpdateState
	managedUserTrafficHandler        func(string, string, time.Time, []ManagedUserTraffic, bool) (bool, error)
	managedUserTrafficFailureHandler func(string, string, time.Time) error
	managedUserTrafficMu             sync.Mutex
	managedUserTrafficWaiters        map[string]chan error
	proxyNodeAddressHandler          func()
	proxyNodeUserHandler             func()
	authoritativeProfileProvider     func(context.Context, string) ([]byte, bool, error)
	managedUserAuthorityMu           sync.Mutex
	managedUserAuthorityWaiters      map[string]chan *controlv1.ManagedUserAuthorityReport
	closeOnce                        sync.Once
}

type ManagedUserTraffic struct {
	InboundPath   string
	Username      string
	UplinkBytes   uint64
	DownlinkBytes uint64
}

func NewServer(
	identities *identity.Registry,
	deployments deployment.Store,
	poolRegistry *pool.Registry,
	notifier deployment.Notifier,
	logger *slog.Logger,
) *Server {
	if notifier == nil {
		notifier = deployment.NopNotifier{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{
		Identities:                  identities,
		Deployments:                 deployments,
		poolRegistry:                poolRegistry,
		Notifier:                    notifier,
		Sessions:                    NewSessionRegistry(),
		Logger:                      logger,
		Now:                         time.Now,
		HeartbeatTimeout:            DefaultHeartbeatTimeout,
		HelloTimeout:                DefaultHelloTimeout,
		probedShadow:                make(map[string]*probedAddressState),
		updates:                     make(map[string]AgentUpdateState),
		singBoxUpdates:              make(map[string]SingBoxUpdateState),
		managedUserAuthorityWaiters: make(map[string]chan *controlv1.ManagedUserAuthorityReport),
		managedUserTrafficWaiters:   make(map[string]chan error),
	}
	return server
}

// Close remains idempotent for callers that share the server lifecycle.
func (s *Server) Close() {
	s.closeOnce.Do(func() {})
}

// SetManagedUserTrafficHandler connects authenticated agent counter reports to
// the master-owned quota store. It must be called before serving gRPC.
func (s *Server) SetManagedUserTrafficHandler(
	handler func(string, string, time.Time, []ManagedUserTraffic, bool) (bool, error),
) {
	s.managedUserTrafficHandler = handler
}

// SetManagedUserTrafficFailureHandler persists bounded, non-sensitive
// accounting failure history. Operational logging remains active if the
// history store itself is unavailable.
func (s *Server) SetManagedUserTrafficFailureHandler(handler func(string, string, time.Time) error) {
	s.managedUserTrafficFailureHandler = handler
}

// SetProxyNodeAddressHandler connects every persisted pool/address mutation to
// Proxy Node reconciliation. It must be installed before serving gRPC.
func (s *Server) SetProxyNodeAddressHandler(handler func()) {
	s.proxyNodeAddressHandler = handler
}

// SetProxyNodeUserHandler requests a fresh independent user-plane sync after
// an Agent reconnects. The callback must return quickly; it is invoked in its
// own goroutine after the authenticated send loop is ready.
func (s *Server) SetProxyNodeUserHandler(handler func()) {
	s.proxyNodeUserHandler = handler
}

// SetAuthoritativeProfileProvider lets the Proxy Node store rebuild the
// currently applied topology with the running master's compiler. Historical
// deployment records remain the fallback for Agents outside that store.
func (s *Server) SetAuthoritativeProfileProvider(
	provider func(context.Context, string) ([]byte, bool, error),
) {
	s.authoritativeProfileProvider = provider
}

// PoolRegistry exposes the outbound-pool registry so master-local callers
// (the web interface) can manage manual entries. It may be nil.
func (s *Server) PoolRegistry() *pool.Registry {
	return s.poolRegistry
}

// DeploymentRecords lists the latest stored deployment record per agent so
// master-local callers (the web interface's outbound-pool view) can derive
// pool entries without reaching the store directly.
func (s *Server) DeploymentRecords(ctx context.Context) ([]deployment.Record, error) {
	return s.Deployments.List(ctx)
}

// PropagateManualPoolChange re-renders and redeploys every agent whose
// logical configuration references pool entries after a manual entry was
// upserted or removed through PoolRegistry. It never returns an error:
// per-agent failures are logged and the stale pool-version check on agent
// reconnect is the backstop.
func (s *Server) PropagateManualPoolChange(ctx context.Context) {
	s.propagatePoolChange(ctx, "manual pool change", "")
	s.notifyProxyNodeAddressChange()
}

func (s *Server) notifyProxyNodeAddressChange() {
	if s.proxyNodeAddressHandler != nil {
		s.proxyNodeAddressHandler()
	}
}

func (s *Server) Enroll(
	ctx context.Context,
	request *controlv1.EnrollRequest,
) (*controlv1.EnrollResponse, error) {
	if request == nil ||
		len(request.GetEnrollmentToken()) != identity.EnrollmentTokenBytes ||
		len(request.GetPublicKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid enrollment request")
	}

	now := s.now()
	s.authorizationMu.Lock()
	agentID, err := s.Identities.EnrollByToken(
		ctx,
		request.GetEnrollmentToken(),
		request.GetPublicKey(),
		now,
	)
	disconnectedPrevious := false
	if err == nil {
		// A replacement token atomically changes the authorized key. Disconnect
		// any session using the previous key before releasing authorizationMu.
		disconnectedPrevious = s.Sessions.Disconnect(agentID)
	}
	s.authorizationMu.Unlock()
	if err != nil {
		if errors.Is(err, identity.ErrInvalidPublicKey) {
			return nil, status.Error(codes.InvalidArgument, "invalid enrollment request")
		}
		return nil, status.Error(codes.PermissionDenied, "enrollment was not accepted")
	}

	s.Logger.Info(
		"agent enrolled",
		"agent_id", agentID,
		"replaced_active_session", disconnectedPrevious,
	)
	return &controlv1.EnrollResponse{
		EnrolledAtUnix: now.Unix(),
	}, nil
}

// RevokeAgent durably revokes every enrollment credential for agentID and
// invalidates its active control session before returning. It is the
// revocation entry point for master-local callers such as the web interface.
func (s *Server) RevokeAgent(ctx context.Context, agentID string) error {
	s.authorizationMu.Lock()
	if err := s.Deployments.RemoveAgent(ctx, agentID); err != nil &&
		!errors.Is(err, deployment.ErrNotFound) {
		s.authorizationMu.Unlock()
		return fmt.Errorf("remove agent deployment data: %w", err)
	}
	if err := s.Identities.Revoke(ctx, agentID); err != nil {
		s.authorizationMu.Unlock()
		return err
	}
	connected := s.Sessions.Disconnect(agentID)
	s.authorizationMu.Unlock()
	s.Logger.Info(
		"agent revoked",
		"agent_id", agentID,
		"was_connected", connected,
	)

	// Pool cleanup and dependent propagation run after authorizationMu is
	// released: propagatePoolChange reaches QueueDeployment, which acquires
	// that same mutex.
	if s.poolRegistry != nil {
		if err := s.poolRegistry.RemoveAgent(agentID); err != nil {
			s.Logger.Error(
				"remove agent from outbound pool failed",
				"agent_id", agentID,
				"error", err,
			)
		}
		s.propagatePoolChange(ctx, "agent revoked", agentID)
		s.notifyProxyNodeAddressChange()
	}
	return nil
}

func (s *Server) Connect(stream controlv1.AgentControlService_ConnectServer) error {
	ctx := stream.Context()
	firstFrame, err := receiveWithTimeout(stream, s.helloTimeout())
	if err != nil {
		return err
	}
	hello := firstFrame.GetHello()
	if hello == nil ||
		firstFrame.GetSequence() == 0 ||
		len(hello.GetPublicKey()) != ed25519.PublicKeySize ||
		hello.GetProtocolVersion() != ProtocolVersion ||
		!validCapabilities(hello.GetCapabilities()) ||
		!validAgentMetadata(hello) {
		return status.Error(codes.InvalidArgument, "expected a compatible agent hello")
	}

	publicKey := append([]byte(nil), hello.GetPublicKey()...)
	agentID, err := s.Identities.AgentIDForPublicKey(ctx, publicKey)
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
		identity.VerifyProof(publicKey, nonce, proof.GetSignature())

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

	session := newSessionFromHello(agentID, hello)
	for _, capability := range hello.GetCapabilities() {
		session.capabilities[capability] = struct{}{}
	}
	s.authorizationMu.Lock()
	currentAgentID, currentKeyErr := s.Identities.AgentIDForPublicKey(ctx, publicKey)
	stillAuthorized := currentKeyErr == nil && currentAgentID == agentID
	var registerErr error
	if stillAuthorized {
		registerErr = s.Sessions.Register(session)
	}
	s.authorizationMu.Unlock()
	if !stillAuthorized {
		authResult.GetAuthenticationResult().Authenticated = false
		authResult.GetAuthenticationResult().ErrorCode = "authentication_failed"
		_ = stream.Send(authResult)
		return status.Error(codes.Unauthenticated, "agent authentication failed")
	}
	if registerErr != nil {
		authResult.GetAuthenticationResult().Authenticated = false
		authResult.GetAuthenticationResult().ErrorCode = "already_connected"
		_ = stream.Send(authResult)
		return status.Error(codes.AlreadyExists, "agent already has an active session")
	}
	defer s.Sessions.Unregister(session)
	// authorizationMu is released at this point; the calls below may reach
	// QueueDeployment, which acquires it.
	s.syncPoolAddresses(ctx, agentID, session.info.ReportedIPv4, session.info.ReportedIPv6)
	s.syncObservedAddress(ctx, agentID, observedAddress(ctx))
	if err := s.syncProfileOnConnect(ctx, agentID); err != nil {
		s.Logger.Error(
			"authoritative Agent profile could not be queued",
			"agent_id", agentID,
			"error", err,
		)
		return status.Error(codes.Internal, "could not synchronize Agent profile")
	}
	outgoing := make(chan *controlv1.MasterFrame)
	sendResults := make(chan error, 1)
	go sendMasterFrames(stream, outgoing, sendResults)
	if err := sendAuthorizedMasterFrame(
		stream.Context(),
		session.done,
		outgoing,
		sendResults,
		authResult,
	); err != nil {
		return err
	}
	if s.proxyNodeUserHandler != nil && s.Sessions.Supports(agentID, ManagedUserAuthorityCapability) {
		go s.proxyNodeUserHandler()
	}
	s.Logger.Info("agent connected", "agent_id", agentID)
	defer s.Logger.Info("agent disconnected", "agent_id", agentID)

	incoming := make(chan receivedFrame, 1)
	go receiveFrames(stream, incoming)
	lastAgentSequence := proofFrame.GetSequence()
	var heartbeatTimer *time.Timer
	var heartbeatDeadline <-chan time.Time
	if _, supported := session.capabilities[HeartbeatCapability]; supported {
		heartbeatTimer = time.NewTimer(s.heartbeatTimeout())
		defer heartbeatTimer.Stop()
		heartbeatDeadline = heartbeatTimer.C
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-session.done:
			return status.Error(codes.Unauthenticated, "agent authorization was revoked")
		case <-heartbeatDeadline:
			return status.Error(codes.DeadlineExceeded, "agent heartbeat timed out")
		case frame := <-session.commands:
			select {
			case <-session.done:
				return status.Error(codes.Unauthenticated, "agent authorization was revoked")
			default:
			}
			masterSequence++
			frame.Sequence = masterSequence
			if err := sendAuthorizedMasterFrame(
				ctx,
				session.done,
				outgoing,
				sendResults,
				frame,
			); err != nil {
				return err
			}
		case received := <-incoming:
			select {
			case <-session.done:
				return status.Error(codes.Unauthenticated, "agent authorization was revoked")
			default:
			}
			if received.err != nil {
				return received.err
			}
			if received.frame.GetSequence() <= lastAgentSequence {
				return status.Error(codes.InvalidArgument, "agent sequence is not monotonic")
			}
			lastAgentSequence = received.frame.GetSequence()
			resetTimer(heartbeatTimer, s.heartbeatTimeout())
			if err := s.handleAgentFrame(ctx, agentID, received.frame); err != nil {
				return err
			}
		}
	}
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}

func (s *Server) heartbeatTimeout() time.Duration {
	if s.HeartbeatTimeout <= 0 {
		return DefaultHeartbeatTimeout
	}
	return s.HeartbeatTimeout
}

func (s *Server) helloTimeout() time.Duration {
	if s.HelloTimeout <= 0 {
		return DefaultHelloTimeout
	}
	return s.HelloTimeout
}

type masterFrameSender interface {
	Send(*controlv1.MasterFrame) error
	Context() context.Context
}

func sendMasterFrames(
	stream masterFrameSender,
	input <-chan *controlv1.MasterFrame,
	results chan<- error,
) {
	for {
		var frame *controlv1.MasterFrame
		select {
		case <-stream.Context().Done():
			return
		case frame = <-input:
		}
		err := stream.Send(frame)
		select {
		case results <- err:
		case <-stream.Context().Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func sendAuthorizedMasterFrame(
	ctx context.Context,
	authorizationDone <-chan struct{},
	output chan<- *controlv1.MasterFrame,
	results <-chan error,
	frame *controlv1.MasterFrame,
) error {
	select {
	case <-authorizationDone:
		return status.Error(codes.Unauthenticated, "agent authorization was revoked")
	default:
	}
	select {
	case output <- frame:
	case <-authorizationDone:
		return status.Error(codes.Unauthenticated, "agent authorization was revoked")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-results:
		if err != nil {
			return err
		}
		select {
		case <-authorizationDone:
			return status.Error(codes.Unauthenticated, "agent authorization was revoked")
		default:
			return nil
		}
	case <-authorizationDone:
		return status.Error(codes.Unauthenticated, "agent authorization was revoked")
	case <-ctx.Done():
		return ctx.Err()
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
	// config is the logical document and may contain pool refs. Only the
	// rendered document is size/policy checked, digested, and sent to the
	// agent; the record keeps the logical bytes plus the rendered digest.
	rendered, renderedSHA, err := s.renderLogicalConfig(config)
	if err != nil {
		return deployment.Record{}, err
	}
	if len(rendered) == 0 || len(rendered) > DefaultMaxConfigBytes {
		return deployment.Record{}, errors.New("candidate configuration is empty or exceeds the size limit")
	}
	if err := singbox.ValidateManagedConfig(rendered); err != nil {
		return deployment.Record{}, err
	}
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	now := s.now()
	record, err := deployment.New(deploymentID, agentID, revisionID, config, now)
	if err != nil {
		return deployment.Record{}, err
	}
	record.RenderedSHA256 = renderedSHA
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
				ConfigSha256:   renderedSHA[:],
				ConfigJson:     append([]byte(nil), rendered...),
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

func (s *Server) QueueDeployment(
	ctx context.Context,
	agentID string,
	deploymentID string,
	revisionID string,
	config []byte,
	timeout time.Duration,
) (deployment.Record, error) {
	// config is the logical document and may contain pool refs. Only the
	// rendered document is size/policy checked, digested, and sent to the
	// agent; the record keeps the logical bytes plus the rendered digest.
	rendered, renderedSHA, err := s.renderLogicalConfig(config)
	if err != nil {
		return deployment.Record{}, err
	}
	if len(rendered) == 0 || len(rendered) > DefaultMaxConfigBytes {
		return deployment.Record{}, errors.New("candidate configuration is empty or exceeds the size limit")
	}
	if err := singbox.ValidateManagedConfig(rendered); err != nil {
		return deployment.Record{}, err
	}
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	if _, err := s.Identities.PublicKey(ctx, agentID); err != nil {
		return deployment.Record{}, err
	}
	if !s.CanDeployProxyNodeConfiguration(agentID) {
		return deployment.Record{}, ErrAgentOffline
	}
	if current, err := s.Deployments.LatestForAgent(ctx, agentID); err == nil {
		switch current.Status {
		case deployment.StatusQueued,
			deployment.StatusValidating,
			deployment.StatusDeploying:
			if s.now().Before(current.UpdatedAt.Add(DeploymentReportGrace)) {
				return deployment.Record{}, deployment.ErrDeploymentInProgress
			}
			if _, err := s.Deployments.Transition(
				ctx,
				current.ID,
				deployment.StatusDeliveryFailed,
				"agent did not report a result before the deployment deadline",
				s.now(),
			); err != nil {
				return deployment.Record{}, err
			}
		}
	} else if !errors.Is(err, deployment.ErrNotFound) {
		return deployment.Record{}, err
	}

	now := s.now()
	record, err := deployment.New(deploymentID, agentID, revisionID, config, now)
	if err != nil {
		return deployment.Record{}, err
	}
	record.RenderedSHA256 = renderedSHA
	if err := s.Deployments.Create(ctx, record); err != nil {
		return deployment.Record{}, err
	}
	deploying, err := s.Deployments.Transition(
		ctx,
		record.ID,
		deployment.StatusDeploying,
		"",
		s.now(),
	)
	if err != nil {
		return deployment.Record{}, err
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if timeout > DefaultValidationLimit {
		timeout = DefaultValidationLimit
	}
	command := &controlv1.MasterFrame{
		Payload: &controlv1.MasterFrame_DeployConfig{
			DeployConfig: &controlv1.DeployConfigCommand{
				DeploymentId:   record.ID,
				RevisionId:     record.RevisionID,
				ConfigSha256:   renderedSHA[:],
				ConfigJson:     append([]byte(nil), rendered...),
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
	return deploying, nil
}

func (s *Server) LatestDeployment(
	ctx context.Context,
	agentID string,
) (deployment.Record, error) {
	record, err := s.Deployments.LatestForAgent(ctx, agentID)
	if err != nil {
		return deployment.Record{}, err
	}
	if !awaitingDeploymentReport(record.Status) ||
		s.now().Before(record.UpdatedAt.Add(DeploymentReportGrace)) {
		return record, nil
	}

	failed, err := s.Deployments.Transition(
		ctx,
		record.ID,
		deployment.StatusDeliveryFailed,
		"agent did not report a result before the deployment deadline",
		s.now(),
	)
	if errors.Is(err, deployment.ErrInvalidTransition) {
		return s.Deployments.LatestForAgent(ctx, agentID)
	}
	if err != nil {
		return deployment.Record{}, err
	}
	if err := s.Notifier.Notify(ctx, deployment.Event{
		Deployment: failed,
		Message:    "The agent did not report a configuration result before the deadline.",
	}); err != nil {
		s.Logger.Error(
			"stale deployment notification failed",
			"deployment_id", record.ID,
			"agent_id", agentID,
			"error", err,
		)
	}
	return failed, nil
}

func awaitingDeploymentReport(status deployment.Status) bool {
	switch status {
	case deployment.StatusQueued,
		deployment.StatusValidating,
		deployment.StatusDeploying:
		return true
	default:
		return false
	}
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
		s.Sessions.SetSingBoxVersion(
			agentID,
			payload.Heartbeat.GetSingBoxVersion(),
		)
		reportedV4, reportedV6 := sanitizeReportedAddresses(
			payload.Heartbeat.GetReportedAddresses(),
		)
		if s.Sessions.SetReportedAddresses(agentID, reportedV4, reportedV6) {
			s.syncPoolAddresses(ctx, agentID, reportedV4, reportedV6)
		}
		return nil
	case *controlv1.AgentFrame_ConfigValidationReport:
		return s.handleValidationReport(ctx, agentID, payload.ConfigValidationReport)
	case *controlv1.AgentFrame_ConfigDeploymentReport:
		return s.handleDeploymentReport(ctx, agentID, payload.ConfigDeploymentReport)
	case *controlv1.AgentFrame_ConfigRuntimeReport:
		return s.handleRuntimeReport(ctx, agentID, payload.ConfigRuntimeReport)
	case *controlv1.AgentFrame_AgentUpdateReport:
		return s.handleAgentUpdateReport(agentID, payload.AgentUpdateReport)
	case *controlv1.AgentFrame_SingBoxUpdateReport:
		return s.handleSingBoxUpdateReport(
			agentID,
			payload.SingBoxUpdateReport,
		)
	case *controlv1.AgentFrame_AddressProbeReport:
		return s.handleAddressProbeReport(ctx, agentID, payload.AddressProbeReport)
	case *controlv1.AgentFrame_ManagedUserTrafficReport:
		return s.handleManagedUserTrafficReport(ctx, agentID, payload.ManagedUserTrafficReport)
	case *controlv1.AgentFrame_ManagedUserAuthorityReport:
		if !s.Sessions.Supports(agentID, ManagedUserAuthorityCapability) {
			return status.Error(codes.FailedPrecondition, "managed-user authority is unavailable")
		}
		report := payload.ManagedUserAuthorityReport
		if report == nil || strings.TrimSpace(report.GetRequestId()) == "" || report.GetUserRevision() == 0 ||
			report.GetCompletedAtUnix() == 0 || len(report.GetDiagnostic()) > MaxDiagnosticBytes {
			return status.Error(codes.InvalidArgument, "invalid managed-user authority report")
		}
		key := managedUserAuthorityWaiterKey(agentID, report.GetRequestId())
		s.managedUserAuthorityMu.Lock()
		waiter := s.managedUserAuthorityWaiters[key]
		s.managedUserAuthorityMu.Unlock()
		if waiter != nil {
			select {
			case waiter <- report:
			default:
			}
		}
		return nil
	case *controlv1.AgentFrame_MasterMigrationReport:
		report := payload.MasterMigrationReport
		if !s.Sessions.Supports(agentID, MasterMigrationCapability) || report == nil ||
			strings.TrimSpace(report.GetMigrationId()) == "" || len(report.GetMigrationId()) > 128 || len(report.GetErrorCode()) > 128 {
			return status.Error(codes.InvalidArgument, "invalid Master migration report")
		}
		level := slog.LevelInfo
		if !report.GetAccepted() {
			level = slog.LevelWarn
		}
		s.Logger.Log(ctx, level, "Agent processed Master migration", "agent_id", agentID,
			"migration_id", report.GetMigrationId(), "accepted", report.GetAccepted(), "error_code", report.GetErrorCode())
		if report.GetAccepted() {
			// Closing only after the report is processed is the migration
			// acknowledgement. The Agent then exits and systemd restarts it
			// against its durably staged new control address.
			s.Sessions.Disconnect(agentID)
		}
		return nil
	default:
		return status.Error(codes.InvalidArgument, "unexpected agent frame")
	}
}

// QueueOnlineMasterMigration sends a non-persistent cutover command only to
// Agents that are connected and advertise support. Offline and older Agents
// remain untouched and can be reinstalled manually.
func (s *Server) QueueOnlineMasterMigration(ctx context.Context, migrationID, address string) (queued, skipped int, err error) {
	migrationID = strings.TrimSpace(migrationID)
	address = strings.TrimSpace(address)
	if migrationID == "" || len(migrationID) > 128 || address == "" || len(address) > 512 {
		return 0, 0, errors.New("invalid Master migration command")
	}
	for _, snapshot := range s.Identities.Snapshot(s.now()) {
		if snapshot.State != identity.AgentStateEnrolled || !s.Sessions.IsOnline(snapshot.ID) ||
			!s.Sessions.Supports(snapshot.ID, MasterMigrationCapability) {
			skipped++
			continue
		}
		frame := &controlv1.MasterFrame{Payload: &controlv1.MasterFrame_MigrateMaster{
			MigrateMaster: &controlv1.MigrateMasterCommand{MigrationId: migrationID, MasterAddress: address},
		}}
		if sendErr := s.Sessions.Send(ctx, snapshot.ID, frame); sendErr != nil {
			skipped++
			continue
		}
		queued++
	}
	return queued, skipped, nil
}

// QueueManagedUserAuthority sends a revisioned end-user authority command
// without creating or waiting behind a topology deployment record.
func (s *Server) QueueManagedUserAuthority(
	ctx context.Context,
	agentID string,
	revision uint64,
	variants []singbox.ManagedUserAuthorityVariant,
) error {
	if ctx == nil || revision == 0 || len(variants) == 0 ||
		!s.Sessions.Supports(agentID, ManagedUserAuthorityCapability) {
		return ErrAgentOffline
	}
	requestID, err := randomOpaqueID("usr")
	if err != nil {
		return err
	}
	command := &controlv1.ManagedUserAuthorityCommand{RequestId: requestID, UserRevision: revision}
	for _, variant := range variants {
		item := &controlv1.ManagedUserAuthorityVariant{TopologySha256: append([]byte(nil), variant.TopologySHA256[:]...)}
		for _, endpoint := range variant.Endpoints {
			endpointItem := &controlv1.ManagedUserAuthorityEndpoint{InboundPath: endpoint.Path}
			for _, user := range endpoint.Users {
				endpointItem.Users = append(endpointItem.Users, &controlv1.ManagedUserAuthorityUser{
					Username: user.Username, Password: user.Password,
				})
			}
			item.Endpoints = append(item.Endpoints, endpointItem)
		}
		command.Variants = append(command.Variants, item)
	}
	waiter := make(chan *controlv1.ManagedUserAuthorityReport, 1)
	key := managedUserAuthorityWaiterKey(agentID, requestID)
	s.managedUserAuthorityMu.Lock()
	s.managedUserAuthorityWaiters[key] = waiter
	s.managedUserAuthorityMu.Unlock()
	defer func() {
		s.managedUserAuthorityMu.Lock()
		delete(s.managedUserAuthorityWaiters, key)
		s.managedUserAuthorityMu.Unlock()
	}()
	if err := s.Sessions.Send(ctx, agentID, &controlv1.MasterFrame{
		Payload: &controlv1.MasterFrame_ManagedUserAuthority{ManagedUserAuthority: command},
	}); err != nil {
		return err
	}
	select {
	case report := <-waiter:
		if report.GetUserRevision() != revision {
			return errors.New("Agent reported a mismatched managed-user revision")
		}
		if report.GetStatus() != controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_APPLIED {
			diagnostic := strings.TrimSpace(report.GetDiagnostic())
			if diagnostic == "" {
				diagnostic = "Agent rejected managed-user authority"
			}
			if diagnostic == singbox.ManagedUserAuthorityTopologyMismatchDiagnostic {
				if repairErr := s.queueAuthoritativeProfile(
					ctx,
					agentID,
					"managed-user authority did not match the active topology",
				); repairErr != nil {
					return fmt.Errorf("%s; authoritative profile repair failed: %w", diagnostic, repairErr)
				}
				return errors.New("Agent topology was stale; authoritative profile repair queued")
			}
			return errors.New(diagnostic)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func managedUserAuthorityWaiterKey(agentID, requestID string) string {
	return agentID + "\x00" + requestID
}

type SingBoxUpdateState struct {
	RequestID      string
	TargetVersion  string
	RunningVersion string
	Status         string
	Diagnostic     string
	UpdatedAt      time.Time
}

func (s *Server) QueueSingBoxUpdate(
	ctx context.Context,
	agentID string,
	requestID string,
	targetVersion string,
) error {
	if !singboxupdate.ValidVersion(targetVersion) {
		return errors.New("target sing-box version is invalid")
	}
	if !singboxupdate.ValidRequestID(requestID) {
		return errors.New("sing-box update request ID is invalid")
	}
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	if _, err := s.Identities.PublicKey(ctx, agentID); err != nil {
		return err
	}
	if !s.Sessions.Supports(agentID, SingBoxUpdateCapability) {
		return ErrAgentOffline
	}
	info, _ := s.Sessions.AgentInfo(agentID)
	state := SingBoxUpdateState{
		RequestID:      requestID,
		TargetVersion:  targetVersion,
		RunningVersion: info.SingBoxVersion,
		Status:         "requested",
		UpdatedAt:      s.now(),
	}
	s.updateMu.Lock()
	previous, hadPrevious := s.singBoxUpdates[agentID]
	if hadPrevious &&
		(previous.Status == "requested" || previous.Status == "scheduled") {
		s.updateMu.Unlock()
		return singboxupdate.ErrUpdatePending
	}
	s.singBoxUpdates[agentID] = state
	s.updateMu.Unlock()
	err := s.Sessions.Send(ctx, agentID, &controlv1.MasterFrame{
		Payload: &controlv1.MasterFrame_UpdateSingBox{
			UpdateSingBox: &controlv1.SingBoxUpdateCommand{
				RequestId:     requestID,
				TargetVersion: targetVersion,
			},
		},
	})
	if err != nil {
		s.updateMu.Lock()
		if hadPrevious {
			s.singBoxUpdates[agentID] = previous
		} else {
			delete(s.singBoxUpdates, agentID)
		}
		s.updateMu.Unlock()
		return err
	}
	return nil
}

func (s *Server) LatestSingBoxUpdate(
	agentID string,
) (SingBoxUpdateState, bool) {
	s.updateMu.RLock()
	defer s.updateMu.RUnlock()
	state, exists := s.singBoxUpdates[agentID]
	return state, exists
}

func (s *Server) handleSingBoxUpdateReport(
	agentID string,
	report *controlv1.SingBoxUpdateReport,
) error {
	if report == nil ||
		!singboxupdate.ValidRequestID(report.GetRequestId()) ||
		!singboxupdate.ValidVersion(report.GetTargetVersion()) ||
		report.GetObservedAtUnix() <= 0 ||
		len(report.GetDiagnostic()) > MaxDiagnosticBytes*4 {
		return status.Error(codes.InvalidArgument, "invalid sing-box update report")
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	current, exists := s.singBoxUpdates[agentID]
	if !exists || current.RequestID != report.GetRequestId() ||
		current.TargetVersion != report.GetTargetVersion() {
		return status.Error(
			codes.PermissionDenied,
			"sing-box update report does not match its request",
		)
	}
	switch report.GetStatus() {
	case controlv1.SingBoxUpdateStatus_SING_BOX_UPDATE_STATUS_SCHEDULED:
		current.Status = "scheduled"
	case controlv1.SingBoxUpdateStatus_SING_BOX_UPDATE_STATUS_APPLIED:
		current.Status = "applied"
	case controlv1.SingBoxUpdateStatus_SING_BOX_UPDATE_STATUS_FAILED:
		current.Status = "failed"
	case controlv1.SingBoxUpdateStatus_SING_BOX_UPDATE_STATUS_REJECTED:
		current.Status = "rejected"
	default:
		return status.Error(codes.InvalidArgument, "unknown sing-box update status")
	}
	current.RunningVersion = report.GetRunningVersion()
	current.Diagnostic = sanitizeAgentDiagnostic(report.GetDiagnostic())
	current.UpdatedAt = time.Unix(report.GetObservedAtUnix(), 0).UTC()
	s.singBoxUpdates[agentID] = current
	if report.GetRunningVersion() != "" {
		s.Sessions.SetSingBoxVersion(agentID, report.GetRunningVersion())
	}
	return nil
}

type AgentUpdateState struct {
	RequestID      string
	TargetVersion  string
	RunningVersion string
	Status         string
	Diagnostic     string
	UpdatedAt      time.Time
}

func (s *Server) QueueAgentUpdate(
	ctx context.Context,
	agentID string,
	requestID string,
	targetVersion string,
) error {
	if !agentupdate.ValidVersion(targetVersion) {
		return errors.New("target agent version is invalid")
	}
	if !agentupdate.ValidRequestID(requestID) {
		return errors.New("agent update request ID is invalid")
	}
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	if _, err := s.Identities.PublicKey(ctx, agentID); err != nil {
		return err
	}
	if !s.Sessions.Supports(agentID, AgentUpdateCapability) {
		return ErrAgentOffline
	}
	info, _ := s.Sessions.AgentInfo(agentID)
	state := AgentUpdateState{
		RequestID:      requestID,
		TargetVersion:  targetVersion,
		RunningVersion: info.Version,
		Status:         "requested",
		UpdatedAt:      s.now(),
	}
	s.updateMu.Lock()
	previous, hadPrevious := s.updates[agentID]
	if hadPrevious &&
		(previous.Status == "requested" || previous.Status == "scheduled") {
		s.updateMu.Unlock()
		return agentupdate.ErrUpdatePending
	}
	s.updates[agentID] = state
	s.updateMu.Unlock()
	err := s.Sessions.Send(ctx, agentID, &controlv1.MasterFrame{
		Payload: &controlv1.MasterFrame_UpdateAgent{
			UpdateAgent: &controlv1.AgentUpdateCommand{
				RequestId:     requestID,
				TargetVersion: targetVersion,
			},
		},
	})
	if err != nil {
		s.updateMu.Lock()
		if current, exists := s.updates[agentID]; exists &&
			current.RequestID == requestID {
			if hadPrevious {
				s.updates[agentID] = previous
			} else {
				delete(s.updates, agentID)
			}
		}
		s.updateMu.Unlock()
		return err
	}
	return nil
}

func (s *Server) LatestAgentUpdate(agentID string) (AgentUpdateState, bool) {
	s.updateMu.RLock()
	defer s.updateMu.RUnlock()
	state, exists := s.updates[agentID]
	return state, exists
}

func (s *Server) handleAgentUpdateReport(
	agentID string,
	report *controlv1.AgentUpdateReport,
) error {
	if report == nil ||
		!agentupdate.ValidRequestID(report.GetRequestId()) ||
		!agentupdate.ValidVersion(report.GetTargetVersion()) ||
		report.GetObservedAtUnix() <= 0 ||
		len(report.GetDiagnostic()) > MaxDiagnosticBytes*4 {
		return status.Error(codes.InvalidArgument, "invalid agent update report")
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	current, exists := s.updates[agentID]
	if !exists ||
		current.RequestID != report.GetRequestId() ||
		current.TargetVersion != report.GetTargetVersion() {
		// The helper result intentionally survives an agent restart until the
		// master accepts it. A master restart loses the in-memory request map,
		// so reject only unmatched non-terminal reports. Silently accepting an
		// old terminal report lets the authenticated agent acknowledge and
		// remove it without allowing it to mutate a newer request.
		if report.GetStatus() ==
			controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_APPLIED ||
			report.GetStatus() ==
				controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_FAILED {
			return nil
		}
		return status.Error(codes.PermissionDenied, "agent update report does not match its request")
	}
	switch report.GetStatus() {
	case controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_SCHEDULED:
		current.Status = "scheduled"
	case controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_APPLIED:
		current.Status = "applied"
	case controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_FAILED:
		current.Status = "failed"
	case controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_REJECTED:
		current.Status = "rejected"
	default:
		return status.Error(codes.InvalidArgument, "unknown agent update status")
	}
	current.RunningVersion = report.GetRunningVersion()
	current.Diagnostic = sanitizeAgentDiagnostic(report.GetDiagnostic())
	current.UpdatedAt = time.Unix(report.GetObservedAtUnix(), 0).UTC()
	s.updates[agentID] = current
	return nil
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
	renderedDigest := record.RenderedDigest()
	if record.AgentID != agentID ||
		record.RevisionID != report.GetRevisionId() ||
		!bytes.Equal(renderedDigest[:], report.GetConfigSha256()) {
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
	)
	return nil
}

func (s *Server) handleDeploymentReport(
	ctx context.Context,
	agentID string,
	report *controlv1.ConfigDeploymentReport,
) error {
	if report == nil {
		return status.Error(codes.InvalidArgument, "missing deployment report")
	}
	if len(report.GetDiagnostic()) > MaxDiagnosticBytes*4 {
		return status.Error(codes.InvalidArgument, "deployment diagnostic exceeds the wire limit")
	}
	record, err := s.Deployments.Get(ctx, report.GetDeploymentId())
	if err != nil {
		return status.Error(codes.NotFound, "deployment not found")
	}
	renderedDigest := record.RenderedDigest()
	if record.AgentID != agentID ||
		record.RevisionID != report.GetRevisionId() {
		return status.Error(codes.PermissionDenied, "deployment report does not match its request")
	}
	digestMatches := bytes.Equal(renderedDigest[:], report.GetConfigSha256())
	materializedTopology := !digestMatches &&
		deployment.ClassifyRevision(record.RevisionID) == deployment.RevisionPlaneProxyNodeTopology &&
		len(report.GetConfigSha256()) == sha256.Size
	if !digestMatches && !materializedTopology {
		return status.Error(codes.PermissionDenied, "deployment report does not match its request")
	}

	var next deployment.Status
	var userMessage string
	switch report.GetStatus() {
	case controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED:
		next = deployment.StatusApplied
		userMessage = "Agent activated the configuration."
	case controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_VALIDATION_FAILED:
		next = deployment.StatusValidationFailed
		userMessage = "Agent rejected the candidate configuration. Review the validation diagnostic."
	case controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_ACTIVATION_FAILED:
		next = deployment.StatusActivationFailed
		userMessage = "sing-box could not activate the candidate configuration; the agent rolled back where possible."
	case controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_INTERNAL_ERROR:
		next = deployment.StatusInternalError
		userMessage = "Agent could not complete the configuration deployment."
	default:
		return status.Error(codes.InvalidArgument, "unknown deployment status")
	}

	diagnostic := sanitizeAgentDiagnostic(report.GetDiagnostic())
	if next == deployment.StatusApplied && materializedTopology {
		var effectiveDigest [sha256.Size]byte
		copy(effectiveDigest[:], report.GetConfigSha256())
		record, err = s.Deployments.SetRenderedDigest(ctx, record.ID, effectiveDigest)
		if err != nil {
			return status.Error(codes.FailedPrecondition, "effective Agent configuration could not be recorded")
		}
	}
	updated, err := s.Deployments.Transition(ctx, record.ID, next, diagnostic, s.now())
	if err != nil {
		return status.Error(codes.FailedPrecondition, "deployment is not awaiting a report")
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
	if next != deployment.StatusApplied {
		level = slog.LevelWarn
	}
	s.Logger.Log(
		ctx,
		level,
		"agent configuration deployment completed",
		"agent_id", agentID,
		"deployment_id", record.ID,
		"status", next,
	)
	if next == deployment.StatusApplied && s.poolRegistry != nil {
		// The agent now runs this rendered document: stamp its render state
		// so the reconnect staleness check does not flag it, then let every
		// dependent re-render against the inbound set this config provides.
		if err := s.poolRegistry.MarkRendered(
			agentID,
			s.poolRegistry.PoolVersion(),
			updated.RenderedDigest(),
		); err != nil {
			s.Logger.Error(
				"outbound pool render stamp failed",
				"agent_id", agentID,
				"error", err,
			)
		}
		s.propagatePoolChange(ctx, "deployment applied", agentID)
	}
	return nil
}

func (s *Server) handleRuntimeReport(
	ctx context.Context,
	agentID string,
	report *controlv1.ConfigRuntimeReport,
) error {
	if report == nil ||
		len(report.GetConfigSha256()) != sha256.Size ||
		report.GetObservedAtUnix() <= 0 {
		return status.Error(codes.InvalidArgument, "invalid sing-box runtime report")
	}
	if len(report.GetDiagnostic()) > MaxDiagnosticBytes*4 {
		return status.Error(codes.InvalidArgument, "runtime diagnostic exceeds the wire limit")
	}
	record, err := s.Deployments.LatestForAgent(ctx, agentID)
	if errors.Is(err, deployment.ErrNotFound) {
		return nil
	}
	if err != nil {
		return status.Error(codes.Internal, "deployment state could not be loaded")
	}
	renderedDigest := record.RenderedDigest()
	if !bytes.Equal(renderedDigest[:], report.GetConfigSha256()) {
		// A buffered event for the previously active configuration can arrive
		// after a newer candidate becomes the latest master record.
		return nil
	}

	var (
		next        deployment.Status
		message     string
		shouldStore bool
	)
	switch report.GetStatus() {
	case controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RUNNING:
		if record.Status == deployment.StatusRuntimeFailed {
			next = deployment.StatusApplied
			message = "sing-box recovered and is running the managed configuration."
			shouldStore = true
		}
	case controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_EXITED,
		controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RESTART_FAILED,
		controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_VALIDATION_FAILED,
		controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_ACTIVATION_FAILED,
		controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_STOP_FAILED:
		if record.Status == deployment.StatusApplied {
			next = deployment.StatusRuntimeFailed
			message = "The managed sing-box process is not running correctly."
			shouldStore = true
		}
	case controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_STOPPED:
		return nil
	default:
		return status.Error(codes.InvalidArgument, "unknown sing-box runtime status")
	}
	if !shouldStore {
		return nil
	}

	diagnostic := sanitizeAgentDiagnostic(report.GetDiagnostic())
	updated, err := s.Deployments.Transition(
		ctx,
		record.ID,
		next,
		diagnostic,
		s.now(),
	)
	if err != nil {
		// A deployment report can race this asynchronous runtime event. The
		// latest authoritative state will be reported again by the supervisor.
		return nil
	}
	if err := s.Notifier.Notify(ctx, deployment.Event{
		Deployment: updated,
		Message:    message,
	}); err != nil {
		s.Logger.Error(
			"runtime notification failed",
			"deployment_id", record.ID,
			"agent_id", agentID,
			"error", err,
		)
	}
	level := slog.LevelInfo
	if next == deployment.StatusRuntimeFailed {
		level = slog.LevelWarn
	}
	s.Logger.Log(
		ctx,
		level,
		"managed sing-box runtime changed",
		"agent_id", agentID,
		"deployment_id", record.ID,
		"status", next,
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
	agentID      string
	commands     chan *controlv1.MasterFrame
	done         chan struct{}
	capabilities map[string]struct{}
	info         AgentInfo
}

type AgentInfo struct {
	Version         string
	SingBoxVersion  string
	OperatingSystem string
	Architecture    string
	// ObservedAddress is the address the agent's control connection arrives
	// from (X-Forwarded-For through Caddy, else the transport peer).
	ObservedAddress string
	ReportedIPv4    []string
	ReportedIPv6    []string
}

func newSession(agentID string) *session {
	return &session{
		agentID:      agentID,
		commands:     make(chan *controlv1.MasterFrame, DefaultCommandQueue),
		done:         make(chan struct{}),
		capabilities: make(map[string]struct{}),
	}
}

func newSessionFromHello(agentID string, hello *controlv1.AgentHello) *session {
	session := newSession(agentID)
	session.info = AgentInfo{
		Version:         hello.GetAgentVersion(),
		SingBoxVersion:  hello.GetSingBoxVersion(),
		OperatingSystem: hello.GetOperatingSystem(),
		Architecture:    hello.GetArchitecture(),
	}
	session.info.ReportedIPv4, session.info.ReportedIPv6 =
		sanitizeReportedAddresses(hello.GetReportedAddresses())
	return session
}

func (r *SessionRegistry) AgentInfo(agentID string) (AgentInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, exists := r.sessions[agentID]
	if !exists {
		return AgentInfo{}, false
	}
	// Clone the address slices so a caller mutating the returned struct
	// cannot race the registry's stored state.
	info := session.info
	info.ReportedIPv4 = slices.Clone(info.ReportedIPv4)
	info.ReportedIPv6 = slices.Clone(info.ReportedIPv6)
	return info, true
}

func (r *SessionRegistry) SetSingBoxVersion(agentID, version string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if session, exists := r.sessions[agentID]; exists {
		session.info.SingBoxVersion = version
	}
}

// SetObservedAddress records the address the agent's control connection
// arrived from. It mirrors SetSingBoxVersion: the write happens under the
// same registry mutex that guards session lookup.
func (r *SessionRegistry) SetObservedAddress(agentID, addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if session, exists := r.sessions[agentID]; exists {
		session.info.ObservedAddress = addr
	}
}

// SetReportedAddresses replaces the stored interface addresses for a
// connected agent and reports whether they differ from what was stored. It
// mirrors SetSingBoxVersion: the comparison and the write happen under the
// same registry mutex that guards session lookup, so a heartbeat racing an
// unregister simply becomes a no-op. Both the stored and incoming slices are
// deduplicated and deterministically ordered by the agent (preferred
// addresses first), which makes a plain slice compare an exact compare.
// Copies are stored so later mutation of the caller's slices cannot alias
// registry state.
func (r *SessionRegistry) SetReportedAddresses(
	agentID string,
	v4, v6 []string,
) (changed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session, exists := r.sessions[agentID]
	if !exists {
		return false
	}
	if slices.Equal(session.info.ReportedIPv4, v4) &&
		slices.Equal(session.info.ReportedIPv6, v6) {
		return false
	}
	session.info.ReportedIPv4 = slices.Clone(v4)
	session.info.ReportedIPv6 = slices.Clone(v6)
	return true
}

const (
	// maxReportedAddressesPerFamily caps how many addresses per IP family
	// the master retains for an agent. maxReportedAddressEntries caps how
	// many raw strings of a single frame are even looked at, so a
	// misbehaving agent cannot turn heartbeat handling into unbounded work.
	maxReportedAddressesPerFamily = 8
	maxReportedAddressEntries     = 256
)

// sanitizeReportedAddresses parses the plain address strings an agent
// reports into canonical IPv4/IPv6 lists. The master never trusts wire data:
// unparseable entries are dropped, IPv4-in-IPv6 forms are unmapped into the
// v4 family, duplicates are removed, each family is capped, and only
// globally routable addresses are kept (globallyRoutable — no RFC 1918, ULA,
// CGNAT, or reserved space, same rule the agent applies at collection and
// the pool registry at write). The agent's ORDER IS PRESERVED, not
// re-sorted: the pool's first-entry selection relies on the agent's
// deterministic order, so change detection and persistence churn stay
// stable. (Public addresses discovered by on-command probes travel in probe
// reports, not here.)
func sanitizeReportedAddresses(reported []string) (v4, v6 []string) {
	seen4 := make(map[netip.Addr]struct{})
	seen6 := make(map[netip.Addr]struct{})
	for index, entry := range reported {
		if index >= maxReportedAddressEntries {
			break
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !globallyRoutable(addr) {
			continue
		}
		if addr.Is4() {
			if _, duplicate := seen4[addr]; duplicate {
				continue
			}
			if len(v4) >= maxReportedAddressesPerFamily {
				continue
			}
			seen4[addr] = struct{}{}
			v4 = append(v4, addr.String())
		} else {
			if _, duplicate := seen6[addr]; duplicate {
				continue
			}
			if len(v6) >= maxReportedAddressesPerFamily {
				continue
			}
			seen6[addr] = struct{}{}
			v6 = append(v6, addr.String())
		}
	}
	return v4, v6
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
		close(session.done)
	}
}

// Disconnect immediately makes agentID appear offline and signals its Connect
// handler to close the authenticated control stream. The commands channel is
// intentionally left open so concurrent senders cannot panic.
func (r *SessionRegistry) Disconnect(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, exists := r.sessions[agentID]
	if !exists {
		return false
	}
	delete(r.sessions, agentID)
	close(session.done)
	return true
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
	case <-session.done:
		return ErrAgentOffline
	default:
	}
	select {
	case session.commands <- frame:
		select {
		case <-session.done:
			return ErrAgentOffline
		default:
			return nil
		}
	case <-session.done:
		return ErrAgentOffline
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

func (r *SessionRegistry) Supports(agentID, capability string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, exists := r.sessions[agentID]
	if !exists {
		return false
	}
	_, supported := session.capabilities[capability]
	return supported
}

func (s *Server) CanDeployConfiguration(agentID string) bool {
	return s.Sessions.Supports(agentID, ConfigDeployCapability)
}

func (s *Server) CanDeployProxyNodeConfiguration(agentID string) bool {
	return s.Sessions.Supports(agentID, ProxyNodeDeployCapability)
}

func (s *Server) CanSyncManagedUserAuthority(agentID string) bool {
	return s.Sessions.Supports(agentID, ManagedUserAuthorityCapability)
}

func (s *Server) CanUpdateAgent(agentID string) bool {
	return s.Sessions.Supports(agentID, AgentUpdateCapability)
}

func (s *Server) CanUpdateSingBox(agentID string) bool {
	return s.Sessions.Supports(agentID, SingBoxUpdateCapability)
}

func validCapabilities(capabilities []string) bool {
	if len(capabilities) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if len(capability) == 0 || len(capability) > 64 {
			return false
		}
		for _, character := range capability {
			if character > unicode.MaxASCII ||
				!(unicode.IsLetter(character) ||
					unicode.IsDigit(character) ||
					character == '-' ||
					character == '_' ||
					character == '.') {
				return false
			}
		}
		if _, duplicate := seen[capability]; duplicate {
			return false
		}
		seen[capability] = struct{}{}
	}
	return true
}

func validAgentMetadata(hello *controlv1.AgentHello) bool {
	for value, limit := range map[string]int{
		hello.GetAgentVersion():    64,
		hello.GetOperatingSystem(): 16,
		hello.GetArchitecture():    16,
	} {
		if len(value) > limit {
			return false
		}
		for _, character := range value {
			if character < 0x20 || character > 0x7e {
				return false
			}
		}
	}
	return true
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
