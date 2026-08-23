package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"runtime"
	"strings"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"github.com/masterauguste/theatropolis/internal/singboxupdate"
	"google.golang.org/grpc"
)

const (
	ProtocolVersion        = 2
	MaxValidationPeriod    = 60 * time.Second
	managerStopPeriod      = 10 * time.Second
	reconnectMinBackoff    = time.Second
	reconnectMaxBackoff    = 30 * time.Second
	defaultHeartbeatPeriod = 20 * time.Second
)

type ConfigurationManager interface {
	ResetForEnrollment() error
	Start(context.Context) (singbox.StartupResult, error)
	Apply(context.Context, []byte, []byte) (singbox.ApplyResult, error)
	Stop(context.Context) error
	Events() <-chan singbox.RuntimeEvent
}

type Runner struct {
	AgentVersion    string
	SingBoxVersion  string
	PrivateKey      ed25519.PrivateKey
	Validator       singbox.Validator
	Manager         ConfigurationManager
	Updater         *agentupdate.Scheduler
	SingBoxUpdater  *singboxupdate.Scheduler
	HeartbeatPeriod time.Duration
	Now             func() time.Time
	// Prober drives periodic public-address probing for families without a
	// globally routable interface address. Nil means a fresh default
	// ProbeScheduler per control session (production); tests substitute a
	// scoped scheduler, e.g. one with a negative Interval to disable
	// periodic probing.
	Prober *ProbeScheduler
}

func (r *Runner) Enroll(
	ctx context.Context,
	client controlv1.AgentControlServiceClient,
	token []byte,
) error {
	if len(r.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("agent private key is invalid")
	}
	if len(token) != identity.EnrollmentTokenBytes {
		return errors.New("enrollment token has an invalid length")
	}
	publicKey, ok := r.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("could not derive the agent public key")
	}
	response, err := client.Enroll(ctx, &controlv1.EnrollRequest{
		EnrollmentToken: append([]byte(nil), token...),
		PublicKey:       append([]byte(nil), publicKey...),
	})
	if err != nil {
		return fmt.Errorf("enroll agent: %w", err)
	}
	if response == nil || response.GetEnrolledAtUnix() == 0 {
		return errors.New("master returned an invalid enrollment result")
	}
	if r.Manager != nil {
		if err := r.Manager.ResetForEnrollment(); err != nil {
			return fmt.Errorf("disable previous sing-box configuration: %w", err)
		}
	}
	return nil
}

func (r *Runner) Run(
	ctx context.Context,
	client controlv1.AgentControlServiceClient,
) (runErr error) {
	if err := r.validateIdentity(); err != nil {
		return err
	}
	if r.Manager != nil {
		startup, err := r.Manager.Start(ctx)
		if err != nil {
			return fmt.Errorf("start sing-box manager: %w", err)
		}
		if startup.LegacyQuarantine != "" {
			slog.Warn("legacy sing-box configuration quarantined during Proxy Node cutover", "path", startup.LegacyQuarantine)
		}
		defer func() {
			stopCtx, cancel := context.WithTimeout(
				context.Background(),
				managerStopPeriod,
			)
			defer cancel()
			if err := r.Manager.Stop(stopCtx); err != nil && runErr == nil {
				runErr = fmt.Errorf("stop sing-box manager: %w", err)
			}
		}()
	}
	reconnectBackoff := reconnectMinBackoff
	for {
		connectedAt := r.now()
		sessionErr := r.runControlSession(ctx, client)
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.now().Sub(connectedAt) >= time.Minute {
			reconnectBackoff = reconnectMinBackoff
		}
		slog.Warn(
			"agent control session ended; reconnecting",
			"error", sessionErr,
			"retry_in", reconnectBackoff,
		)
		timer := time.NewTimer(reconnectBackoff)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		}
		reconnectBackoff = min(reconnectBackoff*2, reconnectMaxBackoff)
	}
}

func (r *Runner) runControlSession(
	ctx context.Context,
	client controlv1.AgentControlServiceClient,
) error {
	sessionContext, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	stream, err := client.Connect(sessionContext, grpc.WaitForReady(true))
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	defer stream.CloseSend()

	var agentSequence uint64 = 1
	publicKey, ok := r.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("could not derive the agent public key")
	}
	hello := &controlv1.AgentHello{
		ProtocolVersion: ProtocolVersion,
		AgentVersion:    r.AgentVersion,
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		SingBoxVersion:  r.SingBoxVersion,
		PublicKey:       append([]byte(nil), publicKey...),
	}
	if r.Manager != nil {
		hello.Capabilities = append(
			hello.Capabilities,
			control.ProxyNodeDeployCapability,
		)
	}
	if r.Updater != nil {
		hello.Capabilities = append(
			hello.Capabilities,
			control.AgentUpdateCapability,
		)
	}
	if r.SingBoxUpdater != nil {
		hello.Capabilities = append(
			hello.Capabilities,
			control.SingBoxUpdateCapability,
		)
	}
	hello.Capabilities = append(
		hello.Capabilities,
		control.HeartbeatCapability,
		control.CapabilityAddressReport,
		control.CapabilityAddressProbe,
	)
	hello.ReportedAddresses = collectReportedAddresses()
	if err := stream.Send(&controlv1.AgentFrame{
		Sequence: agentSequence,
		Payload: &controlv1.AgentFrame_Hello{
			Hello: hello,
		},
	}); err != nil {
		return fmt.Errorf("send agent hello: %w", err)
	}

	challengeFrame, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("receive authentication challenge: %w", err)
	}
	challenge := challengeFrame.GetChallenge()
	if challenge == nil ||
		challengeFrame.GetSequence() == 0 ||
		len(challenge.GetNonce()) != identity.ChallengeNonceBytes ||
		r.now().After(time.Unix(challenge.GetExpiresAtUnix(), 0)) {
		return errors.New("master returned an invalid authentication challenge")
	}

	agentSequence++
	signature := ed25519.Sign(
		r.PrivateKey,
		identity.ChallengePayload(publicKey, challenge.GetNonce()),
	)
	if err := stream.Send(&controlv1.AgentFrame{
		Sequence: agentSequence,
		Payload: &controlv1.AgentFrame_Proof{
			Proof: &controlv1.AgentProof{Signature: signature},
		},
	}); err != nil {
		return fmt.Errorf("send authentication proof: %w", err)
	}

	authFrame, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("receive authentication result: %w", err)
	}
	authResult := authFrame.GetAuthenticationResult()
	if authResult == nil ||
		authFrame.GetSequence() <= challengeFrame.GetSequence() ||
		!authResult.GetAuthenticated() {
		return errors.New("master rejected the agent identity")
	}
	lastMasterSequence := authFrame.GetSequence()
	if err := r.sendPendingUpdateResult(stream, &agentSequence); err != nil {
		return err
	}
	if err := r.sendPendingSingBoxUpdateResult(stream, &agentSequence); err != nil {
		return err
	}

	var runtimeEvents <-chan singbox.RuntimeEvent
	if r.Manager != nil {
		runtimeEvents = r.Manager.Events()
	}
	incoming := make(chan receivedMasterFrame, 1)
	go receiveMasterFrames(stream, incoming)
	var updateTicker *time.Ticker
	var updateTicks <-chan time.Time
	if r.Updater != nil || r.SingBoxUpdater != nil {
		updateTicker = time.NewTicker(2 * time.Second)
		defer updateTicker.Stop()
		updateTicks = updateTicker.C
	}
	heartbeatTicker := time.NewTicker(r.heartbeatPeriod())
	defer heartbeatTicker.Stop()
	// Address probes run off the control loop (worst case ~2*probeTimeout);
	// finished reports are serialized back through this channel so the
	// select loop below remains the only sender and the only writer of
	// agentSequence — the same pattern updateTicks uses for update results.
	probeReports := make(chan *controlv1.AddressProbeReport, 4)
	// The periodic prober is per-session: a reconnect re-arms its state, so
	// the first probe of a fresh session re-reports the public address and
	// the master re-learns it even though reports are change-only within a
	// session.
	prober := r.Prober
	if prober == nil {
		prober = &ProbeScheduler{}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case received := <-incoming:
			if errors.Is(received.err, io.EOF) {
				return errors.New("master closed the control stream")
			}
			if received.err != nil {
				return fmt.Errorf("receive master command: %w", received.err)
			}
			frame := received.frame
			if frame.GetSequence() <= lastMasterSequence {
				return errors.New("master sequence is not monotonic")
			}
			lastMasterSequence = frame.GetSequence()

			agentSequence++
			response := &controlv1.AgentFrame{Sequence: agentSequence}
			switch command := frame.GetPayload().(type) {
			case *controlv1.MasterFrame_ValidateConfig:
				response.Payload = &controlv1.AgentFrame_ConfigValidationReport{
					ConfigValidationReport: r.validateConfiguration(
						ctx,
						command.ValidateConfig,
					),
				}
			case *controlv1.MasterFrame_DeployConfig:
				if r.Manager == nil {
					return errors.New(
						"master sent a configuration deployment to an incompatible agent",
					)
				}
				response.Payload = &controlv1.AgentFrame_ConfigDeploymentReport{
					ConfigDeploymentReport: r.deployConfiguration(
						ctx,
						command.DeployConfig,
					),
				}
			case *controlv1.MasterFrame_UpdateAgent:
				response.Payload = &controlv1.AgentFrame_AgentUpdateReport{
					AgentUpdateReport: r.scheduleAgentUpdate(
						command.UpdateAgent,
					),
				}
			case *controlv1.MasterFrame_UpdateSingBox:
				response.Payload = &controlv1.AgentFrame_SingBoxUpdateReport{
					SingBoxUpdateReport: r.scheduleSingBoxUpdate(
						command.UpdateSingBox,
					),
				}
			case *controlv1.MasterFrame_ProbeAddresses:
				family := command.ProbeAddresses.GetFamily()
				if is6, supported := probeFamilyIs6(family); supported {
					// Reply asynchronously via probeReports; this slot's
					// sequence number stays unused, which is fine because
					// the master only requires monotonic increase.
					go runAddressProbe(sessionContext, prober, family, is6, probeReports)
				} else {
					response.Payload = &controlv1.AgentFrame_AddressProbeReport{
						AddressProbeReport: &controlv1.AddressProbeReport{
							Family: family,
							Error:  "unsupported family",
						},
					}
				}
			default:
				return errors.New("master sent an unsupported command")
			}
			if response.Payload == nil {
				continue
			}
			if err := stream.Send(response); err != nil {
				return fmt.Errorf("send configuration report: %w", err)
			}
		case report := <-probeReports:
			agentSequence++
			if err := stream.Send(&controlv1.AgentFrame{
				Sequence: agentSequence,
				Payload: &controlv1.AgentFrame_AddressProbeReport{
					AddressProbeReport: report,
				},
			}); err != nil {
				return fmt.Errorf("send address probe report: %w", err)
			}
		case <-updateTicks:
			if err := r.sendPendingUpdateResult(
				stream,
				&agentSequence,
			); err != nil {
				return err
			}
			if err := r.sendPendingSingBoxUpdateResult(
				stream,
				&agentSequence,
			); err != nil {
				return err
			}
		case <-heartbeatTicker.C:
			agentSequence++
			v4, v6 := reportedAddresses.Addresses()
			if err := stream.Send(&controlv1.AgentFrame{
				Sequence: agentSequence,
				Payload: &controlv1.AgentFrame_Heartbeat{
					Heartbeat: &controlv1.AgentHeartbeat{
						ObservedAtUnix:    r.now().Unix(),
						SingBoxVersion:    r.SingBoxVersion,
						ReportedAddresses: append(v4, v6...),
					},
				},
			}); err != nil {
				return fmt.Errorf("send agent heartbeat: %w", err)
			}
			// Komari-style periodic probing: a family with no globally
			// routable interface address (1:1 NAT) probes its public
			// address and reports changes; direct-attach families never
			// generate probe traffic.
			prober.Maintain(
				false,
				len(v4) > 0,
				periodicProbeReporter(sessionContext, "ipv4", probeReports),
			)
			prober.Maintain(
				true,
				len(v6) > 0,
				periodicProbeReporter(sessionContext, "ipv6", probeReports),
			)
		case event := <-runtimeEvents:
			agentSequence++
			if err := stream.Send(&controlv1.AgentFrame{
				Sequence: agentSequence,
				Payload: &controlv1.AgentFrame_ConfigRuntimeReport{
					ConfigRuntimeReport: runtimeReport(event),
				},
			}); err != nil {
				return fmt.Errorf("send sing-box runtime report: %w", err)
			}
		}
	}
}

// reportedAddresses is the process-wide reporter: interface addresses are
// collected per frame, and public-address probing happens on master command
// (ProbeAddresses) and periodically via ProbeScheduler for families without
// a routable interface address.
var reportedAddresses = &AddressReporter{}

// maxProbeErrorBytes caps the failure reason carried in an
// AddressProbeReport; the endpoints are hardcoded, so the underlying error
// never contains credentials, only potentially long transport messages.
const maxProbeErrorBytes = 256

// collectReportedAddresses snapshots the host's interface addresses as plain
// strings (both families mixed; the master splits them by parsing). No
// probing happens here — collection is a cheap syscall done on hello and
// every heartbeat. Failure is non-fatal: the frame goes out with no
// addresses and the master keeps whatever it last saw.
func collectReportedAddresses() []string {
	v4, v6 := reportedAddresses.Addresses()
	return append(v4, v6...)
}

// probeFamilyIs6 maps a ProbeAddresses family string to the probe's boolean
// family selector; only exactly "ipv4" and "ipv6" are supported.
func probeFamilyIs6(family string) (is6, supported bool) {
	switch family {
	case "ipv4":
		return false, true
	case "ipv6":
		return true, true
	}
	return false, false
}

// runAddressProbe executes a master-commanded probe off the control loop and
// hands the report back through out. A successful result is also folded into
// the periodic scheduler so it does not re-report the same address. The send
// is bounded by ctx so a dead session cannot leak the goroutine.
func runAddressProbe(
	ctx context.Context,
	prober *ProbeScheduler,
	family string,
	is6 bool,
	out chan<- *controlv1.AddressProbeReport,
) {
	report := &controlv1.AddressProbeReport{Family: family}
	addr, err := reportedAddresses.Probe(ctx, is6)
	if err != nil {
		report.Error = sanitizeProbeError(err)
	} else {
		report.Address = addr.String()
		prober.noteProbed(is6, addr)
	}
	select {
	case out <- report:
	case <-ctx.Done():
	}
}

// periodicProbeReporter returns the report callback ProbeScheduler.Maintain
// invokes with a changed probed address: it queues an AddressProbeReport for
// the control loop's probeReports case, exactly like an on-demand probe
// answer, bounded by the session context so a dead session drops it.
func periodicProbeReporter(
	ctx context.Context,
	family string,
	out chan<- *controlv1.AddressProbeReport,
) func(netip.Addr) {
	return func(addr netip.Addr) {
		report := &controlv1.AddressProbeReport{
			Family:  family,
			Address: addr.String(),
		}
		select {
		case out <- report:
		case <-ctx.Done():
		}
	}
}

func sanitizeProbeError(err error) string {
	text := err.Error()
	if len(text) > maxProbeErrorBytes {
		text = text[:maxProbeErrorBytes]
	}
	return text
}

func (r *Runner) scheduleSingBoxUpdate(
	command *controlv1.SingBoxUpdateCommand,
) *controlv1.SingBoxUpdateReport {
	report := &controlv1.SingBoxUpdateReport{
		Status:         controlv1.SingBoxUpdateStatus_SING_BOX_UPDATE_STATUS_REJECTED,
		RunningVersion: r.SingBoxVersion,
		ObservedAtUnix: r.now().Unix(),
	}
	if command != nil {
		report.RequestId = command.GetRequestId()
		report.TargetVersion = command.GetTargetVersion()
	}
	if r.SingBoxUpdater == nil || command == nil {
		report.Diagnostic = "sing-box update control is unavailable"
		return report
	}
	if err := r.SingBoxUpdater.Schedule(
		command.GetRequestId(),
		command.GetTargetVersion(),
	); err != nil {
		if errors.Is(err, singboxupdate.ErrUpdatePending) {
			report.Diagnostic = "another sing-box update is already pending"
		} else {
			report.Diagnostic = "agent rejected the sing-box update request"
		}
		return report
	}
	report.Status =
		controlv1.SingBoxUpdateStatus_SING_BOX_UPDATE_STATUS_SCHEDULED
	return report
}

func (r *Runner) sendPendingSingBoxUpdateResult(
	stream controlv1.AgentControlService_ConnectClient,
	agentSequence *uint64,
) error {
	if r.SingBoxUpdater == nil {
		return nil
	}
	result, exists, err := r.SingBoxUpdater.LoadResult()
	if err != nil {
		return fmt.Errorf("load sing-box update result: %w", err)
	}
	if !exists {
		return nil
	}
	status := controlv1.SingBoxUpdateStatus_SING_BOX_UPDATE_STATUS_FAILED
	if result.Status == "applied" {
		status = controlv1.SingBoxUpdateStatus_SING_BOX_UPDATE_STATUS_APPLIED
	}
	(*agentSequence)++
	if err := stream.Send(&controlv1.AgentFrame{
		Sequence: *agentSequence,
		Payload: &controlv1.AgentFrame_SingBoxUpdateReport{
			SingBoxUpdateReport: &controlv1.SingBoxUpdateReport{
				RequestId:      result.RequestID,
				TargetVersion:  result.TargetVersion,
				RunningVersion: result.RunningVersion,
				Status:         status,
				Diagnostic:     result.Diagnostic,
				ObservedAtUnix: result.ObservedAt.Unix(),
			},
		},
	}); err != nil {
		return fmt.Errorf("send sing-box update result: %w", err)
	}
	if err := r.SingBoxUpdater.AcknowledgeResult(result.RequestID); err != nil {
		return fmt.Errorf("acknowledge sing-box update result: %w", err)
	}
	return nil
}

func (r *Runner) scheduleAgentUpdate(
	command *controlv1.AgentUpdateCommand,
) *controlv1.AgentUpdateReport {
	report := &controlv1.AgentUpdateReport{
		RequestId:      command.GetRequestId(),
		TargetVersion:  command.GetTargetVersion(),
		RunningVersion: r.AgentVersion,
		Status:         controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_REJECTED,
		ObservedAtUnix: r.now().Unix(),
	}
	if r.Updater == nil || command == nil {
		report.Diagnostic = "agent update control is unavailable"
		return report
	}
	if err := r.Updater.Schedule(
		command.GetRequestId(),
		command.GetTargetVersion(),
	); err != nil {
		if errors.Is(err, agentupdate.ErrUpdatePending) {
			report.Diagnostic = "another agent update is already pending"
		} else {
			report.Diagnostic = "agent rejected the update request"
		}
		return report
	}
	report.Status = controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_SCHEDULED
	return report
}

func (r *Runner) sendPendingUpdateResult(
	stream controlv1.AgentControlService_ConnectClient,
	agentSequence *uint64,
) error {
	if r.Updater == nil {
		return nil
	}
	result, exists, err := r.Updater.LoadResult()
	if err != nil {
		return fmt.Errorf("load agent update result: %w", err)
	}
	if !exists {
		return nil
	}
	status := controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_FAILED
	if result.Status == "applied" {
		status = controlv1.AgentUpdateStatus_AGENT_UPDATE_STATUS_APPLIED
	}
	(*agentSequence)++
	if err := stream.Send(&controlv1.AgentFrame{
		Sequence: *agentSequence,
		Payload: &controlv1.AgentFrame_AgentUpdateReport{
			AgentUpdateReport: &controlv1.AgentUpdateReport{
				RequestId:      result.RequestID,
				TargetVersion:  result.TargetVersion,
				RunningVersion: r.AgentVersion,
				Status:         status,
				Diagnostic:     result.Diagnostic,
				ObservedAtUnix: result.ObservedAt.Unix(),
			},
		},
	}); err != nil {
		return fmt.Errorf("send agent update result: %w", err)
	}
	if err := r.Updater.AcknowledgeResult(result.RequestID); err != nil {
		return fmt.Errorf("acknowledge agent update result: %w", err)
	}
	return nil
}

type receivedMasterFrame struct {
	frame *controlv1.MasterFrame
	err   error
}

func receiveMasterFrames(
	stream controlv1.AgentControlService_ConnectClient,
	output chan<- receivedMasterFrame,
) {
	for {
		frame, err := stream.Recv()
		select {
		case output <- receivedMasterFrame{frame: frame, err: err}:
		case <-stream.Context().Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func runtimeReport(event singbox.RuntimeEvent) *controlv1.ConfigRuntimeReport {
	report := &controlv1.ConfigRuntimeReport{
		ConfigSha256:   event.ConfigSHA256[:],
		Diagnostic:     event.Diagnostic,
		ObservedAtUnix: event.ObservedAt.Unix(),
	}
	switch event.Status {
	case singbox.RuntimeStatusRunning:
		report.Status = controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RUNNING
	case singbox.RuntimeStatusExited:
		report.Status = controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_EXITED
	case singbox.RuntimeStatusRestartFailed:
		report.Status = controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RESTART_FAILED
	case singbox.RuntimeStatusValidationFailed:
		report.Status = controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_VALIDATION_FAILED
	case singbox.RuntimeStatusActivationFailed:
		report.Status = controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_ACTIVATION_FAILED
	case singbox.RuntimeStatusStopFailed:
		report.Status = controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_STOP_FAILED
	case singbox.RuntimeStatusStopped:
		report.Status = controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_STOPPED
	}
	return report
}

func (r *Runner) deployConfiguration(
	ctx context.Context,
	command *controlv1.DeployConfigCommand,
) *controlv1.ConfigDeploymentReport {
	started := r.now()
	report := &controlv1.ConfigDeploymentReport{
		DeploymentId:    command.GetDeploymentId(),
		RevisionId:      command.GetRevisionId(),
		ConfigSha256:    append([]byte(nil), command.GetConfigSha256()...),
		Status:          controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_INTERNAL_ERROR,
		CompletedAtUnix: started.Unix(),
	}
	if command == nil ||
		strings.TrimSpace(command.GetDeploymentId()) == "" ||
		strings.TrimSpace(command.GetRevisionId()) == "" ||
		len(command.GetConfigSha256()) != sha256.Size {
		report.Diagnostic = "master sent an invalid configuration deployment command"
		return report
	}

	timeout := time.Duration(command.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if timeout > MaxValidationPeriod {
		timeout = MaxValidationPeriod
	}
	applyContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := r.Manager.Apply(
		applyContext,
		command.GetConfigJson(),
		command.GetConfigSha256(),
	)
	completed := r.now()
	report.CompletedAtUnix = completed.Unix()
	report.DurationMilliseconds = uint64(max(0, completed.Sub(started).Milliseconds()))
	if err != nil {
		report.Diagnostic = "agent could not complete the configuration deployment"
		return report
	}
	report.Diagnostic = result.Diagnostic
	switch result.Status {
	case singbox.ApplyStatusApplied:
		report.Status = controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED
	case singbox.ApplyStatusValidationFailed:
		report.Status = controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_VALIDATION_FAILED
	case singbox.ApplyStatusActivationFailed:
		report.Status = controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_ACTIVATION_FAILED
	default:
		report.Status = controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_INTERNAL_ERROR
	}
	return report
}

func (r *Runner) validateConfiguration(
	ctx context.Context,
	command *controlv1.ValidateConfigCommand,
) *controlv1.ConfigValidationReport {
	report := &controlv1.ConfigValidationReport{
		DeploymentId:  command.GetDeploymentId(),
		RevisionId:    command.GetRevisionId(),
		ConfigSha256:  append([]byte(nil), command.GetConfigSha256()...),
		Status:        controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_INTERNAL_ERROR,
		CheckedAtUnix: r.now().Unix(),
	}
	if strings.TrimSpace(command.GetDeploymentId()) == "" ||
		strings.TrimSpace(command.GetRevisionId()) == "" ||
		len(command.GetConfigSha256()) != sha256.Size {
		report.Diagnostic = "master sent an invalid configuration validation command"
		return report
	}

	validator := r.Validator
	timeout := time.Duration(command.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if timeout > MaxValidationPeriod {
		timeout = MaxValidationPeriod
	}
	validator.Timeout = timeout
	result := validator.Check(ctx, command.GetConfigJson(), command.GetConfigSha256())
	report.Status = validationStatus(result.Status)
	report.Diagnostic = result.Diagnostic
	report.CheckedAtUnix = result.CheckedAt.Unix()
	report.DurationMilliseconds = uint64(max(0, result.Duration.Milliseconds()))
	return report
}

func validationStatus(status singbox.ValidationStatus) controlv1.ConfigValidationStatus {
	switch status {
	case singbox.ValidationValid:
		return controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_VALID
	case singbox.ValidationInvalid:
		return controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_INVALID
	default:
		return controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_INTERNAL_ERROR
	}
}

func (r *Runner) validateIdentity() error {
	if len(r.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("agent Ed25519 private key is required")
	}
	return nil
}

func (r *Runner) now() time.Time {
	if r.Now == nil {
		return time.Now().UTC()
	}
	return r.Now().UTC()
}

func (r *Runner) heartbeatPeriod() time.Duration {
	if r.HeartbeatPeriod <= 0 {
		return defaultHeartbeatPeriod
	}
	return r.HeartbeatPeriod
}
