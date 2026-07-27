package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"google.golang.org/grpc"
)

const (
	ProtocolVersion     = 1
	MaxValidationPeriod = 60 * time.Second
	managerStopPeriod   = 10 * time.Second
	reconnectMinBackoff = time.Second
	reconnectMaxBackoff = 30 * time.Second
)

type ConfigurationManager interface {
	Start(context.Context) (singbox.StartupResult, error)
	Apply(context.Context, []byte, []byte) (singbox.ApplyResult, error)
	Stop(context.Context) error
	Events() <-chan singbox.RuntimeEvent
}

type Runner struct {
	AgentID      string
	AgentVersion string
	PrivateKey   ed25519.PrivateKey
	Validator    singbox.Validator
	Manager      ConfigurationManager
	Now          func() time.Time
}

func (r *Runner) Enroll(
	ctx context.Context,
	client controlv1.AgentControlServiceClient,
	token []byte,
) error {
	if err := r.validateIdentity(); err != nil {
		return err
	}
	if len(token) != identity.EnrollmentTokenBytes {
		return errors.New("enrollment token has an invalid length")
	}
	publicKey, ok := r.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("could not derive the agent public key")
	}
	response, err := client.Enroll(ctx, &controlv1.EnrollRequest{
		AgentId:         r.AgentID,
		EnrollmentToken: append([]byte(nil), token...),
		PublicKey:       append([]byte(nil), publicKey...),
	})
	if err != nil {
		return fmt.Errorf("enroll agent: %w", err)
	}
	if response.GetAgentId() != r.AgentID {
		return errors.New("master returned an unexpected agent identity")
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
		if _, err := r.Manager.Start(ctx); err != nil {
			return fmt.Errorf("start sing-box manager: %w", err)
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
		_ = r.runControlSession(ctx, client)
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.now().Sub(connectedAt) >= time.Minute {
			reconnectBackoff = reconnectMinBackoff
		}
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
	hello := &controlv1.AgentHello{
		AgentId:         r.AgentID,
		ProtocolVersion: ProtocolVersion,
		AgentVersion:    r.AgentVersion,
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
	}
	if r.Manager != nil {
		hello.Capabilities = []string{control.ConfigDeployCapability}
	}
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
		identity.ChallengePayload(r.AgentID, challenge.GetNonce()),
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

	var runtimeEvents <-chan singbox.RuntimeEvent
	if r.Manager != nil {
		runtimeEvents = r.Manager.Events()
	}
	incoming := make(chan receivedMasterFrame, 1)
	go receiveMasterFrames(stream, incoming)
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
			default:
				return errors.New("master sent an unsupported command")
			}
			if err := stream.Send(response); err != nil {
				return fmt.Errorf("send configuration report: %w", err)
			}
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
	if strings.TrimSpace(r.AgentID) == "" {
		return errors.New("agent ID is required")
	}
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
