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
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"google.golang.org/grpc"
)

const (
	ProtocolVersion     = 1
	MaxValidationPeriod = 60 * time.Second
)

type Runner struct {
	AgentID      string
	AgentVersion string
	PrivateKey   ed25519.PrivateKey
	Validator    singbox.Validator
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
) error {
	if err := r.validateIdentity(); err != nil {
		return err
	}
	stream, err := client.Connect(ctx, grpc.WaitForReady(true))
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	defer stream.CloseSend()

	var agentSequence uint64 = 1
	if err := stream.Send(&controlv1.AgentFrame{
		Sequence: agentSequence,
		Payload: &controlv1.AgentFrame_Hello{
			Hello: &controlv1.AgentHello{
				AgentId:         r.AgentID,
				ProtocolVersion: ProtocolVersion,
				AgentVersion:    r.AgentVersion,
				OperatingSystem: runtime.GOOS,
				Architecture:    runtime.GOARCH,
			},
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

	for {
		frame, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return errors.New("master closed the control stream")
		}
		if err != nil {
			return fmt.Errorf("receive master command: %w", err)
		}
		if frame.GetSequence() <= lastMasterSequence {
			return errors.New("master sequence is not monotonic")
		}
		lastMasterSequence = frame.GetSequence()

		command := frame.GetValidateConfig()
		if command == nil {
			return errors.New("master sent an unsupported command")
		}
		report := r.validateConfiguration(ctx, command)
		agentSequence++
		if err := stream.Send(&controlv1.AgentFrame{
			Sequence: agentSequence,
			Payload: &controlv1.AgentFrame_ConfigValidationReport{
				ConfigValidationReport: report,
			},
		}); err != nil {
			return fmt.Errorf("send configuration validation report: %w", err)
		}
	}
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
