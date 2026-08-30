package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/deployment"
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
	defaultTrafficPeriod   = 15 * time.Second
)

type MasterMigrationManager interface {
	StageMasterMigration(migrationID, masterAddress string) error
}

type ConfigurationManager interface {
	ResetForEnrollment() error
	Start(context.Context) (singbox.StartupResult, error)
	Apply(context.Context, []byte, []byte) (singbox.ApplyResult, error)
	Stop(context.Context) error
	Events() <-chan singbox.RuntimeEvent
}

type managedUserTrafficCollector interface {
	ManagedUserTraffic(context.Context) (singbox.ManagedUserTrafficSnapshot, error)
}

type managedUserAuthorityManager interface {
	ApplyManagedUserAuthority(context.Context, uint64, []singbox.ManagedUserAuthorityVariant) (singbox.ApplyResult, error)
}

type classifiedConfigurationManager interface {
	ApplyWithMode(context.Context, []byte, []byte, singbox.ApplyMode) (singbox.ApplyResult, error)
}

type Runner struct {
	AgentVersion    string
	SingBoxVersion  string
	PrivateKey      ed25519.PrivateKey
	Validator       singbox.Validator
	Manager         ConfigurationManager
	Updater         *agentupdate.Scheduler
	SingBoxUpdater  *singboxupdate.Scheduler
	MasterMigrator  MasterMigrationManager
	HeartbeatPeriod time.Duration
	// MasterMigrationExitDelay is a test seam. Production waits long enough
	// for the old Master to process the acceptance report and acknowledge it
	// by closing the authenticated stream.
	MasterMigrationExitDelay time.Duration
	Now                      func() time.Time
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
		if errors.Is(sessionErr, ErrMasterMigrationRequested) {
			return sessionErr
		}
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
	trafficCollector, reportsTraffic := r.Manager.(managedUserTrafficCollector)
	if reportsTraffic {
		hello.Capabilities = append(
			hello.Capabilities,
			// Retain the cumulative capability during the rolling transition so
			// an older master can consume uniquely-epoched reset batches safely.
			control.ManagedUserTrafficCapability,
			control.ManagedUserTrafficDeltaCapability,
			control.ManagedUserTrafficRequestCapability,
		)
	}
	latencyProvider, reportsLinkLatency := r.Manager.(linkLatencyTargetProvider)
	if reportsLinkLatency {
		hello.Capabilities = append(hello.Capabilities, control.LinkLatencyCapability)
		hello.Capabilities = append(hello.Capabilities, control.LinkLatencyProbeCapability)
	}
	_, managesUserAuthority := r.Manager.(managedUserAuthorityManager)
	if managesUserAuthority {
		hello.Capabilities = append(hello.Capabilities, control.ManagedUserAuthorityCapability)
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
	if r.MasterMigrator != nil {
		hello.Capabilities = append(hello.Capabilities, control.MasterMigrationCapability)
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
	monitorLinkLatency := reportsLinkLatency && slices.Contains(authResult.GetCapabilities(), control.LinkLatencyCapability)
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
	linkLatencyProbeReports := make(chan linkLatencyProbeResult, control.DefaultCommandQueue)
	// The periodic prober is per-session: a reconnect re-arms its state, so
	// the first probe of a fresh session re-reports the public address and
	// the master re-learns it even though reports are change-only within a
	// session.
	prober := r.Prober
	if prober == nil {
		prober = &ProbeScheduler{}
	}
	var trafficTicker *time.Ticker
	var trafficTicks <-chan time.Time
	trafficReports := make(chan trafficCollectionResult, 1)
	trafficCollecting := false
	trafficRequestIDs := make([]string, 0, 1)
	var migrationExit <-chan time.Time
	migrationStaged := false
	var latencyTicker *time.Ticker
	var latencyTicks <-chan time.Time
	latencyReports := make(chan linkLatencyCollectionResult, 1)
	latencyCollecting := false
	if monitorLinkLatency {
		latencyTicker = time.NewTicker(defaultLinkLatencyPeriod)
		defer latencyTicker.Stop()
		latencyTicks = latencyTicker.C
		latencyCollecting = true
		go func() { latencyReports <- collectLinkLatency(sessionContext, latencyProvider, r.now()) }()
	}
	if reportsTraffic {
		trafficTicker = time.NewTicker(defaultTrafficPeriod)
		defer trafficTicker.Stop()
		trafficTicks = trafficTicker.C
		trafficCollecting = true
		go collectManagedUserTraffic(sessionContext, trafficCollector, trafficReports)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case received := <-incoming:
			if errors.Is(received.err, io.EOF) {
				if migrationStaged {
					return ErrMasterMigrationRequested
				}
				return errors.New("master closed the control stream")
			}
			if received.err != nil {
				if migrationStaged {
					return ErrMasterMigrationRequested
				}
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
			case *controlv1.MasterFrame_LinkLatencyProbe:
				if !reportsLinkLatency {
					return errors.New("master requested Link latency from an incompatible agent")
				}
				go runLinkLatencyProbe(sessionContext, command.LinkLatencyProbe, linkLatencyProbeReports)
			case *controlv1.MasterFrame_ManagedUserAuthority:
				manager, ok := r.Manager.(managedUserAuthorityManager)
				if !ok {
					return errors.New("master sent managed-user authority to an incompatible agent")
				}
				response.Payload = &controlv1.AgentFrame_ManagedUserAuthorityReport{
					ManagedUserAuthorityReport: r.applyManagedUserAuthority(
						ctx, manager, command.ManagedUserAuthority,
					),
				}
			case *controlv1.MasterFrame_ManagedUserTrafficAck:
				// Older masters acknowledge cumulative reports. Reset-delta Agents
				// have no local accounting state to prune, so this is intentionally
				// a compatibility no-op.
			case *controlv1.MasterFrame_ManagedUserTrafficRequest:
				if !reportsTraffic {
					return errors.New("master requested managed-user traffic from an incompatible agent")
				}
				requestID := strings.TrimSpace(command.ManagedUserTrafficRequest.GetRequestId())
				if requestID == "" || len(requestID) > 128 || strings.ContainsRune(requestID, '\x00') {
					return errors.New("master sent an invalid managed-user traffic request")
				}
				if !slices.Contains(trafficRequestIDs, requestID) {
					if len(trafficRequestIDs) >= control.DefaultCommandQueue {
						// A slow fleet-wide sample can outlive a master's request
						// timeout. Retain the newest bounded set instead of letting
						// stale correlation IDs tear down the control stream.
						trafficRequestIDs = trafficRequestIDs[1:]
					}
					trafficRequestIDs = append(trafficRequestIDs, requestID)
				}
				if !trafficCollecting {
					trafficCollecting = true
					go collectManagedUserTraffic(sessionContext, trafficCollector, trafficReports)
				}
			case *controlv1.MasterFrame_MigrateMaster:
				migrationCommand := command.MigrateMaster
				migrationID := ""
				masterAddress := ""
				if migrationCommand != nil {
					migrationID = migrationCommand.GetMigrationId()
					masterAddress = migrationCommand.GetMasterAddress()
				}
				err := errors.New("Master migration is unavailable")
				if r.MasterMigrator != nil && migrationCommand != nil {
					err = r.MasterMigrator.StageMasterMigration(migrationID, masterAddress)
				}
				report := &controlv1.MasterMigrationReport{MigrationId: migrationID, Accepted: err == nil}
				if err != nil {
					report.ErrorCode = "invalid_target"
				} else {
					migrationStaged = true
					// A current Master closes this authenticated stream after it
					// receives the acceptance report. The timeout is only a
					// compatibility escape hatch; it prevents a persisted cutover
					// from remaining dormant forever if the old Master disappears
					// immediately after issuing the command.
					migrationExit = time.After(r.masterMigrationExitDelay())
				}
				response.Payload = &controlv1.AgentFrame_MasterMigrationReport{MasterMigrationReport: report}
			default:
				return errors.New("master sent an unsupported command")
			}
			if response.Payload == nil {
				continue
			}
			if err := stream.Send(response); err != nil {
				return fmt.Errorf("send configuration report: %w", err)
			}
		case <-migrationExit:
			return ErrMasterMigrationRequested
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
		case result := <-linkLatencyProbeReports:
			agentSequence++
			if err := stream.Send(&controlv1.AgentFrame{
				Sequence: agentSequence,
				Payload: &controlv1.AgentFrame_LinkLatencyProbeReport{
					LinkLatencyProbeReport: result.report,
				},
			}); err != nil {
				return fmt.Errorf("send on-demand Link latency report: %w", err)
			}
		case <-latencyTicks:
			if !latencyCollecting {
				latencyCollecting = true
				go func() { latencyReports <- collectLinkLatency(sessionContext, latencyProvider, r.now()) }()
			}
		case result := <-latencyReports:
			latencyCollecting = false
			if result.err != nil {
				slog.Warn("collect Link path latency", "error", result.err)
				continue
			}
			agentSequence++
			if err := stream.Send(&controlv1.AgentFrame{
				Sequence: agentSequence,
				Payload:  &controlv1.AgentFrame_LinkLatencyReport{LinkLatencyReport: result.report},
			}); err != nil {
				return fmt.Errorf("send Link latency report: %w", err)
			}
		case <-trafficTicks:
			if !trafficCollecting {
				trafficCollecting = true
				go collectManagedUserTraffic(sessionContext, trafficCollector, trafficReports)
			}
		case report := <-trafficReports:
			trafficCollecting = false
			requestIDs := trafficRequestIDs
			trafficRequestIDs = make([]string, 0, 1)
			users := make([]*controlv1.ManagedUserTraffic, 0, len(report.snapshot.Users))
			for _, usage := range report.snapshot.Users {
				users = append(users, &controlv1.ManagedUserTraffic{
					InboundPath: usage.InboundPath, Username: usage.Username,
					UplinkBytes: usage.UplinkBytes, DownlinkBytes: usage.DownlinkBytes,
				})
			}
			successfulEndpoints := report.snapshot.SuccessfulEndpoints
			if successfulEndpoints == 0 && report.err == nil && len(users) > 0 {
				// Compatibility for traffic collectors compiled against the earlier
				// snapshot shape and for small test doubles.
				successfulEndpoints = 1
			}
			partial := report.err != nil && successfulEndpoints > 0
			dataReady := partial || (report.err == nil && (successfulEndpoints > 0 || len(requestIDs) > 0))
			batchID := ""
			if dataReady {
				var batchErr error
				batchID, batchErr = newTrafficBatchID()
				if batchErr != nil {
					slog.Warn("identify managed-user traffic batch", "error", batchErr)
					report.err = batchErr
					dataReady = false
				}
			}
			sendTrafficReport := func(trafficReport *controlv1.ManagedUserTrafficReport) error {
				agentSequence++
				if err := stream.Send(&controlv1.AgentFrame{
					Sequence: agentSequence,
					Payload: &controlv1.AgentFrame_ManagedUserTrafficReport{
						ManagedUserTrafficReport: trafficReport,
					},
				}); err != nil {
					return err
				}
				return nil
			}
			if dataReady {
				dataRequestIDs := requestIDs
				if partial {
					// Persist every successfully reset entrance before reporting the
					// partial failure to the correlated request.
					dataRequestIDs = []string{""}
				} else if len(dataRequestIDs) == 0 {
					dataRequestIDs = []string{""}
				}
				for index, requestID := range dataRequestIDs {
					trafficReport := &controlv1.ManagedUserTrafficReport{
						Epoch: batchID, ObservedAtUnix: r.now().Unix(), RequestId: requestID,
					}
					// A collection may satisfy several coalesced master requests. Send
					// its deltas exactly once; later reports only complete their waiters.
					if index == 0 {
						trafficReport.Users = users
					}
					if err := sendTrafficReport(trafficReport); err != nil {
						return fmt.Errorf("send managed-user traffic report: %w", err)
					}
				}
			}
			if report.err != nil {
				slog.Warn("collect managed-user traffic", "error", report.err)
				failureRequestIDs := requestIDs
				if len(failureRequestIDs) == 0 {
					failureRequestIDs = []string{""}
				}
				for _, requestID := range failureRequestIDs {
					if err := sendTrafficReport(&controlv1.ManagedUserTrafficReport{
						ObservedAtUnix: r.now().Unix(), RequestId: requestID,
						Diagnostic: "managed-user traffic collection failed",
					}); err != nil {
						return fmt.Errorf("send managed-user traffic failure: %w", err)
					}
				}
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

func (r *Runner) applyManagedUserAuthority(
	ctx context.Context,
	manager managedUserAuthorityManager,
	command *controlv1.ManagedUserAuthorityCommand,
) *controlv1.ManagedUserAuthorityReport {
	report := &controlv1.ManagedUserAuthorityReport{
		Status:          controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_INTERNAL_ERROR,
		CompletedAtUnix: r.now().Unix(),
	}
	if command == nil {
		report.Diagnostic = "master sent an invalid managed-user authority command"
		return report
	}
	report.RequestId = command.GetRequestId()
	report.UserRevision = command.GetUserRevision()
	if strings.TrimSpace(report.RequestId) == "" || report.UserRevision == 0 || len(command.GetVariants()) == 0 {
		report.Status = controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_INVALID
		report.Diagnostic = "master sent an invalid managed-user authority command"
		return report
	}
	variants := make([]singbox.ManagedUserAuthorityVariant, 0, len(command.GetVariants()))
	for _, rawVariant := range command.GetVariants() {
		if rawVariant == nil || len(rawVariant.GetTopologySha256()) != sha256.Size {
			report.Status = controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_INVALID
			report.Diagnostic = "master sent an invalid managed-user authority variant"
			return report
		}
		variant := singbox.ManagedUserAuthorityVariant{}
		copy(variant.TopologySHA256[:], rawVariant.GetTopologySha256())
		for _, rawEndpoint := range rawVariant.GetEndpoints() {
			if rawEndpoint == nil {
				report.Status = controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_INVALID
				report.Diagnostic = "master sent an invalid managed-user authority endpoint"
				return report
			}
			endpoint := singbox.ManagedUserAuthorityEndpoint{Path: rawEndpoint.GetInboundPath()}
			for _, rawUser := range rawEndpoint.GetUsers() {
				if rawUser == nil {
					report.Status = controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_INVALID
					report.Diagnostic = "master sent an invalid managed-user authority user"
					return report
				}
				endpoint.Users = append(endpoint.Users, singbox.ManagedUserAuthorityUser{
					Username: rawUser.GetUsername(), Password: rawUser.GetPassword(),
				})
			}
			variant.Endpoints = append(variant.Endpoints, endpoint)
		}
		variants = append(variants, variant)
	}
	applyContext, cancel := context.WithTimeout(ctx, MaxValidationPeriod)
	defer cancel()
	result, err := manager.ApplyManagedUserAuthority(applyContext, report.UserRevision, variants)
	report.CompletedAtUnix = r.now().Unix()
	if err != nil {
		report.Diagnostic = "agent could not apply managed-user authority"
		return report
	}
	report.Diagnostic = result.Diagnostic
	switch result.Status {
	case singbox.ApplyStatusApplied:
		report.Status = controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_APPLIED
	case singbox.ApplyStatusValidationFailed:
		report.Status = controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_INVALID
	default:
		report.Status = controlv1.ManagedUserAuthorityStatus_MANAGED_USER_AUTHORITY_STATUS_INTERNAL_ERROR
	}
	return report
}

type trafficCollectionResult struct {
	snapshot singbox.ManagedUserTrafficSnapshot
	err      error
}

func newTrafficBatchID() (string, error) {
	var value [18]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate traffic batch identity: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func collectManagedUserTraffic(
	ctx context.Context,
	collector managedUserTrafficCollector,
	out chan<- trafficCollectionResult,
) {
	snapshot, err := collector.ManagedUserTraffic(ctx)
	select {
	case out <- trafficCollectionResult{snapshot: snapshot, err: err}:
	case <-ctx.Done():
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
	var result singbox.ApplyResult
	var err error
	if manager, ok := r.Manager.(classifiedConfigurationManager); ok {
		mode := singbox.ApplyModeGeneric
		switch deployment.ClassifyRevision(command.GetRevisionId()) {
		case deployment.RevisionPlaneProxyNodeTopology:
			mode = singbox.ApplyModeProxyNodeTopology
		case deployment.RevisionPlaneProxyNodeUsers:
			mode = singbox.ApplyModeProxyNodeUsers
		}
		result, err = manager.ApplyWithMode(
			applyContext, command.GetConfigJson(), command.GetConfigSha256(), mode,
		)
	} else {
		result, err = r.Manager.Apply(
			applyContext, command.GetConfigJson(), command.GetConfigSha256(),
		)
	}
	completed := r.now()
	report.CompletedAtUnix = completed.Unix()
	report.DurationMilliseconds = uint64(max(0, completed.Sub(started).Milliseconds()))
	if result.ConfigSHA256 != ([sha256.Size]byte{}) {
		report.ConfigSha256 = append(report.ConfigSha256[:0], result.ConfigSHA256[:]...)
	}
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

func (r *Runner) masterMigrationExitDelay() time.Duration {
	if r.MasterMigrationExitDelay > 0 {
		return r.MasterMigrationExitDelay
	}
	return 10 * time.Second
}
