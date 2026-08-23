package singbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	activeConfigDirectory = "sing-box"
	activeConfigFilename  = "active.json"

	defaultStartupGracePeriod = 750 * time.Millisecond
	defaultProcessStopTimeout = 5 * time.Second
	defaultRestartMinBackoff  = time.Second
	defaultRestartMaxBackoff  = 30 * time.Second
	defaultStablePeriod       = 30 * time.Second

	maxStartupDiagnosticBytes = 4096
)

var (
	ErrManagerAlreadyStarted = errors.New("sing-box manager is already started")
	ErrManagerNotRunning     = errors.New("sing-box manager is not running")
	errProcessExitedEarly    = errors.New("sing-box process exited during startup")
)

// StartupStatus describes what happened to a persisted configuration when a
// Manager started. A failed persisted configuration does not stop the manager;
// a later Apply call can replace it.
type StartupStatus string

const (
	StartupNoConfig         StartupStatus = "no_config"
	StartupRunning          StartupStatus = "running"
	StartupValidationFailed StartupStatus = "validation_failed"
	StartupActivationFailed StartupStatus = "activation_failed"
)

// StartupResult contains no configuration contents. Diagnostic is sanitized
// against every string value in the candidate configuration.
type StartupResult struct {
	Status           StartupStatus
	ValidationStatus ValidationStatus
	Diagnostic       string
	ConfigSHA256     [sha256.Size]byte
	LegacyQuarantine string
}

// RuntimeStatus describes an asynchronous child-process state change.
type RuntimeStatus string

const (
	RuntimeStatusRunning          RuntimeStatus = "running"
	RuntimeStatusExited           RuntimeStatus = "exited"
	RuntimeStatusRestartFailed    RuntimeStatus = "restart_failed"
	RuntimeStatusValidationFailed RuntimeStatus = "validation_failed"
	RuntimeStatusActivationFailed RuntimeStatus = "activation_failed"
	RuntimeStatusStopFailed       RuntimeStatus = "stop_failed"
	RuntimeStatusStopped          RuntimeStatus = "stopped"
)

// RuntimeEvent lets the agent report boot failures and post-activation crash
// loops without exposing configuration contents.
type RuntimeEvent struct {
	Status       RuntimeStatus
	ConfigSHA256 [sha256.Size]byte
	ObservedAt   time.Time
	Diagnostic   string
}

// ApplyStatus describes the terminal result of one configuration request.
type ApplyStatus string

const (
	ApplyStatusApplied          ApplyStatus = "applied"
	ApplyStatusValidationFailed ApplyStatus = "validation_failed"
	ApplyStatusActivationFailed ApplyStatus = "activation_failed"
	ApplyStatusInternalError    ApplyStatus = "internal_error"
)

// ApplyResult deliberately contains no configuration bytes.
type ApplyResult struct {
	Status           ApplyStatus
	ValidationStatus ValidationStatus
	Diagnostic       string
	ConfigSHA256     [sha256.Size]byte
	CheckedAt        time.Time
	Duration         time.Duration
	RolledBack       bool
	Active           bool
}

// ManagerOptions configures a non-root sing-box child-process manager.
type ManagerOptions struct {
	Validator          Validator
	ConfigGeneration   string
	AgentVersion       string
	AgentCommit        string
	StartupGracePeriod time.Duration
	ProcessStopTimeout time.Duration
	RestartMinBackoff  time.Duration
	RestartMaxBackoff  time.Duration
	StablePeriod       time.Duration
}

// Manager validates, persists, activates, and supervises one sing-box
// configuration. Start must be called before Apply.
type Manager struct {
	validator          Validator
	binaryPath         string
	stateDirectory     string
	configDirectory    string
	activeConfigPath   string
	maxConfigBytes     int
	startupGracePeriod time.Duration
	processStopTimeout time.Duration
	restartMinBackoff  time.Duration
	restartMaxBackoff  time.Duration
	stablePeriod       time.Duration
	configGeneration   string
	agentVersion       string
	agentCommit        string

	newProcess      func(string, string) managedProcess
	replaceFile     func(string, string) error
	checkExecutable func(context.Context, string) error
	now             func() time.Time

	lifecycleMu sync.Mutex
	started     bool
	running     bool
	cancel      context.CancelFunc
	apply       chan applyRequest
	done        chan struct{}
	terminalErr error
	events      chan RuntimeEvent
	eventsOnce  sync.Once
}

type applyRequest struct {
	ctx            context.Context
	config         []byte
	expectedDigest []byte
	result         chan applyResponse
}

type applyResponse struct {
	result ApplyResult
	err    error
}

type supervisorState struct {
	activeConfig  []byte
	hasActive     bool
	child         *runningProcess
	restart       bool
	restartFailed int
	retryTimer    *time.Timer
	retry         <-chan time.Time
}

type managedProcess interface {
	Start() error
	Wait() error
	Signal(os.Signal) error
	Kill() error
}

type runningProcess struct {
	process   managedProcess
	exit      <-chan error
	startedAt time.Time
}

type commandProcess struct {
	command   *exec.Cmd
	stderrBuf *boundedBuffer
}

func (p *commandProcess) Start() error                  { return p.command.Start() }
func (p *commandProcess) Wait() error                   { return p.command.Wait() }
func (p *commandProcess) Signal(signal os.Signal) error { return p.command.Process.Signal(signal) }
func (p *commandProcess) Kill() error                   { return p.command.Process.Kill() }

// NewManager returns an inactive manager. The Validator's BinaryPath and
// StateDirectory are also used for the managed process and active config.
func NewManager(options ManagerOptions) (*Manager, error) {
	binaryPath := options.Validator.BinaryPath
	if strings.TrimSpace(binaryPath) == "" {
		return nil, errors.New("sing-box executable path is required")
	}
	stateDirectory := options.Validator.StateDirectory
	if strings.TrimSpace(stateDirectory) == "" {
		return nil, errors.New("sing-box state directory is required")
	}
	if strings.IndexByte(binaryPath, 0) >= 0 ||
		strings.IndexByte(stateDirectory, 0) >= 0 {
		return nil, errors.New("sing-box manager paths contain invalid data")
	}

	startupGracePeriod := durationOrDefault(
		options.StartupGracePeriod,
		defaultStartupGracePeriod,
	)
	processStopTimeout := durationOrDefault(
		options.ProcessStopTimeout,
		defaultProcessStopTimeout,
	)
	restartMinBackoff := durationOrDefault(
		options.RestartMinBackoff,
		defaultRestartMinBackoff,
	)
	restartMaxBackoff := durationOrDefault(
		options.RestartMaxBackoff,
		defaultRestartMaxBackoff,
	)
	stablePeriod := durationOrDefault(options.StablePeriod, defaultStablePeriod)
	if restartMinBackoff > restartMaxBackoff {
		return nil, errors.New("sing-box restart minimum exceeds maximum")
	}

	maxConfigBytes := options.Validator.MaxConfigBytes
	if maxConfigBytes <= 0 {
		maxConfigBytes = DefaultMaxConfigBytes
	}
	cleanStateDirectory := filepath.Clean(stateDirectory)
	configDirectory := filepath.Join(cleanStateDirectory, activeConfigDirectory)
	validator := options.Validator
	validator.BinaryPath = binaryPath
	validator.StateDirectory = cleanStateDirectory
	manager := &Manager{
		validator:          validator,
		binaryPath:         binaryPath,
		stateDirectory:     cleanStateDirectory,
		configDirectory:    configDirectory,
		activeConfigPath:   filepath.Join(configDirectory, activeConfigFilename),
		maxConfigBytes:     maxConfigBytes,
		startupGracePeriod: startupGracePeriod,
		processStopTimeout: processStopTimeout,
		restartMinBackoff:  restartMinBackoff,
		restartMaxBackoff:  restartMaxBackoff,
		stablePeriod:       stablePeriod,
		configGeneration:   strings.TrimSpace(options.ConfigGeneration),
		agentVersion:       strings.TrimSpace(options.AgentVersion),
		agentCommit:        strings.TrimSpace(options.AgentCommit),
		replaceFile:        replaceConfigFile,
		checkExecutable:    CheckSupportedExecutable,
		now:                time.Now,
		events:             make(chan RuntimeEvent, 16),
	}
	manager.newProcess = func(executable, configPath string) managedProcess {
		command := exec.Command(executable, "run", "-c", configPath)
		command.Dir = cleanStateDirectory
		// A validation or runtime error must not accidentally copy credentials
		// from a configuration into the agent's journal.
		command.Stdout = io.Discard
		stderrBuf := newBoundedBuffer(maxStartupDiagnosticBytes)
		command.Stderr = stderrBuf
		return &commandProcess{command: command, stderrBuf: stderrBuf}
	}
	return manager, nil
}

func durationOrDefault(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

// ActiveConfigPath returns the fixed path managed by this instance.
func (m *Manager) ActiveConfigPath() string {
	return m.activeConfigPath
}

// Events returns a bounded stream of secret-free runtime state changes. A slow
// consumer may miss intermediate events, but the newest event is retained.
func (m *Manager) Events() <-chan RuntimeEvent {
	return m.events
}

// ResetForEnrollment removes the inactive persisted configuration before a
// newly enrolled Agent starts. This makes a master transfer fail closed: an
// old master's profile cannot start while the new master is reconnecting or
// preparing its authoritative deployment.
func (m *Manager) ResetForEnrollment() error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.started {
		return errors.New("cannot reset a running sing-box manager")
	}
	if err := m.prepareDirectories(); err != nil {
		return err
	}
	if err := m.restoreConfig(nil, false); err != nil {
		return fmt.Errorf("remove previous active configuration: %w", err)
	}
	certificates := filepath.Join(m.stateDirectory, managedSelfSignedDirectory)
	certificatesExist, err := safeDirectoryExists(certificates)
	if err != nil {
		return fmt.Errorf("inspect previous managed certificates: %w", err)
	}
	if certificatesExist {
		if err := os.RemoveAll(certificates); err != nil {
			return fmt.Errorf("remove previous managed certificates: %w", err)
		}
		if err := syncDirectory(filepath.Dir(certificates)); err != nil {
			return fmt.Errorf("flush managed certificate reset: %w", err)
		}
	}
	return nil
}

// Start prepares secure state, validates a persisted active configuration, and
// starts its child. The supervisor remains available after a boot validation
// or activation failure so that Apply can repair the server.
func (m *Manager) Start(ctx context.Context) (StartupResult, error) {
	if ctx == nil {
		return StartupResult{}, errors.New("sing-box manager context is required")
	}

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.started {
		return StartupResult{}, ErrManagerAlreadyStarted
	}
	if err := ctx.Err(); err != nil {
		return StartupResult{}, err
	}
	if err := m.checkExecutable(ctx, m.binaryPath); err != nil {
		return StartupResult{}, fmt.Errorf("check sing-box executable: %w", err)
	}
	if err := m.prepareDirectories(); err != nil {
		return StartupResult{}, err
	}
	quarantine, err := m.prepareConfigGeneration()
	if err != nil {
		return StartupResult{}, err
	}

	activeConfig, hasActive, err := m.loadActiveConfig()
	if err != nil {
		return StartupResult{}, err
	}
	runContext, cancel := context.WithCancel(ctx)
	state := supervisorState{
		activeConfig: activeConfig,
		hasActive:    hasActive,
	}
	startup := StartupResult{Status: StartupNoConfig, LegacyQuarantine: quarantine}
	var startErr error
	if hasActive {
		digest := sha256.Sum256(activeConfig)
		startup.ConfigSHA256 = digest
		if policyErr := ValidateManagedConfig(activeConfig); policyErr != nil {
			startup.ValidationStatus = ValidationInvalid
			startup.Diagnostic = managedPolicyDiagnostic(policyErr)
			startup.Status = StartupValidationFailed
			m.emitRuntimeEvent(
				RuntimeStatusValidationFailed,
				activeConfig,
				startup.Diagnostic,
			)
		} else {
			validation := m.validator.Check(runContext, activeConfig, digest[:])
			startup.ValidationStatus = validation.Status
			startup.Diagnostic = redactConfigValues(validation.Diagnostic, activeConfig)
			switch validation.Status {
			case ValidationValid:
				child, launchErr := m.launchProcess(runContext)
				if launchErr == nil {
					state.child = child
					state.restart = true
					startup.Status = StartupRunning
					m.emitRuntimeEvent(RuntimeStatusRunning, activeConfig, "")
				} else {
					state.child = child
					state.restart = runContext.Err() == nil
					state.restartFailed = 1
					startup.Status = StartupActivationFailed
					if !errors.Is(launchErr, errProcessExitedEarly) {
						startup.Diagnostic = sanitizeStartupOutput(launchErr.Error())
					} else {
						startup.Diagnostic = "sing-box could not activate the persisted configuration"
					}
					m.emitRuntimeEvent(
						RuntimeStatusActivationFailed,
						activeConfig,
						startup.Diagnostic,
					)
					if runContext.Err() != nil {
						if child == nil {
							cancel()
							clear(activeConfig)
							return StartupResult{}, runContext.Err()
						}
						state.restart = false
						startErr = runContext.Err()
					}
				}
			default:
				startup.Status = StartupValidationFailed
				m.emitRuntimeEvent(
					RuntimeStatusValidationFailed,
					activeConfig,
					startup.Diagnostic,
				)
			}
		}
	}
	if err := runContext.Err(); err != nil && startErr == nil {
		cancel()
		clear(activeConfig)
		return StartupResult{}, err
	}

	m.started = true
	m.running = true
	m.cancel = cancel
	m.apply = make(chan applyRequest)
	m.done = make(chan struct{})
	go m.supervise(runContext, state)
	return startup, startErr
}

// Apply validates a candidate without interrupting the current process. Only a
// valid candidate is atomically persisted and activated. If activation fails,
// the previous file and process are restored.
func (m *Manager) Apply(
	ctx context.Context,
	config []byte,
	expectedDigest []byte,
) (ApplyResult, error) {
	if ctx == nil {
		return ApplyResult{}, errors.New("sing-box apply context is required")
	}
	if len(config) > m.maxConfigBytes {
		return ApplyResult{
			Status:           ApplyStatusInternalError,
			ValidationStatus: ValidationInternalError,
			ConfigSHA256:     sha256.Sum256(config),
			Diagnostic: fmt.Sprintf(
				"candidate configuration exceeds the %d-byte limit",
				m.maxConfigBytes,
			),
		}, nil
	}
	if len(expectedDigest) != sha256.Size {
		return ApplyResult{
			Status:           ApplyStatusInternalError,
			ValidationStatus: ValidationInternalError,
			ConfigSHA256:     sha256.Sum256(config),
			Diagnostic:       "candidate configuration digest has an invalid length",
		}, nil
	}
	actualDigest := sha256.Sum256(config)
	if !bytes.Equal(actualDigest[:], expectedDigest) {
		return ApplyResult{
			Status:           ApplyStatusInternalError,
			ValidationStatus: ValidationInternalError,
			ConfigSHA256:     actualDigest,
			Diagnostic:       "candidate configuration digest does not match the deployment command",
		}, nil
	}
	if policyErr := ValidateManagedConfig(config); policyErr != nil {
		return ApplyResult{
			Status:           ApplyStatusValidationFailed,
			ValidationStatus: ValidationInvalid,
			ConfigSHA256:     actualDigest,
			CheckedAt:        m.now().UTC(),
			Diagnostic:       managedPolicyDiagnostic(policyErr),
		}, nil
	}

	m.lifecycleMu.Lock()
	if !m.running {
		m.lifecycleMu.Unlock()
		return ApplyResult{}, ErrManagerNotRunning
	}
	requests := m.apply
	done := m.done
	m.lifecycleMu.Unlock()

	request := applyRequest{
		ctx:            ctx,
		config:         append([]byte(nil), config...),
		expectedDigest: append([]byte(nil), expectedDigest...),
		result:         make(chan applyResponse, 1),
	}
	select {
	case requests <- request:
	case <-ctx.Done():
		clear(request.config)
		clear(request.expectedDigest)
		return ApplyResult{}, ctx.Err()
	case <-done:
		clear(request.config)
		clear(request.expectedDigest)
		return ApplyResult{}, ErrManagerNotRunning
	}

	select {
	case response := <-request.result:
		return response.result, response.err
	case <-done:
		// Once the supervisor accepts a request it always publishes the
		// terminal apply result before completing shutdown.
		select {
		case response := <-request.result:
			return response.result, response.err
		default:
			return ApplyResult{}, ErrManagerNotRunning
		}
	}
}

// Stop cancels supervision and waits for the child process to stop.
func (m *Manager) Stop(ctx context.Context) error {
	if ctx == nil {
		return errors.New("sing-box stop context is required")
	}
	m.lifecycleMu.Lock()
	if !m.started {
		m.lifecycleMu.Unlock()
		return nil
	}
	cancel := m.cancel
	done := m.done
	m.lifecycleMu.Unlock()

	cancel()
	select {
	case <-done:
		m.lifecycleMu.Lock()
		err := m.terminalErr
		m.lifecycleMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) supervise(ctx context.Context, state supervisorState) {
	if state.restart && state.child == nil {
		m.scheduleRestart(&state)
	}
	var terminalErr error
	defer func() {
		m.stopRetryTimer(&state)
		shutdownContext, cancel := context.WithTimeout(
			context.Background(),
			m.processStopTimeout+m.reapTimeout(),
		)
		defer cancel()
		if err := m.stopProcess(shutdownContext, state.child); err != nil {
			terminalErr = err
			m.emitRuntimeEvent(
				RuntimeStatusStopFailed,
				state.activeConfig,
				"managed sing-box termination could not be confirmed",
			)
			m.trackProcessUntilExit(state.child, true)
		} else {
			m.emitRuntimeEvent(RuntimeStatusStopped, state.activeConfig, "")
			m.closeRuntimeEvents()
		}
		clear(state.activeConfig)

		m.lifecycleMu.Lock()
		m.running = false
		m.terminalErr = terminalErr
		close(m.done)
		m.lifecycleMu.Unlock()
	}()

	for {
		var processExit <-chan error
		if state.child != nil {
			processExit = state.child.exit
		}
		select {
		case <-ctx.Done():
			return
		case request := <-m.apply:
			result, err := m.applyCandidate(ctx, &state, request)
			clear(request.config)
			clear(request.expectedDigest)
			request.result <- applyResponse{result: result, err: err}
		case <-processExit:
			runPeriod := m.now().Sub(state.child.startedAt)
			m.emitRuntimeEvent(
				RuntimeStatusExited,
				state.activeConfig,
				"managed sing-box exited unexpectedly",
			)
			state.child = nil
			if state.restart && state.hasActive {
				if runPeriod >= m.stablePeriod {
					state.restartFailed = 0
				}
				state.restartFailed++
				m.scheduleRestart(&state)
			}
		case <-state.retry:
			m.stopRetryTimer(&state)
			if !state.restart || !state.hasActive {
				continue
			}
			if !m.activeConfigMatches(state.activeConfig) {
				state.restart = false
				m.emitRuntimeEvent(
					RuntimeStatusActivationFailed,
					state.activeConfig,
					"active configuration changed outside the manager; automatic restart was disabled",
				)
				continue
			}
			child, err := m.launchProcess(ctx)
			if err != nil {
				if ctx.Err() != nil {
					state.child = child
					state.restart = false
					return
				}
				if child != nil {
					state.child = child
					state.restart = false
					m.emitRuntimeEvent(
						RuntimeStatusActivationFailed,
						state.activeConfig,
						"managed sing-box restart could not be stopped safely",
					)
					continue
				}
				state.restartFailed++
				m.emitRuntimeEvent(
					RuntimeStatusRestartFailed,
					state.activeConfig,
					"managed sing-box could not be restarted",
				)
				m.scheduleRestart(&state)
				continue
			}
			state.child = child
			m.emitRuntimeEvent(RuntimeStatusRunning, state.activeConfig, "")
		}
	}
}

func (m *Manager) applyCandidate(
	managerContext context.Context,
	state *supervisorState,
	request applyRequest,
) (ApplyResult, error) {
	validationContext, cancelValidation := context.WithCancel(request.ctx)
	stopCancellation := context.AfterFunc(managerContext, cancelValidation)
	validation := m.validator.Check(
		validationContext,
		request.config,
		request.expectedDigest,
	)
	stopCancellation()
	cancelValidation()

	result := ApplyResult{
		ValidationStatus: validation.Status,
		Diagnostic:       redactConfigValues(validation.Diagnostic, request.config),
		ConfigSHA256:     validation.ConfigSHA256,
		CheckedAt:        validation.CheckedAt,
		Duration:         validation.Duration,
		Active:           state.child != nil,
	}
	switch validation.Status {
	case ValidationInvalid:
		result.Status = ApplyStatusValidationFailed
		return result, nil
	case ValidationValid:
	default:
		result.Status = ApplyStatusInternalError
		return result, nil
	}
	if err := managerContext.Err(); err != nil {
		result.Status = ApplyStatusInternalError
		result.Diagnostic = "sing-box manager is shutting down"
		return result, err
	}
	if err := request.ctx.Err(); err != nil {
		result.Status = ApplyStatusInternalError
		result.Diagnostic = "configuration deployment timed out before activation"
		return result, err
	}

	stagedPath, err := m.stageConfig(request.config)
	if err != nil {
		result.Status = ApplyStatusInternalError
		result.Diagnostic = "candidate configuration could not be staged"
		return result, nil
	}
	if err := request.ctx.Err(); err != nil {
		_ = os.Remove(stagedPath)
		result.Status = ApplyStatusInternalError
		result.Diagnostic = "configuration deployment timed out before activation"
		return result, err
	}
	stagedInstalled := false
	defer func() {
		if !stagedInstalled {
			_ = os.Remove(stagedPath)
		}
	}()

	previousConfig := append([]byte(nil), state.activeConfig...)
	hadPrevious := state.hasActive
	restartPrevious := state.restart
	previousChild := state.child
	m.stopRetryTimer(state)
	state.restart = false
	state.child = nil

	operationContext, cancelOperation := context.WithTimeout(
		context.Background(),
		m.processStopTimeout+m.reapTimeout(),
	)
	stopErr := m.stopProcess(operationContext, previousChild)
	cancelOperation()
	if stopErr != nil {
		state.child = previousChild
		state.restart = restartPrevious
		clear(previousConfig)
		result.Status = ApplyStatusInternalError
		result.Diagnostic = "the active sing-box process could not be stopped safely"
		return result, nil
	}

	installed, installErr := m.installStagedConfig(stagedPath)
	stagedInstalled = installed
	if installErr != nil {
		if installed {
			if restoreErr := m.restoreConfig(previousConfig, hadPrevious); restoreErr != nil {
				clear(previousConfig)
				state.hasActive = false
				state.restart = false
				result.Status = ApplyStatusInternalError
				result.Diagnostic = "candidate persistence failed and the previous configuration could not be restored"
				result.Active = false
				return result, nil
			}
		}
		state.restart = restartPrevious
		rollbackChild, rollbackRunning := m.restartPreviousConfig(
			restartPrevious,
			state,
		)
		state.child = rollbackChild
		clear(previousConfig)
		result.Status = ApplyStatusInternalError
		result.Diagnostic = "candidate configuration could not be persisted"
		result.RolledBack = hadPrevious
		result.Active = rollbackRunning
		if restartPrevious && !rollbackRunning {
			result.Diagnostic += "; the previous configuration was restored, but sing-box has not restarted yet"
			m.emitRuntimeEvent(
				RuntimeStatusRestartFailed,
				state.activeConfig,
				"the previous sing-box configuration was restored but has not restarted yet",
			)
		}
		return result, nil
	}
	stagedInstalled = true

	launchContext, cancelLaunch := context.WithTimeout(
		context.Background(),
		m.startupGracePeriod+m.processStopTimeout,
	)
	candidateChild, launchErr := m.launchProcess(launchContext)
	cancelLaunch()
	if launchErr == nil {
		clear(state.activeConfig)
		state.activeConfig = append([]byte(nil), request.config...)
		state.hasActive = true
		state.child = candidateChild
		state.restart = true
		state.restartFailed = 0
		clear(previousConfig)
		result.Status = ApplyStatusApplied
		result.Diagnostic = ""
		result.Active = true
		m.emitRuntimeEvent(RuntimeStatusRunning, state.activeConfig, "")
		return result, nil
	}
	if candidateChild != nil {
		clear(state.activeConfig)
		state.activeConfig = append([]byte(nil), request.config...)
		state.hasActive = true
		state.child = candidateChild
		state.restart = false
		clear(previousConfig)
		result.Status = ApplyStatusInternalError
		result.Diagnostic = "candidate activation did not reach a stable state and its process could not be stopped safely"
		result.Active = false
		m.emitRuntimeEvent(
			RuntimeStatusStopFailed,
			state.activeConfig,
			result.Diagnostic,
		)
		return result, nil
	}

	restoreErr := m.restoreConfig(previousConfig, hadPrevious)
	if restoreErr != nil {
		clear(previousConfig)
		state.hasActive = false
		state.restart = false
		result.Status = ApplyStatusInternalError
		result.Diagnostic = "candidate activation failed and the previous configuration could not be restored"
		result.Active = false
		return result, nil
	}

	clear(state.activeConfig)
	state.activeConfig = previousConfig
	state.hasActive = hadPrevious
	state.restart = restartPrevious
	state.restartFailed = 0
	rollbackChild, rollbackRunning := m.restartPreviousConfig(
		restartPrevious,
		state,
	)
	state.child = rollbackChild
	result.Status = ApplyStatusActivationFailed
	result.Diagnostic = "sing-box exited before the candidate configuration became active"
	if launchErr != nil && !errors.Is(launchErr, errProcessExitedEarly) {
		result.Diagnostic = sanitizeStartupOutput(launchErr.Error())
	}
	result.RolledBack = hadPrevious
	result.Active = rollbackRunning
	if restartPrevious && !rollbackRunning {
		result.Diagnostic += "; the previous configuration was restored, but sing-box has not restarted yet"
	}
	if restartPrevious && !rollbackRunning {
		m.emitRuntimeEvent(
			RuntimeStatusRestartFailed,
			state.activeConfig,
			"the previous sing-box configuration was restored but has not restarted yet",
		)
	}
	return result, nil
}

func (m *Manager) restartPreviousConfig(
	restartPrevious bool,
	state *supervisorState,
) (*runningProcess, bool) {
	if !restartPrevious {
		return nil, false
	}
	restartContext, cancel := context.WithTimeout(
		context.Background(),
		m.startupGracePeriod+m.processStopTimeout,
	)
	defer cancel()
	child, err := m.launchProcess(restartContext)
	if err == nil {
		return child, true
	}
	if child != nil {
		return child, false
	}
	state.restartFailed++
	m.scheduleRestart(state)
	return nil, false
}

func (m *Manager) prepareDirectories() error {
	if err := ensureSecureDirectory(m.stateDirectory); err != nil {
		return fmt.Errorf("secure sing-box state directory: %w", err)
	}
	if err := ensureSecureDirectory(m.configDirectory); err != nil {
		return fmt.Errorf("secure active configuration directory: %w", err)
	}
	if err := ensureSecureDirectory(
		filepath.Join(m.stateDirectory, "validation"),
	); err != nil {
		return fmt.Errorf("secure validation directory: %w", err)
	}
	return nil
}

func ensureSecureDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path is not a regular directory")
	}
	return os.Chmod(path, 0o700)
}

func (m *Manager) loadActiveConfig() ([]byte, bool, error) {
	info, err := os.Lstat(m.activeConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect active sing-box configuration: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, errors.New("active sing-box configuration is not a regular file")
	}
	if info.Size() > int64(m.maxConfigBytes) {
		return nil, false, errors.New("active sing-box configuration exceeds the size limit")
	}

	file, err := os.Open(m.activeConfigPath)
	if err != nil {
		return nil, false, fmt.Errorf("open active sing-box configuration: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("inspect opened sing-box configuration: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, false, errors.New("active sing-box configuration changed while opening")
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, false, fmt.Errorf("secure active sing-box configuration: %w", err)
	}
	config, err := io.ReadAll(io.LimitReader(file, int64(m.maxConfigBytes)+1))
	if err != nil {
		clear(config)
		return nil, false, fmt.Errorf("read active sing-box configuration: %w", err)
	}
	if len(config) > m.maxConfigBytes {
		clear(config)
		return nil, false, errors.New("active sing-box configuration exceeds the size limit")
	}
	return config, true, nil
}

func (m *Manager) stageConfig(config []byte) (string, error) {
	file, err := os.CreateTemp(m.configDirectory, ".candidate-*.json")
	if err != nil {
		return "", err
	}
	path := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := file.Write(config); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	keep = true
	return path, nil
}

func (m *Manager) installStagedConfig(stagedPath string) (bool, error) {
	if err := rejectUnsafeFileIfPresent(m.activeConfigPath, m.maxConfigBytes); err != nil {
		return false, err
	}
	if err := m.replaceFile(stagedPath, m.activeConfigPath); err != nil {
		return false, err
	}
	if err := os.Chmod(m.activeConfigPath, 0o600); err != nil {
		return true, err
	}
	if err := syncDirectory(m.configDirectory); err != nil {
		return true, err
	}
	return true, nil
}

func (m *Manager) restoreConfig(config []byte, existed bool) error {
	if !existed {
		if err := rejectUnsafeFileIfPresent(m.activeConfigPath, m.maxConfigBytes); err != nil {
			return err
		}
		err := os.Remove(m.activeConfigPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(m.configDirectory)
	}
	stagedPath, err := m.stageConfig(config)
	if err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(stagedPath)
		}
	}()
	installed, err = m.installStagedConfig(stagedPath)
	if err != nil {
		return err
	}
	return nil
}

func rejectUnsafeFileIfPresent(path string, maxBytes int) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("active sing-box configuration is not a regular file")
	}
	if info.Size() > int64(maxBytes) {
		return errors.New("active sing-box configuration exceeds the size limit")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}

func (m *Manager) launchProcess(ctx context.Context) (*runningProcess, error) {
	process := m.newProcess(m.binaryPath, m.activeConfigPath)
	if process == nil {
		return nil, errors.New("sing-box process factory returned nil")
	}
	if err := process.Start(); err != nil {
		return nil, err
	}
	exit := make(chan error, 1)
	running := &runningProcess{
		process:   process,
		exit:      exit,
		startedAt: m.now(),
	}
	go func() {
		exit <- process.Wait()
		close(exit)
	}()

	timer := time.NewTimer(m.startupGracePeriod)
	defer timer.Stop()
	select {
	case <-exit:
		stderr := ""
		if cp, ok := process.(*commandProcess); ok {
			stderr = strings.TrimSpace(cp.stderrBuf.String())
		}
		if stderr != "" {
			return nil, fmt.Errorf(
				"sing-box exited during startup: %s",
				sanitizeStartupOutput(stderr),
			)
		}
		return nil, errProcessExitedEarly
	case <-timer.C:
		return running, nil
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(
			context.Background(),
			m.processStopTimeout+m.reapTimeout(),
		)
		defer cancel()
		if err := m.stopProcess(shutdownContext, running); err != nil {
			return running, fmt.Errorf(
				"stop sing-box after canceled startup: %w",
				err,
			)
		}
		return nil, ctx.Err()
	}
}

func (m *Manager) stopProcess(ctx context.Context, child *runningProcess) error {
	if child == nil {
		return nil
	}
	select {
	case <-child.exit:
		return nil
	default:
	}

	signalErr := child.process.Signal(os.Interrupt)
	if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
		return m.killAndReap(ctx, child)
	}

	timer := time.NewTimer(m.processStopTimeout)
	defer timer.Stop()
	select {
	case <-child.exit:
		return nil
	case <-timer.C:
		return m.killAndReap(ctx, child)
	case <-ctx.Done():
		return m.killAndReap(ctx, child)
	}
}

func (m *Manager) killAndReap(
	ctx context.Context,
	child *runningProcess,
) error {
	if err := child.process.Kill(); err != nil &&
		!errors.Is(err, os.ErrProcessDone) {
		return errors.New("could not kill sing-box process")
	}
	select {
	case <-child.exit:
		return nil
	case <-ctx.Done():
		return errors.New("sing-box process did not exit after being killed")
	}
}

func (m *Manager) reapTimeout() time.Duration {
	return min(m.processStopTimeout, time.Second)
}

// trackProcessUntilExit retains the only process handle after a bounded
// shutdown attempt failed. It keeps issuing an exact process kill without
// blocking the control channel and exits only after Wait has completed.
func (m *Manager) trackProcessUntilExit(
	child *runningProcess,
	closeEvents bool,
) {
	if child == nil {
		if closeEvents {
			m.closeRuntimeEvents()
		}
		return
	}
	go func() {
		delay := m.restartMinBackoff
		for {
			select {
			case <-child.exit:
				if closeEvents {
					m.emitRuntimeEvent(RuntimeStatusStopped, nil, "")
					m.closeRuntimeEvents()
				}
				return
			case <-time.After(delay):
				_ = child.process.Kill()
				if delay < m.restartMaxBackoff {
					if delay >= m.restartMaxBackoff/2 {
						delay = m.restartMaxBackoff
					} else {
						delay *= 2
					}
				}
			}
		}
	}()
}

func (m *Manager) activeConfigMatches(expected []byte) bool {
	config, exists, err := m.loadActiveConfig()
	if err != nil || !exists {
		clear(config)
		return false
	}
	defer clear(config)
	expectedDigest := sha256.Sum256(expected)
	actualDigest := sha256.Sum256(config)
	return bytes.Equal(expectedDigest[:], actualDigest[:])
}

func (m *Manager) scheduleRestart(state *supervisorState) {
	if state.retryTimer != nil || !state.restart || !state.hasActive {
		return
	}
	delay := m.restartDelay(state.restartFailed)
	state.retryTimer = time.NewTimer(delay)
	state.retry = state.retryTimer.C
}

func (m *Manager) stopRetryTimer(state *supervisorState) {
	if state.retryTimer != nil {
		if !state.retryTimer.Stop() {
			select {
			case <-state.retryTimer.C:
			default:
			}
		}
	}
	state.retryTimer = nil
	state.retry = nil
}

func (m *Manager) restartDelay(failures int) time.Duration {
	if failures <= 1 {
		return m.restartMinBackoff
	}
	delay := m.restartMinBackoff
	for attempt := 1; attempt < failures; attempt++ {
		if delay >= m.restartMaxBackoff/2 {
			return m.restartMaxBackoff
		}
		delay *= 2
	}
	return min(delay, m.restartMaxBackoff)
}

func redactConfigValues(diagnostic string, config []byte) string {
	if diagnostic == "" || !json.Valid(config) {
		return diagnostic
	}
	var document any
	if err := json.Unmarshal(config, &document); err != nil {
		return diagnostic
	}
	unique := make(map[string]struct{})
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for _, child := range typed {
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		case string:
			if typed != "" {
				unique[typed] = struct{}{}
			}
		}
	}
	visit(document)
	values := make([]string, 0, len(unique))
	for value := range unique {
		values = append(values, value)
	}
	sort.Slice(values, func(left, right int) bool {
		return len(values[left]) > len(values[right])
	})
	clean := diagnostic
	for _, value := range values {
		clean = strings.ReplaceAll(clean, value, "<redacted>")
	}
	return clean
}

func managedPolicyDiagnostic(err error) string {
	if errors.Is(err, ErrReservedListenPort) {
		return ReservedListenPortMessage()
	}
	return "candidate configuration is not valid managed sing-box JSON"
}

func (m *Manager) emitRuntimeEvent(
	status RuntimeStatus,
	config []byte,
	diagnostic string,
) {
	event := RuntimeEvent{
		Status:       status,
		ConfigSHA256: sha256.Sum256(config),
		ObservedAt:   m.now().UTC(),
		Diagnostic:   diagnostic,
	}
	select {
	case m.events <- event:
		return
	default:
	}
	select {
	case <-m.events:
	default:
	}
	select {
	case m.events <- event:
	default:
	}
}

func (m *Manager) closeRuntimeEvents() {
	m.eventsOnce.Do(func() {
		close(m.events)
	})
}

type boundedBuffer struct {
	buf      []byte
	maxBytes int
}

func newBoundedBuffer(maxBytes int) *boundedBuffer {
	return &boundedBuffer{maxBytes: maxBytes}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.maxBytes - len(b.buf)
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		b.buf = append(b.buf, p[:remaining]...)
		b.buf = append(b.buf, []byte("\n<output truncated>")...)
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	return string(b.buf)
}

func sanitizeStartupOutput(raw string) string {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == ' ' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, raw)
	clean = strings.TrimSpace(clean)
	if len(clean) > maxStartupDiagnosticBytes {
		clean = clean[:maxStartupDiagnosticBytes] + "\n<output truncated>"
	}
	return clean
}
