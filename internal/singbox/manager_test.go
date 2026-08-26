package singbox

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testStartupGrace = 8 * time.Millisecond
	testStopTimeout  = 100 * time.Millisecond
	testMinBackoff   = 5 * time.Millisecond
	testMaxBackoff   = 20 * time.Millisecond
	testStablePeriod = 50 * time.Millisecond
)

type fakeProcessPlan struct {
	startErr   error
	onStart    func()
	ignoreStop bool
	ignoreKill bool
	killDelay  time.Duration
	autoExit   bool
	exitAfter  time.Duration
	exitErr    error
}

type fakeProcessFactory struct {
	mu        sync.Mutex
	plans     []fakeProcessPlan
	processes []*fakeProcess
	starts    []time.Time
	binaries  []string
	configs   []string
}

func (f *fakeProcessFactory) newProcess(binaryPath, configPath string) managedProcess {
	f.mu.Lock()
	plan := fakeProcessPlan{}
	if len(f.plans) > 0 {
		plan = f.plans[0]
		f.plans = f.plans[1:]
	}
	process := &fakeProcess{
		plan: plan,
		exit: make(chan error, 1),
	}
	f.processes = append(f.processes, process)
	f.binaries = append(f.binaries, binaryPath)
	f.configs = append(f.configs, configPath)
	f.mu.Unlock()
	return process
}

func (f *fakeProcessFactory) snapshot() ([]*fakeProcess, []time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeProcess(nil), f.processes...),
		append([]time.Time(nil), f.starts...)
}

type fakeProcess struct {
	plan fakeProcessPlan

	mu       sync.Mutex
	exit     chan error
	exitOnce sync.Once
	started  bool
	exited   bool
	signals  int
	kills    int
}

func (p *fakeProcess) Start() error {
	p.mu.Lock()
	if p.plan.startErr != nil {
		err := p.plan.startErr
		p.mu.Unlock()
		return err
	}
	p.started = true
	autoExit := p.plan.autoExit
	onStart := p.plan.onStart
	exitAfter := p.plan.exitAfter
	exitErr := p.plan.exitErr
	p.mu.Unlock()
	if onStart != nil {
		onStart()
	}
	if autoExit {
		go func() {
			timer := time.NewTimer(exitAfter)
			defer timer.Stop()
			<-timer.C
			p.finish(exitErr)
		}()
	}
	return nil
}

func (p *fakeProcess) Wait() error {
	return <-p.exit
}

func (p *fakeProcess) Signal(os.Signal) error {
	p.mu.Lock()
	p.signals++
	exited := p.exitedLocked()
	p.mu.Unlock()
	if exited {
		return os.ErrProcessDone
	}
	if p.plan.ignoreStop {
		return nil
	}
	p.finish(nil)
	return nil
}

func (p *fakeProcess) Kill() error {
	p.mu.Lock()
	p.kills++
	exited := p.exitedLocked()
	ignoreKill := p.plan.ignoreKill
	killDelay := p.plan.killDelay
	p.mu.Unlock()
	if exited {
		return os.ErrProcessDone
	}
	if ignoreKill {
		return nil
	}
	if killDelay > 0 {
		go func() {
			timer := time.NewTimer(killDelay)
			defer timer.Stop()
			<-timer.C
			p.finish(errors.New("killed"))
		}()
		return nil
	}
	p.finish(errors.New("killed"))
	return nil
}

func (p *fakeProcess) finish(err error) {
	p.exitOnce.Do(func() {
		p.mu.Lock()
		p.exited = true
		p.mu.Unlock()
		p.exit <- err
	})
}

func (p *fakeProcess) exitedLocked() bool {
	return p.exited
}

func (p *fakeProcess) signalCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signals
}

func newTestManager(
	t *testing.T,
	factory *fakeProcessFactory,
	runCheck func(context.Context, string, string, io.Writer) error,
) *Manager {
	t.Helper()
	if runCheck == nil {
		runCheck = func(context.Context, string, string, io.Writer) error {
			return nil
		}
	}
	manager, err := NewManager(ManagerOptions{
		Validator: Validator{
			BinaryPath:     "sing-box-test",
			StateDirectory: t.TempDir(),
			runCommand:     runCheck,
		},
		StartupGracePeriod: testStartupGrace,
		ProcessStopTimeout: testStopTimeout,
		RestartMinBackoff:  testMinBackoff,
		RestartMaxBackoff:  testMaxBackoff,
		StablePeriod:       testStablePeriod,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.checkExecutable = func(context.Context, string) error {
		return nil
	}
	manager.newProcess = factory.newProcess
	return manager
}

func TestManagerRefusesUnavailableSingBoxBeforeAdvertisingReadiness(t *testing.T) {
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	manager.checkExecutable = func(context.Context, string) error {
		return errors.New("not installed")
	}

	if _, err := manager.Start(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "check sing-box executable") {
		t.Fatalf("Start() error = %v, want executable check failure", err)
	}
	processes, _ := factory.snapshot()
	if len(processes) != 0 {
		t.Fatal("manager started a child after the executable check failed")
	}
}

func TestManagerResetForEnrollmentRemovesPreviousActiveConfig(t *testing.T) {
	t.Parallel()

	manager := newTestManager(t, &fakeProcessFactory{}, nil)
	if err := os.MkdirAll(filepath.Dir(manager.ActiveConfigPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		manager.ActiveConfigPath(),
		[]byte(`{"inbounds":[{"type":"anytls","listen_port":443}]}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(filepath.Dir(manager.ActiveConfigPath()), legacyTrafficLedger),
		[]byte(`{"version":1,"epoch":"old-accounting-state"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	certificateDirectory := filepath.Join(manager.stateDirectory, managedSelfSignedDirectory, "old-profile")
	if err := os.MkdirAll(certificateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(certificateDirectory, "private-key.pem"),
		[]byte("old private key"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := manager.ResetForEnrollment(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(manager.ActiveConfigPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active config after enrollment reset: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(manager.ActiveConfigPath()), legacyTrafficLedger)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("traffic ledger after enrollment reset: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(manager.stateDirectory, managedSelfSignedDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed certificates after enrollment reset: %v", err)
	}
}

func TestManagerStartRemovesLegacyTrafficLedger(t *testing.T) {
	t.Parallel()
	manager := newTestManager(t, &fakeProcessFactory{}, nil)
	ledgerPath := filepath.Join(filepath.Dir(manager.ActiveConfigPath()), legacyTrafficLedger)
	if err := os.MkdirAll(filepath.Dir(ledgerPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledgerPath, []byte(`{"obsolete":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(ledgerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy traffic ledger after startup: %v", err)
	}
	stopContext, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := manager.Stop(stopContext); err != nil {
		t.Fatal(err)
	}
}

func TestManagerManagedUserAuthorityRejectsStaleRevision(t *testing.T) {
	manager := newTestManager(t, &fakeProcessFactory{}, nil)
	runContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := manager.Start(runContext); err != nil {
		t.Fatal(err)
	}
	variant, err := BuildManagedUserAuthorityVariant(managedUserTestConfig(`[
		{"name":"cinema-alice-m-AAAAAAAAAAAA","password":"alice"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := manager.ApplyManagedUserAuthority(context.Background(), 2, []ManagedUserAuthorityVariant{variant}); err != nil || result.Status != ApplyStatusApplied {
		t.Fatalf("apply revision 2 = %+v, %v", result, err)
	}
	variant.Endpoints[0].Users[0].Password = "stale"
	if result, err := manager.ApplyManagedUserAuthority(context.Background(), 1, []ManagedUserAuthorityVariant{variant}); err != nil || result.Status != ApplyStatusApplied {
		t.Fatalf("apply stale revision = %+v, %v", result, err)
	}
	persisted, exists, err := manager.loadManagedUserAuthority()
	if err != nil || !exists {
		t.Fatalf("load authority = %+v, %v, exists=%v", persisted, err, exists)
	}
	if persisted.Revision != 2 || persisted.Variants[0].Endpoints[0].Users[0].Password != "alice" {
		t.Fatalf("stale revision replaced authority: %#v", persisted)
	}
	stopContext, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := manager.Stop(stopContext); err != nil {
		t.Fatal(err)
	}
}

func TestManagerKeepsControlPlaneAvailableForServiceLessAuthorityMigration(t *testing.T) {
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	legacy := []byte(`{
		"inbounds":[{"type":"anytls","tag":"tp-in-legacy","listen":"::","listen_port":443,"users":[{"name":"cinema-link-LLLLLLLLLLLL","password":"link-secret"}]}],
		"outbounds":[{"type":"direct","tag":"tp-direct"}],
		"route":{"rules":[],"final":"tp-direct"}
	}`)
	writeActiveConfig(t, manager, legacy)
	candidate := managedUserTestConfig(`[{"name":"cinema-link-l-LLLLLLLLLLLL","password":"link-secret"}]`)
	variant, err := BuildManagedUserAuthorityVariant(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.persistManagedUserAuthority(managedUserAuthorityState{
		Version: managedUserAuthorityVersion, Revision: 2,
		Variants: []ManagedUserAuthorityVariant{variant},
	}); err != nil {
		t.Fatal(err)
	}

	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	startup, err := manager.Start(runContext)
	if err != nil {
		t.Fatalf("Start() blocked Agent control-plane recovery: %v", err)
	}
	defer stopTestManager(t, manager)
	if startup.Status != StartupValidationFailed ||
		startup.Diagnostic != "persisted configuration is incompatible with managed-user authority" {
		t.Fatalf("migration startup = %+v", startup)
	}
	if processes, _ := factory.snapshot(); len(processes) != 0 {
		t.Fatalf("migration started %d unsafe legacy sing-box processes", len(processes))
	}

	digest := sha256.Sum256(candidate)
	result, err := manager.ApplyWithMode(
		context.Background(), candidate, digest[:], ApplyModeProxyNodeTopology,
	)
	if err != nil || result.Status != ApplyStatusApplied || !result.Active {
		t.Fatalf("authoritative recovery = %+v, %v", result, err)
	}
	if processes, _ := factory.snapshot(); len(processes) != 1 {
		t.Fatalf("authoritative recovery process count = %d", len(processes))
	}
}

func TestManagerQuarantinesLegacyConfigAndStampsGeneration(t *testing.T) {
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	manager.configGeneration = ProxyNodeConfigGeneration
	manager.agentVersion = "v2.0.0"
	manager.agentCommit = "new-format"
	legacy := []byte(`{"inbounds":[],"outbounds":[]}`)
	writeActiveConfig(t, manager, legacy)
	certificateDirectory := filepath.Join(manager.stateDirectory, managedSelfSignedDirectory, "legacy")
	if err := os.MkdirAll(certificateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certificateDirectory, "private-key.pem"), []byte("legacy-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	runContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	startup, err := manager.Start(runContext)
	if err != nil {
		t.Fatal(err)
	}
	defer stopTestManager(t, manager)
	if startup.Status != StartupNoConfig || startup.LegacyQuarantine == "" {
		t.Fatalf("cutover startup = %+v", startup)
	}
	if _, err := os.Stat(manager.ActiveConfigPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy active config remains live: %v", err)
	}
	quarantined, err := os.ReadFile(filepath.Join(startup.LegacyQuarantine, activeConfigFilename))
	if err != nil || string(quarantined) != string(legacy) {
		t.Fatalf("quarantined config = %q, %v", quarantined, err)
	}
	if _, err := os.Stat(filepath.Join(startup.LegacyQuarantine, "theatropolis-self-signed", "legacy", "private-key.pem")); err != nil {
		t.Fatalf("legacy generated certificate was not quarantined: %v", err)
	}
	state, exists, err := readConfigState(filepath.Join(manager.configDirectory, configStateFilename))
	if err != nil || !exists {
		t.Fatalf("read generation state = %+v, %v, %v", state, exists, err)
	}
	if state.Generation != ProxyNodeConfigGeneration || state.LastUsedBy.Version != "v2.0.0" || state.LastUsedBy.Commit != "new-format" {
		t.Fatalf("generation state = %+v", state)
	}
	processes, _ := factory.snapshot()
	if len(processes) != 0 {
		t.Fatal("legacy configuration started sing-box during cutover")
	}
}

func TestManagerBuildsExactRunCommandAndDiscardsOutput(t *testing.T) {
	manager, err := NewManager(ManagerOptions{Validator: Validator{
		BinaryPath:     "/usr/local/bin/sing-box",
		StateDirectory: t.TempDir(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	process, ok := manager.newProcess(
		manager.binaryPath,
		manager.ActiveConfigPath(),
	).(*commandProcess)
	if !ok {
		t.Fatal("default process factory returned an unexpected process type")
	}
	expected := []string{
		"/usr/local/bin/sing-box",
		"run",
		"-c",
		manager.ActiveConfigPath(),
	}
	if !reflect.DeepEqual(process.command.Args, expected) {
		t.Fatalf("sing-box command args = %#v, want %#v", process.command.Args, expected)
	}
	if process.command.Stdout != io.Discard {
		t.Fatal("managed sing-box stdout was not discarded")
	}
	if process.stderrBuf == nil {
		t.Fatal("managed sing-box stderr was not captured")
	}
	if process.command.Stderr != process.stderrBuf {
		t.Fatal("managed sing-box stderr was not routed to the capture buffer")
	}
}

func writeActiveConfig(t *testing.T, manager *Manager, config []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(manager.ActiveConfigPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.ActiveConfigPath(), config, 0o600); err != nil {
		t.Fatal(err)
	}
}

func stopTestManager(t *testing.T, manager *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Stop(ctx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestManagerAppliesConfigAtomicallyAndStopsChild(t *testing.T) {
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()

	startup, err := manager.Start(runContext)
	if err != nil {
		t.Fatal(err)
	}
	if startup.Status != StartupNoConfig {
		t.Fatalf("startup status = %q, want %q", startup.Status, StartupNoConfig)
	}

	config := []byte(`{"inbounds":[],"password":"not-logged"}`)
	digest := sha256.Sum256(config)
	result, err := manager.Apply(context.Background(), config, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ApplyStatusApplied || result.ValidationStatus != ValidationValid {
		t.Fatalf("Apply() result = %+v", result)
	}
	if result.Diagnostic != "" {
		t.Fatalf("successful Apply() diagnostic = %q", result.Diagnostic)
	}

	stored, err := os.ReadFile(manager.ActiveConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(config) {
		t.Fatalf("active config = %q, want %q", stored, config)
	}
	info, err := os.Stat(manager.ActiveConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("active config mode = %o, want 600", info.Mode().Perm())
	}
	candidates, err := filepath.Glob(filepath.Join(
		filepath.Dir(manager.ActiveConfigPath()),
		".candidate-*.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidate files were left behind: %v", candidates)
	}

	processes, _ := factory.snapshot()
	if len(processes) != 1 {
		t.Fatalf("process starts = %d, want 1", len(processes))
	}
	stopTestManager(t, manager)
	if processes[0].signalCount() == 0 {
		t.Fatal("Stop() did not signal the managed child")
	}
	if _, err := manager.Apply(context.Background(), config, digest[:]); !errors.Is(
		err,
		ErrManagerNotRunning,
	) {
		t.Fatalf("Apply() after Stop error = %v, want ErrManagerNotRunning", err)
	}
	for range manager.Events() {
	}
}

func TestManagerAppliesUsersOnlyChangeWithoutRestartingChild(t *testing.T) {
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	previous := []byte(`{"inbounds":[],"marker":"previous"}`)
	writeActiveConfig(t, manager, previous)
	manager.reconcileUsers = func(_ context.Context, oldConfig, newConfig []byte) (bool, error) {
		if string(oldConfig) != string(previous) || !strings.Contains(string(newConfig), `"candidate"`) {
			t.Fatalf("unexpected reconciliation inputs %q %q", oldConfig, newConfig)
		}
		return true, nil
	}

	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	startup, err := manager.Start(runContext)
	if err != nil || startup.Status != StartupRunning {
		t.Fatalf("Start() = %+v, %v", startup, err)
	}
	defer stopTestManager(t, manager)

	candidate := []byte(`{"inbounds":[],"marker":"candidate"}`)
	digest := sha256.Sum256(candidate)
	result, err := manager.Apply(context.Background(), candidate, digest[:])
	if err != nil || result.Status != ApplyStatusApplied || !result.Active {
		t.Fatalf("Apply() = %+v, %v", result, err)
	}
	processes, _ := factory.snapshot()
	if len(processes) != 1 || processes[0].signalCount() != 0 {
		t.Fatalf("users-only apply restarted the child: processes=%d signals=%d", len(processes), processes[0].signalCount())
	}
	stored, err := os.ReadFile(manager.ActiveConfigPath())
	if err != nil || string(stored) != string(candidate) {
		t.Fatalf("persisted candidate = %q, %v", stored, err)
	}
}

func TestManagerRestartsWhenManagedUserAPIIsUnavailable(t *testing.T) {
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	previous := []byte(`{"inbounds":[],"marker":"previous"}`)
	writeActiveConfig(t, manager, previous)
	manager.reconcileUsers = func(context.Context, []byte, []byte) (bool, error) {
		return true, errors.New("unavailable")
	}
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if startup, err := manager.Start(runContext); err != nil || startup.Status != StartupRunning {
		t.Fatalf("Start() = %+v, %v", startup, err)
	}
	defer stopTestManager(t, manager)

	candidate := []byte(`{"inbounds":[],"marker":"candidate"}`)
	digest := sha256.Sum256(candidate)
	result, err := manager.Apply(context.Background(), candidate, digest[:])
	if err != nil || result.Status != ApplyStatusApplied {
		t.Fatalf("Apply() = %+v, %v", result, err)
	}
	processes, _ := factory.snapshot()
	if len(processes) != 2 || processes[0].signalCount() == 0 {
		t.Fatalf("API failure did not use restart fallback: processes=%d first-signals=%d", len(processes), processes[0].signalCount())
	}
}

func TestManagerReportsFinalResultAfterActivationHasBegun(t *testing.T) {
	applyContext, cancelApply := context.WithCancel(context.Background())
	factory := &fakeProcessFactory{
		plans: []fakeProcessPlan{{onStart: cancelApply}},
	}
	manager := newTestManager(t, factory, nil)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if _, err := manager.Start(runContext); err != nil {
		t.Fatal(err)
	}

	config := []byte(`{"inbounds":[]}`)
	digest := sha256.Sum256(config)
	result, err := manager.Apply(applyContext, config, digest[:])
	if err != nil {
		t.Fatalf("Apply() returned early after activation began: %v", err)
	}
	if result.Status != ApplyStatusApplied {
		t.Fatalf("Apply() result = %+v", result)
	}
	stopTestManager(t, manager)
}

func TestManagerValidatesBeforeInterruptingActiveProcess(t *testing.T) {
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	oldConfig := []byte(`{"inbounds":[]}`)
	writeActiveConfig(t, manager, oldConfig)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()

	startup, err := manager.Start(runContext)
	if err != nil {
		t.Fatal(err)
	}
	if startup.Status != StartupRunning {
		t.Fatalf("startup status = %q, want %q", startup.Status, StartupRunning)
	}
	processes, _ := factory.snapshot()
	if len(processes) != 1 {
		t.Fatalf("boot process starts = %d, want 1", len(processes))
	}

	invalidConfig := []byte(`{"inbounds":`)
	digest := sha256.Sum256(invalidConfig)
	result, err := manager.Apply(context.Background(), invalidConfig, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ApplyStatusValidationFailed {
		t.Fatalf("Apply() status = %q, want validation failure", result.Status)
	}
	if processes[0].signalCount() != 0 {
		t.Fatal("invalid candidate interrupted the active process")
	}
	stored, err := os.ReadFile(manager.ActiveConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(oldConfig) {
		t.Fatal("invalid candidate changed the active configuration")
	}
	stopTestManager(t, manager)
}

func TestManagerRejectsHTTP01PortBeforeSingBoxCheckOrActivation(t *testing.T) {
	checkCalled := false
	factory := &fakeProcessFactory{}
	manager := newTestManager(
		t,
		factory,
		func(context.Context, string, string, io.Writer) error {
			checkCalled = true
			return nil
		},
	)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if _, err := manager.Start(runContext); err != nil {
		t.Fatal(err)
	}

	config := []byte(`{"inbounds":[{"type":"anytls","listen_port":80}]}`)
	digest := sha256.Sum256(config)
	result, err := manager.Apply(context.Background(), config, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ApplyStatusValidationFailed ||
		result.ValidationStatus != ValidationInvalid {
		t.Fatalf("Apply() result = %+v", result)
	}
	if !strings.Contains(result.Diagnostic, "Port 80") {
		t.Fatalf("reserved-port diagnostic = %q", result.Diagnostic)
	}
	if checkCalled {
		t.Fatal("reserved port reached sing-box check")
	}
	processes, _ := factory.snapshot()
	if len(processes) != 0 {
		t.Fatal("reserved port started sing-box")
	}
	if _, err := os.Lstat(manager.ActiveConfigPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reserved-port config was persisted: %v", err)
	}
	stopTestManager(t, manager)
}

func TestManagerDoesNotStartPersistedHTTP01PortConfig(t *testing.T) {
	checkCalled := false
	factory := &fakeProcessFactory{}
	manager := newTestManager(
		t,
		factory,
		func(context.Context, string, string, io.Writer) error {
			checkCalled = true
			return nil
		},
	)
	writeActiveConfig(
		t,
		manager,
		[]byte(`{"inbounds":[{"type":"hysteria2","listen_port":80}]}`),
	)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	startup, err := manager.Start(runContext)
	if err != nil {
		t.Fatal(err)
	}
	if startup.Status != StartupValidationFailed ||
		!strings.Contains(startup.Diagnostic, "Port 80") {
		t.Fatalf("Start() result = %+v", startup)
	}
	if checkCalled {
		t.Fatal("persisted reserved port reached sing-box check")
	}
	processes, _ := factory.snapshot()
	if len(processes) != 0 {
		t.Fatal("persisted reserved port started sing-box")
	}
	stopTestManager(t, manager)
}

func TestManagerKillsAndReapsChildThatIgnoresGracefulStop(t *testing.T) {
	factory := &fakeProcessFactory{
		plans: []fakeProcessPlan{
			{ignoreStop: true, killDelay: 3 * time.Millisecond},
			{},
		},
	}
	manager := newTestManager(t, factory, nil)
	manager.processStopTimeout = 10 * time.Millisecond
	writeActiveConfig(t, manager, []byte(`{"route":{"final":"direct"}}`))
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if _, err := manager.Start(runContext); err != nil {
		t.Fatal(err)
	}

	config := []byte(`{"route":{"final":"block"}}`)
	digest := sha256.Sum256(config)
	result, err := manager.Apply(context.Background(), config, digest[:])
	if err != nil || result.Status != ApplyStatusApplied {
		t.Fatalf("Apply() = %+v, %v", result, err)
	}
	processes, _ := factory.snapshot()
	if len(processes) != 2 {
		t.Fatalf("process starts = %d, want 2", len(processes))
	}
	processes[0].mu.Lock()
	kills := processes[0].kills
	processes[0].mu.Unlock()
	if kills == 0 {
		t.Fatal("child which ignored graceful stop was not killed")
	}
	stopTestManager(t, manager)
}

func TestManagerTracksChildWhenStartupCancellationCannotReapIt(t *testing.T) {
	runContext, cancelRun := context.WithCancel(context.Background())
	factory := &fakeProcessFactory{
		plans: []fakeProcessPlan{{
			onStart:    cancelRun,
			ignoreStop: true,
			ignoreKill: true,
		}},
	}
	manager := newTestManager(t, factory, nil)
	manager.processStopTimeout = 5 * time.Millisecond
	writeActiveConfig(t, manager, []byte(`{"inbounds":[]}`))
	if _, err := manager.Start(runContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context cancellation", err)
	}

	processes, _ := factory.snapshot()
	if len(processes) != 1 {
		t.Fatalf("process starts = %d, want 1", len(processes))
	}
	process := processes[0]
	deadline := time.Now().Add(200 * time.Millisecond)
	for {
		process.mu.Lock()
		kills := process.kills
		process.mu.Unlock()
		if kills >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("manager discarded the unreaped child instead of retrying kill")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := manager.Start(context.Background()); !errors.Is(
		err,
		ErrManagerAlreadyStarted,
	) {
		t.Fatalf("second Start() error = %v, want ErrManagerAlreadyStarted", err)
	}
	select {
	case <-manager.done:
	case <-time.After(time.Second):
		t.Fatal("manager did not finish its bounded shutdown attempt")
	}
	statuses := make(map[RuntimeStatus]int)
drainBeforeExit:
	for {
		select {
		case event := <-manager.Events():
			statuses[event.Status]++
		default:
			break drainBeforeExit
		}
	}
	if statuses[RuntimeStatusStopFailed] == 0 {
		t.Fatalf("uncertain termination was not reported: %v", statuses)
	}
	if statuses[RuntimeStatusStopped] != 0 {
		t.Fatalf("manager falsely reported the live child stopped: %v", statuses)
	}
	process.finish(errors.New("eventually reaped"))
	for event := range manager.Events() {
		statuses[event.Status]++
	}
	if statuses[RuntimeStatusStopFailed] == 0 ||
		statuses[RuntimeStatusStopped] == 0 {
		t.Fatalf("uncertain termination events = %v", statuses)
	}
	killsAfterExit := func() int {
		process.mu.Lock()
		defer process.mu.Unlock()
		return process.kills
	}()
	time.Sleep(2 * testMaxBackoff)
	process.mu.Lock()
	finalKills := process.kills
	process.mu.Unlock()
	if finalKills != killsAfterExit {
		t.Fatalf("process tracker kept killing after Wait completed: %d -> %d", killsAfterExit, finalKills)
	}
}

func TestManagerRollsBackConfigAndProcessAfterEarlyExit(t *testing.T) {
	factory := &fakeProcessFactory{
		plans: []fakeProcessPlan{
			{},
			{autoExit: true, exitErr: errors.New("candidate rejected")},
			{},
		},
	}
	manager := newTestManager(t, factory, nil)
	oldConfig := []byte(`{"inbounds":[],"password":"old-secret"}`)
	newConfig := []byte(`{"inbounds":[],"password":"new-secret"}`)
	writeActiveConfig(t, manager, oldConfig)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if startup, err := manager.Start(runContext); err != nil ||
		startup.Status != StartupRunning {
		t.Fatalf("Start() = %+v, %v", startup, err)
	}

	digest := sha256.Sum256(newConfig)
	result, err := manager.Apply(context.Background(), newConfig, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ApplyStatusActivationFailed || !result.RolledBack {
		t.Fatalf("Apply() result = %+v", result)
	}
	for _, secret := range []string{"old-secret", "new-secret"} {
		if strings.Contains(result.Diagnostic, secret) {
			t.Fatalf("activation diagnostic leaked %q: %q", secret, result.Diagnostic)
		}
	}
	stored, err := os.ReadFile(manager.ActiveConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(oldConfig) {
		t.Fatalf("rollback stored %q, want %q", stored, oldConfig)
	}
	processes, _ := factory.snapshot()
	if len(processes) != 3 {
		t.Fatalf("process starts = %d, want boot, candidate, rollback", len(processes))
	}
	if processes[0].signalCount() == 0 {
		t.Fatal("candidate activation did not stop the old process")
	}
	stopTestManager(t, manager)
}

func TestManagerReportsWhenRollbackProcessIsStillDown(t *testing.T) {
	factory := &fakeProcessFactory{
		plans: []fakeProcessPlan{
			{},
			{autoExit: true, exitErr: errors.New("candidate rejected")},
			{startErr: errors.New("old config restart failed")},
			{},
		},
	}
	manager := newTestManager(t, factory, nil)
	oldConfig := []byte(`{"route":{"final":"direct"}}`)
	newConfig := []byte(`{"route":{"final":"block"}}`)
	writeActiveConfig(t, manager, oldConfig)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if _, err := manager.Start(runContext); err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(newConfig)
	result, err := manager.Apply(context.Background(), newConfig, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ApplyStatusActivationFailed ||
		!result.RolledBack ||
		result.Active {
		t.Fatalf("Apply() result = %+v", result)
	}
	if !strings.Contains(result.Diagnostic, "has not restarted yet") {
		t.Fatalf("rollback outage was not reported: %q", result.Diagnostic)
	}
	stored, err := os.ReadFile(manager.ActiveConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(oldConfig) {
		t.Fatal("rollback restart failure did not restore the old config file")
	}

	deadline := time.Now().Add(time.Second)
	for {
		processes, _ := factory.snapshot()
		if len(processes) >= 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("manager did not retry the failed rollback process")
		}
		time.Sleep(time.Millisecond)
	}
	stopTestManager(t, manager)
}

func TestManagerRemovesFirstConfigAfterEarlyActivationFailure(t *testing.T) {
	factory := &fakeProcessFactory{
		plans: []fakeProcessPlan{
			{autoExit: true, exitErr: errors.New("candidate rejected")},
		},
	}
	manager := newTestManager(t, factory, nil)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if _, err := manager.Start(runContext); err != nil {
		t.Fatal(err)
	}

	config := []byte(`{"inbounds":[],"password":"never-active"}`)
	digest := sha256.Sum256(config)
	result, err := manager.Apply(context.Background(), config, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ApplyStatusActivationFailed || result.RolledBack {
		t.Fatalf("Apply() result = %+v", result)
	}
	if _, err := os.Lstat(manager.ActiveConfigPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed first config remained active: %v", err)
	}
	stopTestManager(t, manager)
}

func TestManagerRestartsPriorProcessWhenAtomicInstallFails(t *testing.T) {
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	oldConfig := []byte(`{"route":{"final":"direct"}}`)
	newConfig := []byte(`{"route":{"final":"block"}}`)
	writeActiveConfig(t, manager, oldConfig)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if _, err := manager.Start(runContext); err != nil {
		t.Fatal(err)
	}
	manager.replaceFile = func(string, string) error {
		return errors.New("simulated atomic replacement failure")
	}

	digest := sha256.Sum256(newConfig)
	result, err := manager.Apply(context.Background(), newConfig, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ApplyStatusInternalError || !result.RolledBack {
		t.Fatalf("Apply() result = %+v", result)
	}
	stored, err := os.ReadFile(manager.ActiveConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(oldConfig) {
		t.Fatal("failed atomic replacement changed the active config")
	}
	processes, _ := factory.snapshot()
	if len(processes) != 2 {
		t.Fatalf("process starts = %d, want boot and restored process", len(processes))
	}
	stopTestManager(t, manager)
}

func TestManagerCanRepairInvalidPersistedConfig(t *testing.T) {
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	writeActiveConfig(t, manager, []byte(`{"broken":`))
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()

	startup, err := manager.Start(runContext)
	if err != nil {
		t.Fatal(err)
	}
	if startup.Status != StartupValidationFailed ||
		startup.ValidationStatus != ValidationInvalid {
		t.Fatalf("Start() result = %+v", startup)
	}
	processes, _ := factory.snapshot()
	if len(processes) != 0 {
		t.Fatal("invalid persisted config started a process")
	}

	replacement := []byte(`{"inbounds":[]}`)
	digest := sha256.Sum256(replacement)
	result, err := manager.Apply(context.Background(), replacement, digest[:])
	if err != nil || result.Status != ApplyStatusApplied {
		t.Fatalf("repair Apply() = %+v, %v", result, err)
	}
	stopTestManager(t, manager)
}

func TestManagerRejectsUnsafePersistedConfigPaths(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *Manager)
	}{
		{
			name: "nonregular",
			setup: func(t *testing.T, manager *Manager) {
				t.Helper()
				if err := os.MkdirAll(manager.ActiveConfigPath(), 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "oversize",
			setup: func(t *testing.T, manager *Manager) {
				t.Helper()
				manager.maxConfigBytes = 32
				writeActiveConfig(t, manager, []byte(strings.Repeat("x", 33)))
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, manager *Manager) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(manager.ActiveConfigPath()), 0o700); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(t.TempDir(), "target.json")
				if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, manager.ActiveConfigPath()); err != nil {
					t.Skipf("symlink creation is unavailable: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := newTestManager(t, &fakeProcessFactory{}, nil)
			test.setup(t, manager)
			if _, err := manager.Start(context.Background()); err == nil {
				t.Fatal("Start() accepted an unsafe active configuration")
			}
		})
	}
}

func TestManagerRestartsUnexpectedExitWithBoundedBackoff(t *testing.T) {
	factory := &fakeProcessFactory{
		plans: []fakeProcessPlan{
			{
				autoExit:  true,
				exitAfter: testStartupGrace + 5*time.Millisecond,
				exitErr:   errors.New("unexpected exit"),
			},
			{
				autoExit: true,
				exitErr:  errors.New("early restart failure"),
			},
			{},
		},
	}
	manager := newTestManager(t, factory, nil)
	writeActiveConfig(t, manager, []byte(`{"inbounds":[]}`))
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if startup, err := manager.Start(runContext); err != nil ||
		startup.Status != StartupRunning {
		t.Fatalf("Start() = %+v, %v", startup, err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		processes, _ := factory.snapshot()
		if len(processes) >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("process was not restarted twice; starts = %d", len(processes))
		}
		time.Sleep(time.Millisecond)
	}
	statuses := make(map[RuntimeStatus]int)
	eventDeadline := time.NewTimer(time.Second)
	defer eventDeadline.Stop()
	for statuses[RuntimeStatusRunning] < 2 ||
		statuses[RuntimeStatusExited] == 0 ||
		statuses[RuntimeStatusRestartFailed] == 0 {
		select {
		case event := <-manager.Events():
			statuses[event.Status]++
		case <-eventDeadline.C:
			t.Fatalf("runtime events did not describe the crash loop: %v", statuses)
		}
	}
	if got := manager.restartDelay(1); got != testMinBackoff {
		t.Fatalf("first restart delay = %s, want %s", got, testMinBackoff)
	}
	if got := manager.restartDelay(2); got != 2*testMinBackoff {
		t.Fatalf("second restart delay = %s, want %s", got, 2*testMinBackoff)
	}
	for failures := 3; failures < 20; failures++ {
		if got := manager.restartDelay(failures); got > testMaxBackoff {
			t.Fatalf("restart delay %d = %s, exceeds %s", failures, got, testMaxBackoff)
		}
	}
	stopTestManager(t, manager)
}

func TestManagerRedactsAllConfigStringsFromValidationResult(t *testing.T) {
	const (
		host   = "edge.private.example"
		secret = "not-under-a-sensitive-key"
	)
	factory := &fakeProcessFactory{}
	manager := newTestManager(
		t,
		factory,
		func(_ context.Context, _, _ string, output io.Writer) error {
			_, _ = io.WriteString(output, "invalid "+host+" credential "+secret)
			return &exec.ExitError{}
		},
	)
	runContext, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	if _, err := manager.Start(runContext); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"server":"` + host + `","label":"` + secret + `"}`)
	digest := sha256.Sum256(config)
	result, err := manager.Apply(context.Background(), config, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != ApplyStatusValidationFailed {
		t.Fatalf("Apply() status = %q", result.Status)
	}
	for _, forbidden := range []string{host, secret} {
		if strings.Contains(result.Diagnostic, forbidden) {
			t.Fatalf("diagnostic leaked %q: %q", forbidden, result.Diagnostic)
		}
	}
	if !strings.Contains(result.Diagnostic, "<redacted>") {
		t.Fatalf("diagnostic contains no redaction marker: %q", result.Diagnostic)
	}
	stopTestManager(t, manager)
}
