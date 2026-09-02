package proxynode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

const (
	deploymentTimeout = 90 * time.Second
	pollInterval      = 250 * time.Millisecond
)

var ErrDeploymentActive = errors.New("Proxy Node fleet deployment is already active")

type DeploymentController interface {
	HasAgentIdentity(agentID string) bool
	CanDeployProxyNodeConfiguration(agentID string) bool
	CanSyncManagedUserAuthority(agentID string) bool
	RequestManagedUserTraffic(context.Context, string) error
	QueueDeployment(context.Context, string, string, string, []byte, time.Duration) (deployment.Record, error)
	QueueManagedUserAuthority(context.Context, string, uint64, []singbox.ManagedUserAuthorityVariant) error
	LatestDeployment(context.Context, string) (deployment.Record, error)
}

var ErrAgentIdentityMissing = errors.New("Proxy Node references a deleted Agent identity")

type FleetDeploymentStatus string

const (
	FleetDeploymentPending   FleetDeploymentStatus = "pending"
	FleetDeploymentQueued    FleetDeploymentStatus = "queued"
	FleetDeploymentDeploying FleetDeploymentStatus = "deploying"
	FleetDeploymentApplied   FleetDeploymentStatus = "applied"
	FleetDeploymentFailed    FleetDeploymentStatus = "failed"
)

type AgentDeploymentProgress struct {
	AgentID      string
	Status       string
	DeploymentID string
	Diagnostic   string
}

type FleetDeployment struct {
	ID        string
	Status    FleetDeploymentStatus
	Agents    []AgentDeploymentProgress
	Error     string
	StartedAt time.Time
	UpdatedAt time.Time

	// plane and topologyRevision are local reconciliation metadata. They are
	// intentionally not part of the Web/API contract, but let the retry loop
	// distinguish a failed desired-topology attempt from an applied-refresh
	// job that happens to share the same presentation slot.
	plane            deploymentPlane
	topologyRevision uint64
}

type Deployer struct {
	store      *Store
	resolver   AddressResolver
	controller DeploymentController
	now        func() time.Time

	mu                    sync.RWMutex
	job                   *FleetDeployment
	userJob               *FleetDeployment
	mutationReserved      bool
	onTopologyApplied     func()
	onTopologyDesired     func()
	onUserPlaneChanged    func()
	transaction           *topologyTransaction
	transactionPath       string
	inFlightAuthority     map[string]singbox.ManagedUserAuthorityVariant
	inFlightJobID         string
	pendingAuthority      map[string]singbox.ManagedUserAuthorityVariant
	pendingAuthorityEpoch uint64
}

type deploymentPlane uint8

const (
	deploymentTopology deploymentPlane = iota
	deploymentAppliedRefresh
	deploymentRecovery
)

type desiredRevision struct {
	topology uint64
	users    uint64
}

type retainedAddressResolver struct {
	primary AddressResolver
	byAgent map[string]map[pool.Family]string
}

var (
	retainedCGNATPrefix       = netip.MustParsePrefix("100.64.0.0/10")
	retainedReserved240Prefix = netip.MustParsePrefix("240.0.0.0/4")
)

func retainedAddressIsRoutable(address netip.Addr) bool {
	return address.IsGlobalUnicast() &&
		!address.IsPrivate() &&
		!retainedCGNATPrefix.Contains(address) &&
		!retainedReserved240Prefix.Contains(address)
}

func (r retainedAddressResolver) AgentAddressForFamily(agentID string, family pool.Family) (string, bool) {
	if address, ok := r.primary.AgentAddressForFamily(agentID, family); ok {
		return address, true
	}
	addresses := r.byAgent[agentID]
	if family == pool.FamilyAuto {
		if address := addresses[pool.FamilyIPv4]; address != "" {
			return address, true
		}
		if address := addresses[pool.FamilyIPv6]; address != "" {
			return address, true
		}
		return "", false
	}
	address := addresses[family]
	return address, address != ""
}

func NewDeployer(store *Store, resolver AddressResolver, controller DeploymentController) (*Deployer, error) {
	if store == nil || resolver == nil || controller == nil {
		return nil, errors.New("Proxy Node deployer dependencies are required")
	}
	transactionPath := store.topologyTransactionPath()
	transaction, err := loadTopologyTransaction(transactionPath)
	if err != nil {
		return nil, err
	}
	if transaction != nil && transaction.Phase == "committing" && store.Snapshot().AppliedRevision == transaction.TopologyRevision {
		if err := removeTopologyTransaction(transactionPath); err != nil {
			return nil, err
		}
		transaction = nil
	}
	return &Deployer{
		store: store, resolver: resolver, controller: controller, now: time.Now,
		transaction: transaction, transactionPath: transactionPath,
	}, nil
}

// resolverForState supplements the live pool with addresses retained in the
// last confirmed Agent profiles. Losing an observed address while an Agent is
// offline must not make an otherwise unrelated topology impossible to render.
// Live pool data always wins; retained addresses are only a last-known-good
// fallback and will be replaced by the next applied address refresh.
func (d *Deployer) resolverForState(state State) AddressResolver {
	d.mu.RLock()
	transaction := cloneTopologyTransactionForResolver(d.transaction)
	d.mu.RUnlock()
	return d.resolverForStateWithTransaction(state, transaction)
}

func (d *Deployer) resolverForStateLocked(state State) AddressResolver {
	return d.resolverForStateWithTransaction(state, d.transaction)
}

func (d *Deployer) resolverForStateWithTransaction(
	state State,
	transaction *topologyTransaction,
) AddressResolver {
	targets := make(map[string]map[string]string)
	for _, node := range state.AppliedProxyNodes {
		hops := make(map[string]Hop, len(node.Hops))
		for _, hop := range node.Hops {
			hops[hop.ID] = hop
		}
		for _, link := range node.Links {
			parent, parentExists := hops[link.ParentHopID]
			child, childExists := hops[link.ChildHopID]
			if !parentExists || !childExists {
				continue
			}
			if targets[parent.AgentID] == nil {
				targets[parent.AgentID] = make(map[string]string)
			}
			targets[parent.AgentID][linkOutboundTag(link.ID)] = child.AgentID
		}
	}
	rollbackConfigs := make(map[string][]byte)
	if transaction != nil {
		for _, agent := range transaction.Agents {
			rollbackConfigs[agent.AgentID] = agent.RollbackConfig
		}
	}
	fallback := make(map[string]map[pool.Family]string)
	for parentAgent, tags := range targets {
		config := rollbackConfigs[parentAgent]
		if len(config) == 0 {
			record, err := d.controller.LatestDeployment(context.Background(), parentAgent)
			if err != nil {
				continue
			}
			var exists bool
			config, _, exists = record.AppliedConfiguration()
			if !exists {
				continue
			}
		}
		var document struct {
			Outbounds []struct {
				Tag    string `json:"tag"`
				Server string `json:"server"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal(config, &document); err != nil {
			continue
		}
		for _, outbound := range document.Outbounds {
			childAgent := tags[outbound.Tag]
			address, err := netip.ParseAddr(outbound.Server)
			if childAgent == "" || err != nil || !retainedAddressIsRoutable(address) {
				continue
			}
			family := pool.FamilyIPv6
			if address.Is4() {
				family = pool.FamilyIPv4
			}
			if fallback[childAgent] == nil {
				fallback[childAgent] = make(map[pool.Family]string)
			}
			if fallback[childAgent][family] == "" {
				fallback[childAgent][family] = address.String()
			}
		}
	}
	return retainedAddressResolver{primary: d.resolver, byAgent: fallback}
}

func cloneTopologyTransactionForResolver(transaction *topologyTransaction) *topologyTransaction {
	if transaction == nil {
		return nil
	}
	clone := &topologyTransaction{Agents: make([]topologyTransactionAgent, len(transaction.Agents))}
	for index, agent := range transaction.Agents {
		clone.Agents[index] = topologyTransactionAgent{
			AgentID:        agent.AgentID,
			RollbackConfig: append([]byte(nil), agent.RollbackConfig...),
		}
	}
	return clone
}

func (d *Deployer) Preview() (CompileResult, error) {
	state := d.store.Snapshot()
	return CompileTopology(state, d.resolverForState(state))
}

// GuardAgentRemoval serializes a control-plane revocation with topology
// mutations and refuses it until every desired/applied Hop and managed
// retirement profile has stopped referencing the Agent.
func (d *Deployer) GuardAgentRemoval(agentID string, removal func() error) error {
	if removal == nil {
		return errors.New("Agent removal callback is required")
	}
	d.mu.Lock()
	if d.mutationReserved || d.transaction != nil ||
		(d.job != nil && (d.job.Status == FleetDeploymentQueued || d.job.Status == FleetDeploymentDeploying)) {
		d.mu.Unlock()
		return ErrDeploymentActive
	}
	// Use the same reservation as MutateAndStart, but release d.mu before the
	// control-plane callback performs disk I/O and pool propagation. Every
	// production topology mutation observes the reservation, so the reference
	// check remains atomic without creating a cross-component lock cycle.
	d.mutationReserved = true
	d.mu.Unlock()
	defer d.releaseMutationReservation()
	if err := d.store.RequireAgentUnreferenced(agentID); err != nil {
		return err
	}
	return removal()
}

// AuthoritativeAppliedProfile rebuilds one managed Agent from the last
// committed topology plus the latest live memberships. This is deliberately
// compiler-backed rather than deployment-record-backed: an application
// upgrade may change the generated sing-box structure, making an otherwise
// valid historical profile incompatible with the newest user authority.
func (d *Deployer) AuthoritativeAppliedProfile(
	_ context.Context,
	agentID string,
) ([]byte, bool, error) {
	// Once an Agent has confirmed part of an in-flight topology, its latest
	// deployment record is more authoritative than Store.AppliedProxyNodes
	// until the fleet-wide commit completes. Rebuilding the old Store snapshot
	// during a reconnect would silently roll this Agent back while the original
	// rollout could still commit the new topology. Let profile_sync replay the
	// latest confirmed record for touched Agents; transaction recovery retains
	// the exact pre-change RollbackConfig separately.
	if d.transactionTouchedAgent(agentID) {
		return nil, false, nil
	}
	state := d.store.Snapshot()
	if !slices.Contains(state.ManagedAgents, agentID) {
		return nil, false, nil
	}
	resolver := d.resolverForState(state)
	compiled, err := CompileAppliedUsers(state, resolver)
	if err != nil {
		return nil, true, err
	}
	config := compiled.Configs[agentID]
	if config == nil {
		config = emptyManagedConfig()
	}
	return append([]byte(nil), config...), true, nil
}

func (d *Deployer) transactionTouchedAgent(agentID string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.transaction == nil {
		return false
	}
	for _, agent := range d.transaction.Agents {
		if agent.AgentID == agentID {
			return agent.Touched
		}
	}
	return false
}

func (d *Deployer) Start() (FleetDeployment, error) {
	return d.start(deploymentTopology, nil, false)
}

// MutateAndStart serializes one complete topology edit with its fleet
// deployment. The reservation is acquired before the Store mutation so two
// browser requests cannot both create draft revisions before either starts.
// Structural synchronous failures restore the prior desired topology before
// returning. Temporary address, connection, or deployment-slot unavailability
// leaves the new desired revision pending without touching the applied plane.
// Once a fleet deployment starts, a later Agent failure rolls back only the
// fleet: the accepted desired revision remains editable and retryable.
func (d *Deployer) MutateAndStart(mutation func() error) (FleetDeployment, error) {
	if mutation == nil {
		return FleetDeployment{}, errors.New("topology mutation is required")
	}
	d.mu.Lock()
	if d.mutationReserved ||
		(d.job != nil && (d.job.Status == FleetDeploymentQueued || d.job.Status == FleetDeploymentDeploying)) {
		var current FleetDeployment
		if d.job != nil {
			current = cloneFleetDeployment(*d.job)
		}
		d.mu.Unlock()
		return current, ErrDeploymentActive
	}
	d.mutationReserved = true
	d.mu.Unlock()

	previous := d.store.Snapshot()
	if err := mutation(); err != nil {
		d.releaseMutationReservation()
		return FleetDeployment{}, err
	}
	mutated := d.store.Snapshot()
	if missing := newlyMissingDesiredAgents(previous, mutated, d.controller); len(missing) > 0 {
		currentRevision := mutated.Revision
		if restoreErr := d.store.RestoreTopology(currentRevision, previous); restoreErr != nil {
			d.releaseMutationReservation()
			return FleetDeployment{}, fmt.Errorf("%w; restore rejected topology: %v", ErrAgentIdentityMissing, restoreErr)
		}
		d.releaseMutationReservation()
		return FleetDeployment{}, fmt.Errorf("%w: %s", ErrAgentIdentityMissing, strings.Join(missing, ", "))
	}
	job, err := d.start(deploymentTopology, nil, true)
	if err == nil {
		d.mu.RLock()
		topologyHook := d.onTopologyDesired
		userHook := d.onUserPlaneChanged
		d.mu.RUnlock()
		if topologyHook != nil && job.Status == FleetDeploymentPending {
			topologyHook()
		}
		if userHook != nil && mutated.UserRevision != previous.UserRevision {
			userHook()
		}
		return job, nil
	}
	currentRevision := d.store.Snapshot().Revision
	if restoreErr := d.store.RestoreTopology(currentRevision, previous); restoreErr != nil {
		return FleetDeployment{}, fmt.Errorf("%w; restore rejected topology: %v", err, restoreErr)
	}
	d.mu.RLock()
	hook := d.onTopologyApplied
	d.mu.RUnlock()
	if hook != nil {
		hook()
	}
	return FleetDeployment{}, err
}

func (d *Deployer) releaseMutationReservation() {
	d.mu.Lock()
	d.mutationReserved = false
	d.mu.Unlock()
}

// StartUserSync immediately reconciles memberships against the last applied
// topology. It never compiles draft routing or listener state.
func (d *Deployer) StartUserSync() (FleetDeployment, error) {
	return d.startUserSync()
}

// StartAppliedRefresh re-renders the last committed topology after an address
// source changes. It remains separate from both draft topology deployment and
// revisioned end-user authority synchronization.
func (d *Deployer) StartAppliedRefresh() (FleetDeployment, error) {
	return d.start(deploymentAppliedRefresh, nil, false)
}

func (d *Deployer) SetTopologyAppliedHook(hook func()) {
	d.mu.Lock()
	d.onTopologyApplied = hook
	d.mu.Unlock()
}

// SetTopologyDesiredHook installs a lightweight wake-up callback for the
// coalesced pending-topology reconciler. It runs only after an accepted edit
// could not start because a changed Agent or address is unavailable;
// validation errors and already-started fleet jobs do not wake the retry loop.
func (d *Deployer) SetTopologyDesiredHook(hook func()) {
	d.mu.Lock()
	d.onTopologyDesired = hook
	d.mu.Unlock()
}

// SetUserPlaneChangedHook installs the independent authority reconciler wake
// up used when an accepted topology mutation also adds, removes, or rotates
// Membership authority. It is intentionally separate from topology success:
// an old applied entrance must revoke a deleted Membership even while a relay
// or retirement remains pending offline.
func (d *Deployer) SetUserPlaneChangedHook(hook func()) {
	d.mu.Lock()
	d.onUserPlaneChanged = hook
	d.mu.Unlock()
}

func (d *Deployer) start(plane deploymentPlane, rollbackState *State, reserved bool) (FleetDeployment, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mutationReserved && !reserved {
		return FleetDeployment{}, ErrDeploymentActive
	}
	if reserved {
		if !d.mutationReserved {
			return FleetDeployment{}, ErrDeploymentActive
		}
		defer func() { d.mutationReserved = false }()
	}
	if d.job != nil && (d.job.Status == FleetDeploymentQueued || d.job.Status == FleetDeploymentDeploying) {
		return cloneFleetDeployment(*d.job), ErrDeploymentActive
	}
	if d.transaction != nil {
		if plane != deploymentTopology {
			if d.job != nil {
				return cloneFleetDeployment(*d.job), ErrDeploymentActive
			}
			return FleetDeployment{}, ErrDeploymentActive
		}
		return d.startTransactionRecoveryLocked()
	}
	compiled, revision, err := d.compileCompleteFleetLocked(plane)
	if err != nil {
		var unavailable *AgentAddressUnavailableError
		if plane == deploymentTopology && errors.As(err, &unavailable) {
			return d.pendingTopologyDeploymentLocked(
				[]string{unavailable.AgentID},
				map[string]string{unavailable.AgentID: "waiting for address"},
				err.Error(),
			)
		}
		return FleetDeployment{}, err
	}
	var agents []string
	if plane == deploymentTopology {
		agents, err = d.changedTopologyAgents(compiled)
	} else {
		agents, err = d.changedAgents(compiled)
	}
	if err != nil {
		return FleetDeployment{}, err
	}
	if plane == deploymentTopology {
		waiting := make(map[string]string)
		for _, agentID := range agents {
			if !d.controller.CanDeployProxyNodeConfiguration(agentID) {
				waiting[agentID] = "waiting for Agent"
				continue
			}
			record, recordErr := d.controller.LatestDeployment(context.Background(), agentID)
			if errors.Is(recordErr, deployment.ErrNotFound) {
				continue
			}
			if recordErr != nil {
				return FleetDeployment{}, fmt.Errorf("inspect latest deployment for Agent %q: %w", agentID, recordErr)
			}
			if deploymentRecordBusy(record) {
				waiting[agentID] = "waiting for current deployment"
			}
		}
		if len(waiting) > 0 {
			waitingAgents := make([]string, 0, len(waiting))
			for _, agentID := range agents {
				if _, exists := waiting[agentID]; exists {
					waitingAgents = append(waitingAgents, agentID)
				}
			}
			return d.pendingTopologyDeploymentLocked(
				agents,
				waiting,
				"Topology saved; deployment is waiting for "+strings.Join(waitingAgents, ", "),
			)
		}
	}
	rollback := CompileResult{}
	rollbackAgents := []string(nil)
	if plane == deploymentTopology {
		rollback, err = d.compileAppliedFleet()
		if err != nil {
			return FleetDeployment{}, err
		}
		rollbackAgents = orderedAgentSubset(deploymentOrder(rollback), agents)
	}
	jobID, err := randomID("job")
	if err != nil {
		return FleetDeployment{}, err
	}
	now := d.now().UTC()
	job := &FleetDeployment{ID: jobID, Status: FleetDeploymentQueued, StartedAt: now, UpdatedAt: now}
	job.plane = plane
	job.topologyRevision = revision.topology
	for _, agentID := range agents {
		job.Agents = append(job.Agents, AgentDeploymentProgress{AgentID: agentID, Status: "queued"})
	}
	if plane == deploymentTopology && len(agents) > 0 {
		transaction := &topologyTransaction{
			ID: jobID, TopologyRevision: revision.topology, Phase: "deploying", StartedAt: now,
		}
		if rollbackState != nil {
			cloned := cloneState(*rollbackState)
			transaction.RollbackState = &cloned
		}
		for _, agentID := range rollbackAgents {
			config := rollback.Configs[agentID]
			if config == nil {
				config = emptyManagedConfig()
			}
			transaction.Agents = append(transaction.Agents, topologyTransactionAgent{
				AgentID: agentID, RollbackConfig: append([]byte(nil), config...),
			})
		}
		if err := persistTopologyTransaction(d.transactionPath, *transaction); err != nil {
			return FleetDeployment{}, fmt.Errorf("record topology transaction: %w", err)
		}
		d.transaction = transaction
	}
	if plane == deploymentTopology {
		d.inFlightAuthority = make(map[string]singbox.ManagedUserAuthorityVariant, len(compiled.Configs))
		for agentID, config := range compiled.Configs {
			variant, variantErr := singbox.BuildManagedUserAuthorityVariant(config)
			if variantErr != nil {
				if d.transaction != nil {
					_ = removeTopologyTransaction(d.transactionPath)
					d.transaction = nil
				}
				return FleetDeployment{}, fmt.Errorf("project in-flight user authority for Agent %q: %w", agentID, variantErr)
			}
			d.inFlightAuthority[agentID] = variant
		}
		d.inFlightJobID = jobID
	}
	d.job = job
	result := cloneFleetDeployment(*job)
	go d.run(jobID, compiled, rollback, agents, rollbackAgents, revision, plane, rollbackState)
	return result, nil
}

func (d *Deployer) pendingTopologyDeploymentLocked(
	agents []string,
	waiting map[string]string,
	message string,
) (FleetDeployment, error) {
	jobID, err := randomID("job")
	if err != nil {
		return FleetDeployment{}, err
	}
	now := d.now().UTC()
	job := &FleetDeployment{
		ID: jobID, Status: FleetDeploymentPending, Error: message,
		StartedAt: now, UpdatedAt: now, plane: deploymentTopology,
		topologyRevision: d.store.Snapshot().Revision,
	}
	for _, agentID := range agents {
		status := "ready"
		if pendingStatus := waiting[agentID]; pendingStatus != "" {
			status = pendingStatus
		}
		job.Agents = append(job.Agents, AgentDeploymentProgress{
			AgentID: agentID, Status: status,
		})
	}
	d.job = job
	return cloneFleetDeployment(*job), nil
}

func deploymentRecordBusy(record deployment.Record) bool {
	switch record.Status {
	case deployment.StatusQueued, deployment.StatusValidating, deployment.StatusDeploying:
		return true
	default:
		return false
	}
}

// ReconcilePending starts the newest desired topology only when it is ahead of
// the last applied revision. Control-plane readiness and address-change hooks
// call this after an Agent becomes usable; repeated calls coalesce through the
// ordinary Deployer reservation.
func (d *Deployer) ReconcilePending() (FleetDeployment, error) {
	state := d.store.Snapshot()
	if state.Revision == state.AppliedRevision {
		if current, exists := d.Current(); exists {
			return current, nil
		}
		return FleetDeployment{}, nil
	}
	return d.Start()
}

func (d *Deployer) hasPendingTransaction() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.transaction != nil
}

func (d *Deployer) startUserSync() (FleetDeployment, error) {
	d.mu.Lock()
	if d.userJob != nil && (d.userJob.Status == FleetDeploymentQueued || d.userJob.Status == FleetDeploymentDeploying) {
		job := cloneFleetDeployment(*d.userJob)
		d.mu.Unlock()
		return job, ErrDeploymentActive
	}
	inFlight := cloneAuthorityVariants(d.inFlightAuthority)
	pending := cloneAuthorityVariants(d.pendingAuthority)
	pendingEpoch := d.pendingAuthorityEpoch
	d.mu.Unlock()

	state := d.store.Snapshot()
	authorities, err := d.compileUserAuthorities(state, pending, inFlight)
	if err != nil {
		return FleetDeployment{}, err
	}
	agents := make([]string, 0, len(authorities))
	for agentID := range authorities {
		agents = append(agents, agentID)
	}
	sort.Strings(agents)
	jobID, err := randomID("users")
	if err != nil {
		return FleetDeployment{}, err
	}
	now := d.now().UTC()
	job := &FleetDeployment{ID: jobID, Status: FleetDeploymentQueued, StartedAt: now, UpdatedAt: now}
	for _, agentID := range agents {
		job.Agents = append(job.Agents, AgentDeploymentProgress{AgentID: agentID, Status: "queued"})
	}
	d.mu.Lock()
	if d.userJob != nil && (d.userJob.Status == FleetDeploymentQueued || d.userJob.Status == FleetDeploymentDeploying) {
		existing := cloneFleetDeployment(*d.userJob)
		d.mu.Unlock()
		return existing, ErrDeploymentActive
	}
	d.userJob = job
	d.mu.Unlock()
	result := cloneFleetDeployment(*job)
	go d.runUserSync(jobID, state.UserRevision, pendingEpoch, authorities, agents)
	return result, nil
}

func (d *Deployer) compileUserAuthorities(
	state State,
	pending map[string]singbox.ManagedUserAuthorityVariant,
	inFlight map[string]singbox.ManagedUserAuthorityVariant,
) (map[string][]singbox.ManagedUserAuthorityVariant, error) {
	resolver := d.resolverForState(state)
	applied, err := CompileAppliedUsers(state, resolver)
	if err != nil {
		return nil, err
	}
	for _, agentID := range state.ManagedAgents {
		if _, exists := applied.Configs[agentID]; !exists {
			applied.Configs[agentID] = emptyManagedConfig()
		}
	}
	result := make(map[string][]singbox.ManagedUserAuthorityVariant)
	addConfig := func(agentID string, config []byte) error {
		variant, buildErr := singbox.BuildManagedUserAuthorityVariant(config)
		if buildErr != nil {
			return buildErr
		}
		return addAuthorityVariant(result, agentID, variant)
	}
	for agentID, config := range applied.Configs {
		if err := addConfig(agentID, config); err != nil {
			return nil, fmt.Errorf("project applied user authority for Agent %q: %w", agentID, err)
		}
	}
	// A desired topology that has not reserved a fleet transaction is not a
	// valid authority variant: an offline/address-pending Agent may never have
	// received that listener shape. Only start() publishes a candidate into
	// inFlight after the transaction is durable; commit moves it to pending
	// until the applied projection catches up.
	if len(inFlight) > 0 {
		// Prefer a fresh projection of the already-reserved candidate so a
		// concurrent grant/revoke/reset is reflected on candidate-shaped Agents.
		// If an address vanished after partial deployment, fail closed by
		// filtering the retained shape to currently enabled Memberships. That
		// fallback can omit a concurrent grant, but can never resurrect a revoked
		// credential.
		if desired, desiredErr := compileTopologyDeployment(state, resolver); desiredErr == nil {
			for agentID, config := range desired.Configs {
				if _, reserved := inFlight[agentID]; !reserved {
					continue
				}
				if err := addConfig(agentID, config); err != nil {
					return nil, fmt.Errorf("project current in-flight user authority for Agent %q: %w", agentID, err)
				}
			}
		} else {
			for agentID, variant := range inFlight {
				variant = refreshAuthorityVariantUsers(variant, state, true)
				if err := addAuthorityVariant(result, agentID, variant); err != nil {
					return nil, fmt.Errorf("project fail-closed in-flight user authority for Agent %q: %w", agentID, err)
				}
			}
		}
	}
	for agentID, variant := range pending {
		variant = refreshAuthorityVariantUsers(variant, state, false)
		if err := addAuthorityVariant(result, agentID, variant); err != nil {
			return nil, fmt.Errorf("project pending committed user authority for Agent %q: %w", agentID, err)
		}
	}
	return result, nil
}

func refreshAuthorityVariantUsers(
	variant singbox.ManagedUserAuthorityVariant,
	state State,
	usePendingCredential bool,
) singbox.ManagedUserAuthorityVariant {
	authorized := make(map[string]string)
	for _, node := range state.ProxyNodes {
		for _, membership := range node.Memberships {
			if membership.DisabledReason != MembershipEnabled {
				continue
			}
			credential := membership.Credential
			if usePendingCredential && membership.PendingCredential != nil {
				credential = *membership.PendingCredential
			}
			authorized[AuthenticatedUserLabel(membership.ID)] = credential.Secret
		}
	}
	refreshed := singbox.ManagedUserAuthorityVariant{TopologySHA256: variant.TopologySHA256}
	for _, endpoint := range variant.Endpoints {
		item := singbox.ManagedUserAuthorityEndpoint{Path: endpoint.Path, Users: []singbox.ManagedUserAuthorityUser{}}
		for _, user := range endpoint.Users {
			secret, exists := authorized[user.Username]
			if !exists {
				continue
			}
			item.Users = append(item.Users, singbox.ManagedUserAuthorityUser{
				Username: user.Username,
				Password: secret,
			})
		}
		refreshed.Endpoints = append(refreshed.Endpoints, item)
	}
	return refreshed
}

func addAuthorityVariant(
	result map[string][]singbox.ManagedUserAuthorityVariant,
	agentID string,
	variant singbox.ManagedUserAuthorityVariant,
) error {
	for _, existing := range result[agentID] {
		if existing.TopologySHA256 != variant.TopologySHA256 {
			continue
		}
		// Applied topology is added first and remains authoritative when a draft
		// changes only credential labels without changing sing-box structure.
		// After commit, the next sync compiles the new labels as applied.
		return nil
	}
	result[agentID] = append(result[agentID], variant)
	return nil
}

func cloneAuthorityVariants(source map[string]singbox.ManagedUserAuthorityVariant) map[string]singbox.ManagedUserAuthorityVariant {
	result := make(map[string]singbox.ManagedUserAuthorityVariant, len(source))
	for agentID, variant := range source {
		result[agentID] = variant
	}
	return result
}

func (d *Deployer) runUserSync(
	jobID string,
	revision uint64,
	pendingEpoch uint64,
	authorities map[string][]singbox.ManagedUserAuthorityVariant,
	agents []string,
) {
	d.setUserJobStatus(jobID, FleetDeploymentDeploying, "")
	var failures []string
	for index, agentID := range agents {
		if !d.controller.CanSyncManagedUserAuthority(agentID) {
			d.updateUserAgent(jobID, index, "deferred", "", "Agent is offline or does not support independent user authority")
			failures = append(failures, agentID+": unavailable")
			continue
		}
		d.updateUserAgent(jobID, index, "applying", "", "")
		ctx, cancel := context.WithTimeout(context.Background(), deploymentTimeout)
		err := d.controller.QueueManagedUserAuthority(ctx, agentID, revision, authorities[agentID])
		cancel()
		if err != nil {
			d.updateUserAgent(jobID, index, "deferred", "", err.Error())
			failures = append(failures, agentID+": "+err.Error())
			continue
		}
		d.updateUserAgent(jobID, index, "applied", "", "")
	}
	if d.store.Snapshot().UserRevision != revision {
		failures = append(failures, "a newer user revision is pending")
	}
	if len(failures) > 0 {
		d.setUserJobStatus(jobID, FleetDeploymentFailed, "Some user changes are pending: "+strings.Join(failures, "; "))
		return
	}
	d.clearPendingAuthority(pendingEpoch)
	d.setUserJobStatus(jobID, FleetDeploymentApplied, "")
}

func (d *Deployer) clearPendingAuthority(epoch uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if epoch == 0 || d.pendingAuthorityEpoch != epoch {
		return
	}
	d.pendingAuthority = nil
}

func (d *Deployer) CurrentUserSync() (FleetDeployment, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.userJob == nil {
		return FleetDeployment{}, false
	}
	return cloneFleetDeployment(*d.userJob), true
}

func (d *Deployer) startTransactionRecoveryLocked() (FleetDeployment, error) {
	transaction := d.transaction
	agents := make([]string, 0, len(transaction.Agents))
	waiting := make(map[string]string)
	for _, agent := range transaction.Agents {
		if !agent.Touched {
			continue
		}
		agents = append(agents, agent.AgentID)
		if !d.controller.CanDeployProxyNodeConfiguration(agent.AgentID) {
			waiting[agent.AgentID] = "waiting for Agent"
			continue
		}
		record, err := d.controller.LatestDeployment(context.Background(), agent.AgentID)
		if errors.Is(err, deployment.ErrNotFound) {
			continue
		}
		if err != nil {
			return FleetDeployment{}, fmt.Errorf("inspect interrupted deployment for Agent %q: %w", agent.AgentID, err)
		}
		if deploymentRecordBusy(record) {
			waiting[agent.AgentID] = "waiting for current deployment"
		}
	}
	if len(waiting) > 0 {
		return d.pendingTopologyDeploymentLocked(
			agents,
			waiting,
			"Interrupted topology rollback is waiting for the affected Agents",
		)
	}
	if len(agents) == 0 {
		if err := removeTopologyTransaction(d.transactionPath); err != nil {
			return FleetDeployment{}, err
		}
		d.transaction = nil
		return d.pendingTopologyDeploymentLocked(
			nil,
			nil,
			"Interrupted topology deployment was cleared; the saved topology will be retried",
		)
	}
	now := d.now().UTC()
	job := &FleetDeployment{ID: transaction.ID, Status: FleetDeploymentQueued, StartedAt: now, UpdatedAt: now}
	job.plane = deploymentRecovery
	job.topologyRevision = transaction.TopologyRevision
	for _, agentID := range agents {
		job.Agents = append(job.Agents, AgentDeploymentProgress{AgentID: agentID, Status: "queued for recovery"})
	}
	d.job = job
	result := cloneFleetDeployment(*job)
	go d.recoverTopologyTransaction(transaction, agents)
	return result, nil
}

func (d *Deployer) compileAppliedFleet() (CompileResult, error) {
	state := d.store.Snapshot()
	compiled := CompileResult{Configs: make(map[string][]byte), AgentDepth: appliedAgentDepths(state)}
	agents := managedAndAppliedAgents(state)
	for _, agentID := range agents {
		record, recordErr := d.controller.LatestDeployment(context.Background(), agentID)
		if errors.Is(recordErr, deployment.ErrNotFound) {
			compiled.Configs[agentID] = emptyManagedConfig()
			continue
		}
		if recordErr != nil {
			return CompileResult{}, fmt.Errorf("inspect rollback deployment for Agent %q: %w", agentID, recordErr)
		}
		if applied, _, exists := record.AppliedConfiguration(); exists {
			compiled.Configs[agentID] = applied
		} else {
			compiled.Configs[agentID] = emptyManagedConfig()
		}
	}
	return compiled, nil
}

func (d *Deployer) changedTopologyAgents(candidate CompileResult) ([]string, error) {
	state := d.store.Snapshot()
	desiredAgents := topologyAgentIDs(state.ProxyNodes)
	seen := make(map[string]struct{}, len(candidate.Configs)+len(state.ManagedAgents))
	for agentID := range candidate.Configs {
		seen[agentID] = struct{}{}
	}
	for _, agentID := range managedAndAppliedAgents(state) {
		seen[agentID] = struct{}{}
	}
	agents := make([]string, 0, len(seen))
	for agentID := range seen {
		candidateConfig := candidate.Configs[agentID]
		if candidateConfig == nil {
			candidateConfig = emptyManagedConfig()
			candidate.Configs[agentID] = candidateConfig
			candidate.AgentDepth[agentID] = -1
		}
		// A server identity revoked by an older Master can remain in the
		// applied/managed snapshots even after the administrator redirects or
		// removes its final desired Hop. There is no authenticated Agent left to
		// acknowledge an empty profile, so waiting can never make progress. Once
		// the desired topology no longer references that exact identity, omit it
		// from the physical transaction; MarkTopologyApplied then atomically drops
		// its applied and managed references. An enrolled-but-offline Agent is not
		// eligible and continues to require confirmed remote cleanup.
		if _, desired := desiredAgents[agentID]; !desired && !d.controller.HasAgentIdentity(agentID) {
			continue
		}
		record, err := d.controller.LatestDeployment(context.Background(), agentID)
		if errors.Is(err, deployment.ErrNotFound) {
			// No acknowledgement exists. This is always a changed Agent,
			// including a ManagedAgents-only retirement which still needs an
			// explicit empty profile before it may be forgotten.
			agents = append(agents, agentID)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect latest deployment for Agent %q: %w", agentID, err)
		}
		previousConfig, _, exists := record.AppliedConfiguration()
		if !exists {
			agents = append(agents, agentID)
			continue
		}
		equal, err := managedTopologyConfigsEqual(candidateConfig, previousConfig)
		if err != nil {
			return nil, fmt.Errorf("compare applied topology for Agent %q: %w", agentID, err)
		}
		if !equal {
			agents = append(agents, agentID)
		}
	}
	sort.Slice(agents, func(left, right int) bool {
		leftDepth, rightDepth := candidate.AgentDepth[agents[left]], candidate.AgentDepth[agents[right]]
		if leftDepth != rightDepth {
			return leftDepth > rightDepth
		}
		return agents[left] < agents[right]
	})
	return agents, nil
}

func topologyAgentIDs(nodes []ProxyNode) map[string]struct{} {
	agents := make(map[string]struct{})
	for _, node := range nodes {
		for _, hop := range node.Hops {
			agents[hop.AgentID] = struct{}{}
		}
	}
	return agents
}

func newlyMissingDesiredAgents(before, after State, controller DeploymentController) []string {
	previous := topologyAgentReferences(before.ProxyNodes)
	missing := make([]string, 0)
	for agentID, references := range topologyAgentReferences(after.ProxyNodes) {
		if controller.HasAgentIdentity(agentID) {
			continue
		}
		newReference := false
		for reference := range references {
			if _, legacyOrphan := previous[agentID][reference]; !legacyOrphan {
				newReference = true
				break
			}
		}
		if newReference {
			missing = append(missing, agentID)
		}
	}
	sort.Strings(missing)
	return missing
}

func topologyAgentReferences(nodes []ProxyNode) map[string]map[string]struct{} {
	references := make(map[string]map[string]struct{})
	for _, node := range nodes {
		for _, hop := range node.Hops {
			if references[hop.AgentID] == nil {
				references[hop.AgentID] = make(map[string]struct{})
			}
			references[hop.AgentID][node.ID+"\x00"+hop.ID] = struct{}{}
		}
	}
	return references
}

func managedTopologyConfigsEqual(left, right []byte) (bool, error) {
	if bytes.Equal(bytes.TrimSpace(left), bytes.TrimSpace(right)) {
		return true, nil
	}
	leftVariant, err := singbox.BuildManagedUserAuthorityVariant(left)
	if err != nil {
		return false, err
	}
	rightVariant, err := singbox.BuildManagedUserAuthorityVariant(right)
	if err != nil {
		return false, err
	}
	return leftVariant.TopologySHA256 == rightVariant.TopologySHA256, nil
}

func managedAndAppliedAgents(state State) []string {
	seen := make(map[string]struct{}, len(state.ManagedAgents))
	for _, agentID := range state.ManagedAgents {
		seen[agentID] = struct{}{}
	}
	for _, node := range state.AppliedProxyNodes {
		for _, hop := range node.Hops {
			seen[hop.AgentID] = struct{}{}
		}
	}
	agents := make([]string, 0, len(seen))
	for agentID := range seen {
		agents = append(agents, agentID)
	}
	sort.Strings(agents)
	return agents
}

func appliedAgentDepths(state State) map[string]int {
	depths := make(map[string]int)
	for _, node := range state.AppliedProxyNodes {
		hops := make(map[string]Hop, len(node.Hops))
		for _, hop := range node.Hops {
			hops[hop.ID] = hop
		}
		for hopID, depth := range topologyDepths(node) {
			agentID := hops[hopID].AgentID
			if current, exists := depths[agentID]; !exists || depth > current {
				depths[agentID] = depth
			}
		}
	}
	for _, agentID := range state.ManagedAgents {
		if _, exists := depths[agentID]; !exists {
			depths[agentID] = -1
		}
	}
	return depths
}

func (d *Deployer) changedAgents(compiled CompileResult) ([]string, error) {
	ordered := deploymentOrder(compiled)
	changed := make([]string, 0, len(ordered))
	for _, agentID := range ordered {
		current, err := d.controller.LatestDeployment(context.Background(), agentID)
		if errors.Is(err, deployment.ErrNotFound) {
			changed = append(changed, agentID)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect latest deployment for Agent %q: %w", agentID, err)
		}
		digest := sha256.Sum256(compiled.Configs[agentID])
		if current.Status != deployment.StatusApplied || current.RenderedDigest() != digest {
			changed = append(changed, agentID)
		}
	}
	return changed, nil
}

func (d *Deployer) Current() (FleetDeployment, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.job == nil {
		return FleetDeployment{}, false
	}
	return cloneFleetDeployment(*d.job), true
}

func (d *Deployer) compileCompleteFleet(plane deploymentPlane) (CompileResult, desiredRevision, error) {
	state := d.store.Snapshot()
	resolver := d.resolverForState(state)
	return d.compileCompleteFleetWithResolver(state, plane, resolver)
}

func (d *Deployer) compileCompleteFleetLocked(plane deploymentPlane) (CompileResult, desiredRevision, error) {
	state := d.store.Snapshot()
	resolver := d.resolverForStateLocked(state)
	return d.compileCompleteFleetWithResolver(state, plane, resolver)
}

func (d *Deployer) compileCompleteFleetWithResolver(
	state State,
	plane deploymentPlane,
	resolver AddressResolver,
) (CompileResult, desiredRevision, error) {
	var (
		compiled CompileResult
		err      error
	)
	if plane == deploymentTopology {
		compiled, err = compileTopologyDeployment(state, resolver)
	} else {
		compiled, err = CompileAppliedUsers(state, resolver)
	}
	if err != nil {
		return CompileResult{}, desiredRevision{}, err
	}
	for _, previous := range managedAndAppliedAgents(state) {
		if _, exists := compiled.Configs[previous]; exists {
			continue
		}
		compiled.Configs[previous] = emptyManagedConfig()
		compiled.AgentDepth[previous] = -1
	}
	for agentID, config := range compiled.Configs {
		if err := singbox.ValidateManagedConfig(config); err != nil {
			return CompileResult{}, desiredRevision{}, fmt.Errorf("compiled configuration for Agent %q violates safety policy: %w", agentID, err)
		}
	}
	topologyRevision := state.Revision
	if plane == deploymentAppliedRefresh {
		// Address refresh is deliberately isolated from topology drafts. An
		// administrator may keep editing while this job re-renders only the
		// independently recorded, last-applied topology.
		topologyRevision = state.AppliedRevision
	}
	return compiled, desiredRevision{topology: topologyRevision, users: state.UserRevision}, nil
}

func (d *Deployer) run(
	jobID string,
	compiled, rollback CompileResult,
	agents, rollbackAgents []string,
	revision desiredRevision,
	plane deploymentPlane,
	rollbackState *State,
) {
	if plane == deploymentTopology {
		defer d.clearInFlightAuthority(jobID)
	}
	d.setJobStatus(jobID, FleetDeploymentDeploying, "")
	touched := make([]string, 0, len(agents))
	var refreshFailures []string
	entranceTrafficAgents := appliedEntranceTrafficAgents(d.store.Snapshot(), agents)
	for index, agentID := range agents {
		if plane == deploymentTopology && entranceTrafficAgents[agentID] {
			d.updateAgent(jobID, index, "sampling entrance traffic", "", "")
			sampleContext, cancelSample := context.WithTimeout(context.Background(), deploymentTimeout)
			sampleErr := d.controller.RequestManagedUserTraffic(sampleContext, agentID)
			cancelSample()
			if sampleErr != nil {
				d.rollbackTopology(jobID, rollback, agents, rollbackAgents, touched, rollbackState, revision.topology, fmt.Errorf("sample entrance traffic on Agent %q before topology deployment: %w", agentID, sampleErr))
				return
			}
		}
		d.updateAgent(jobID, index, "deploying", "", "")
		if plane == deploymentTopology {
			if err := d.markTransactionTouched(agentID); err != nil {
				d.rollbackTopology(jobID, rollback, agents, rollbackAgents, touched, rollbackState, revision.topology, fmt.Errorf("record Agent %q as touched: %w", agentID, err))
				return
			}
			if !slices.Contains(touched, agentID) {
				touched = append(touched, agentID)
			}
		}
		if plane == deploymentTopology && incompatibleListenerReplacement(rollback.Configs[agentID], compiled.Configs[agentID]) {
			d.updateAgent(jobID, index, "retiring old listener", "", "")
			retired, retireErr := retireConflictingListeners(rollback.Configs[agentID], compiled.Configs[agentID])
			if retireErr != nil {
				d.rollbackTopology(jobID, rollback, agents, rollbackAgents, touched, rollbackState, revision.topology, fmt.Errorf("prepare old listener retirement on Agent %q: %w", agentID, retireErr))
				return
			}
			if _, err := d.deployAgentConfig(jobID, index, agentID, retired, deploymentTopology); err != nil {
				d.rollbackTopology(jobID, rollback, agents, rollbackAgents, touched, rollbackState, revision.topology, fmt.Errorf("retire old listener on Agent %q: %w", agentID, err))
				return
			}
		}
		record, err := d.deployAgentConfig(jobID, index, agentID, compiled.Configs[agentID], plane)
		if err != nil {
			if plane == deploymentAppliedRefresh {
				refreshFailures = append(refreshFailures, agentID+": "+err.Error())
				d.updateAgent(jobID, index, "deferred", "", err.Error())
				continue
			}
			d.rollbackTopology(jobID, rollback, agents, rollbackAgents, touched, rollbackState, revision.topology, fmt.Errorf("deploy Agent %q: %w", agentID, err))
			return
		}
		if plane == deploymentAppliedRefresh && !slices.Contains(touched, agentID) {
			touched = append(touched, agentID)
		}
		d.updateAgent(jobID, index, "applied", record.ID, "")
	}
	if len(refreshFailures) > 0 {
		d.setJobStatus(jobID, FleetDeploymentFailed, "Some applied-topology refreshes are pending: "+strings.Join(refreshFailures, "; "))
		return
	}
	currentAgents := make([]string, 0)
	state := d.store.Snapshot()
	currentTopologyRevision := state.Revision
	if plane == deploymentAppliedRefresh {
		currentTopologyRevision = state.AppliedRevision
	}
	if currentTopologyRevision != revision.topology ||
		(plane == deploymentAppliedRefresh && state.UserRevision != revision.users) {
		if plane == deploymentTopology {
			d.rollbackTopology(jobID, rollback, agents, rollbackAgents, touched, rollbackState, revision.topology, errors.New("desired topology changed during deployment"))
			return
		}
		d.setJobStatus(jobID, FleetDeploymentFailed, "Desired Proxy Node state changed during deployment; the newest revision will be reconciled next.")
		return
	}
	if plane == deploymentTopology {
		for _, agentID := range agents {
			if err := d.confirmExpectedConfiguration(agentID, compiled.Configs[agentID]); err != nil {
				d.rollbackTopology(
					jobID, rollback, agents, rollbackAgents, touched, rollbackState, revision.topology,
					fmt.Errorf("confirm Agent %q before topology commit: %w", agentID, err),
				)
				return
			}
		}
	}
	seen := make(map[string]struct{})
	for _, node := range state.ProxyNodes {
		for _, hop := range node.Hops {
			if _, exists := seen[hop.AgentID]; !exists {
				seen[hop.AgentID] = struct{}{}
				currentAgents = append(currentAgents, hop.AgentID)
			}
		}
	}
	if plane == deploymentTopology {
		if len(agents) > 0 {
			if err := d.markTransactionCommitting(); err != nil {
				d.rollbackTopology(jobID, rollback, agents, rollbackAgents, touched, rollbackState, revision.topology, fmt.Errorf("record topology commit: %w", err))
				return
			}
		}
		if err := d.store.MarkTopologyApplied(revision.topology, currentAgents); err != nil {
			d.rollbackTopology(jobID, rollback, agents, rollbackAgents, touched, rollbackState, revision.topology, fmt.Errorf("record applied topology: %w", err))
			return
		}
		if len(agents) > 0 {
			if err := d.clearTransaction(); err != nil {
				d.setJobStatus(jobID, FleetDeploymentFailed, "Topology was applied, but its completed transaction journal could not be removed; restart recovery will verify it safely.")
				return
			}
		}
		d.commitInFlightAuthority(jobID)
	}
	d.setJobStatus(jobID, FleetDeploymentApplied, "")
	if plane == deploymentTopology {
		d.mu.RLock()
		hook := d.onTopologyApplied
		d.mu.RUnlock()
		if hook != nil {
			hook()
		}
	}
}

func (d *Deployer) confirmExpectedConfiguration(agentID string, expected []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), deploymentTimeout)
	defer cancel()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		record, err := d.controller.LatestDeployment(ctx, agentID)
		if err == nil {
			if deploymentRecordBusy(record) {
				// A reconnect profile replay may supersede the original
				// deployment record. Wait for the replacement session to
				// confirm the same candidate before committing fleet-wide.
			} else if record.Status != deployment.StatusApplied {
				diagnostic := strings.TrimSpace(record.Diagnostic)
				if diagnostic == "" {
					diagnostic = "latest Agent deployment is not applied"
				}
				return errors.New(diagnostic)
			} else {
				applied, _, exists := record.AppliedConfiguration()
				if !exists || !bytes.Equal(bytes.TrimSpace(applied), bytes.TrimSpace(expected)) {
					return errors.New("latest Agent deployment does not match the topology candidate")
				}
				return nil
			}
		} else if !errors.Is(err, deployment.ErrNotFound) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for Agent confirmation: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// appliedEntranceTrafficAgents selects only changed Agents that currently
// host at least one active Proxy Node entrance. Child-only Agents never carry
// end-user counters and therefore must not be sampled.
func appliedEntranceTrafficAgents(state State, changedAgents []string) map[string]bool {
	changed := make(map[string]struct{}, len(changedAgents))
	for _, agentID := range changedAgents {
		changed[agentID] = struct{}{}
	}
	liveNodes := make(map[string]ProxyNode, len(state.ProxyNodes))
	for _, node := range state.ProxyNodes {
		liveNodes[node.ID] = node
	}
	result := make(map[string]bool)
	for _, appliedNode := range state.AppliedProxyNodes {
		liveNode, exists := liveNodes[appliedNode.ID]
		if !exists || len(liveNode.Memberships) == 0 {
			continue
		}
		root := slices.IndexFunc(appliedNode.Hops, func(hop Hop) bool {
			return hop.ID == appliedNode.Entrance.HopID
		})
		if root < 0 {
			continue
		}
		agentID := appliedNode.Hops[root].AgentID
		if _, exists := changed[agentID]; exists {
			result[agentID] = true
		}
	}
	return result
}

func (d *Deployer) clearInFlightAuthority(jobID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inFlightJobID != jobID {
		return
	}
	d.inFlightAuthority = nil
	d.inFlightJobID = ""
}

func (d *Deployer) commitInFlightAuthority(jobID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inFlightJobID != jobID {
		return
	}
	d.pendingAuthority = cloneAuthorityVariants(d.inFlightAuthority)
	d.pendingAuthorityEpoch++
	d.inFlightAuthority = nil
	d.inFlightJobID = ""
}

func (d *Deployer) markTransactionTouched(agentID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.transaction == nil {
		return errors.New("topology transaction is missing")
	}
	for index := range d.transaction.Agents {
		if d.transaction.Agents[index].AgentID == agentID {
			if d.transaction.Agents[index].Touched {
				return nil
			}
			d.transaction.Agents[index].Touched = true
			return persistTopologyTransaction(d.transactionPath, *d.transaction)
		}
	}
	return errors.New("topology transaction does not contain Agent")
}

func (d *Deployer) markTransactionCommitting() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.transaction == nil {
		return errors.New("topology transaction is missing")
	}
	d.transaction.Phase = "committing"
	return persistTopologyTransaction(d.transactionPath, *d.transaction)
}

func (d *Deployer) clearTransaction() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := removeTopologyTransaction(d.transactionPath); err != nil {
		return err
	}
	d.transaction = nil
	return nil
}

func (d *Deployer) recoverTopologyTransaction(transaction *topologyTransaction, agents []string) {
	rollback := CompileResult{Configs: make(map[string][]byte, len(transaction.Agents))}
	for _, agent := range transaction.Agents {
		rollback.Configs[agent.AgentID] = append([]byte(nil), agent.RollbackConfig...)
	}
	d.setJobStatus(transaction.ID, FleetDeploymentDeploying, "")
	d.rollbackTopology(
		transaction.ID, rollback, agents, agents, agents, nil, transaction.TopologyRevision,
		errors.New("recovering an interrupted topology transaction"),
	)
}

func (d *Deployer) deployAgentConfig(
	jobID string,
	index int,
	agentID string,
	config []byte,
	plane deploymentPlane,
) (deployment.Record, error) {
	deploymentID, err := randomID("dep")
	if err != nil {
		return deployment.Record{}, err
	}
	revisionID, err := randomID("rev")
	if err != nil {
		return deployment.Record{}, err
	}
	if plane == deploymentTopology || plane == deploymentAppliedRefresh {
		revisionID = deployment.ProxyNodeTopologyRevisionPrefix + revisionID
	} else {
		revisionID = deployment.ProxyNodeUsersRevisionPrefix + revisionID
	}
	ctx, cancel := context.WithTimeout(context.Background(), deploymentTimeout)
	defer cancel()
	record, err := d.controller.QueueDeployment(
		ctx, agentID, deploymentID, revisionID, config, deploymentTimeout,
	)
	if err != nil {
		if record.Diagnostic != "" {
			return record, errors.New(record.Diagnostic)
		}
		return record, err
	}
	d.updateAgent(jobID, index, "awaiting agent", record.ID, "")
	terminal, err := d.waitForDeployment(ctx, agentID, record.ID)
	if err != nil {
		return terminal, err
	}
	if terminal.Status != deployment.StatusApplied {
		diagnostic := terminal.Diagnostic
		if diagnostic == "" {
			diagnostic = "Agent did not apply the compiled configuration"
		}
		return terminal, errors.New(diagnostic)
	}
	return terminal, nil
}

func (d *Deployer) rollbackTopology(
	jobID string,
	rollback CompileResult,
	jobAgents, rollbackAgents, touched []string,
	rollbackState *State,
	expectedRevision uint64,
	cause error,
) {
	touchedSet := make(map[string]struct{}, len(touched))
	for _, agentID := range touched {
		touchedSet[agentID] = struct{}{}
	}
	var failures []string
	jobIndexes := make(map[string]int, len(jobAgents))
	for index, agentID := range jobAgents {
		jobIndexes[agentID] = index
	}
	for _, agentID := range rollbackAgents {
		if _, exists := touchedSet[agentID]; !exists {
			continue
		}
		index := jobIndexes[agentID]
		d.updateAgent(jobID, index, "rolling back", "", "")
		config := rollback.Configs[agentID]
		if config == nil {
			config = emptyManagedConfig()
		}
		if _, err := d.deployAgentConfig(jobID, index, agentID, config, deploymentTopology); err != nil {
			failures = append(failures, agentID+": "+err.Error())
			continue
		}
		d.updateAgent(jobID, index, "rolled back", "", "")
	}
	message := cause.Error()
	if rollbackState != nil {
		if err := d.store.RestoreTopology(expectedRevision, *rollbackState); err != nil {
			failures = append(failures, "restore topology state: "+err.Error())
		} else {
			d.mu.RLock()
			hook := d.onTopologyApplied
			d.mu.RUnlock()
			if hook != nil {
				hook()
			}
		}
	}
	if len(failures) > 0 {
		message += "; rollback incomplete: " + strings.Join(failures, "; ")
	} else {
		if len(touched) > 0 {
			message += "; all changed Agents were restored"
		} else if rollbackState != nil {
			message += "; candidate topology was restored"
		}
		d.mu.RLock()
		hasTransaction := d.transaction != nil
		d.mu.RUnlock()
		if hasTransaction {
			if err := d.clearTransaction(); err != nil {
				message += "; restored transaction journal could not be removed: " + err.Error()
			}
		}
	}
	d.setJobStatus(jobID, FleetDeploymentFailed, message)
}

func orderedAgentSubset(order, members []string) []string {
	wanted := make(map[string]struct{}, len(members))
	for _, agentID := range members {
		wanted[agentID] = struct{}{}
	}
	result := make([]string, 0, len(members))
	for _, agentID := range order {
		if _, exists := wanted[agentID]; !exists {
			continue
		}
		result = append(result, agentID)
		delete(wanted, agentID)
	}
	// Defensive deterministic fallback for a newly managed Agent absent from
	// the previous topology compiler output.
	missing := make([]string, 0, len(wanted))
	for agentID := range wanted {
		missing = append(missing, agentID)
	}
	sort.Strings(missing)
	return append(result, missing...)
}

func incompatibleListenerReplacement(previous, candidate []byte) bool {
	type inbound struct {
		Type       string `json:"type"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
	}
	type document struct {
		Inbounds []inbound `json:"inbounds"`
	}
	var oldDocument, newDocument document
	if json.Unmarshal(previous, &oldDocument) != nil || json.Unmarshal(candidate, &newDocument) != nil {
		return false
	}
	oldClaims := make(map[string]string)
	for _, item := range oldDocument.Inbounds {
		for _, network := range listenerNetworks(item.Type) {
			oldClaims[network+"/"+item.Listen+":"+fmt.Sprint(item.ListenPort)] = item.Type
		}
	}
	for _, item := range newDocument.Inbounds {
		for _, network := range listenerNetworks(item.Type) {
			if oldType := oldClaims[network+"/"+item.Listen+":"+fmt.Sprint(item.ListenPort)]; oldType != "" && oldType != item.Type {
				return true
			}
		}
	}
	return false
}

func retireConflictingListeners(previous, candidate []byte) ([]byte, error) {
	type inbound struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
	}
	var oldDocument, newDocument map[string]any
	if err := json.Unmarshal(previous, &oldDocument); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(candidate, &newDocument); err != nil {
		return nil, err
	}
	decodeInbounds := func(document map[string]any) ([]inbound, error) {
		encoded, err := json.Marshal(document["inbounds"])
		if err != nil {
			return nil, err
		}
		var result []inbound
		if err := json.Unmarshal(encoded, &result); err != nil {
			return nil, err
		}
		return result, nil
	}
	oldInbounds, err := decodeInbounds(oldDocument)
	if err != nil {
		return nil, err
	}
	newInbounds, err := decodeInbounds(newDocument)
	if err != nil {
		return nil, err
	}
	newClaims := make(map[string]string)
	for _, item := range newInbounds {
		for _, network := range listenerNetworks(item.Type) {
			newClaims[network+"/"+item.Listen+":"+fmt.Sprint(item.ListenPort)] = item.Type
		}
	}
	removeTags := make(map[string]struct{})
	for _, item := range oldInbounds {
		for _, network := range listenerNetworks(item.Type) {
			claim := network + "/" + item.Listen + ":" + fmt.Sprint(item.ListenPort)
			if newType := newClaims[claim]; newType != "" && newType != item.Type {
				removeTags[item.Tag] = struct{}{}
			}
		}
	}
	rawInbounds, _ := oldDocument["inbounds"].([]any)
	keptInbounds := make([]any, 0, len(rawInbounds))
	for _, raw := range rawInbounds {
		item, _ := raw.(map[string]any)
		tag, _ := item["tag"].(string)
		if _, remove := removeTags[tag]; !remove {
			keptInbounds = append(keptInbounds, raw)
		}
	}
	oldDocument["inbounds"] = keptInbounds
	if route, _ := oldDocument["route"].(map[string]any); route != nil {
		rules, _ := route["rules"].([]any)
		keptRules := make([]any, 0, len(rules))
		for _, raw := range rules {
			rule, _ := raw.(map[string]any)
			rawTags, scoped := rule["inbound"].([]any)
			if !scoped {
				keptRules = append(keptRules, raw)
				continue
			}
			keptTags := make([]any, 0, len(rawTags))
			for _, rawTag := range rawTags {
				tag, _ := rawTag.(string)
				if _, remove := removeTags[tag]; !remove {
					keptTags = append(keptTags, rawTag)
				}
			}
			if len(keptTags) > 0 {
				rule["inbound"] = keptTags
				keptRules = append(keptRules, raw)
			}
		}
		route["rules"] = keptRules
	}
	services, _ := oldDocument["services"].([]any)
	keptServices := make([]any, 0, len(services))
	for _, raw := range services {
		service, _ := raw.(map[string]any)
		servers, managed := service["servers"].(map[string]any)
		if !managed {
			keptServices = append(keptServices, raw)
			continue
		}
		for path, rawTag := range servers {
			tag, _ := rawTag.(string)
			if _, remove := removeTags[tag]; remove {
				delete(servers, path)
			}
		}
		if len(servers) > 0 {
			keptServices = append(keptServices, raw)
		}
	}
	if len(keptServices) == 0 {
		delete(oldDocument, "services")
	} else {
		oldDocument["services"] = keptServices
	}
	encoded, err := json.MarshalIndent(oldDocument, "", "  ")
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if err := singbox.ValidateManagedConfig(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func listenerNetworks(protocol string) []string {
	switch Protocol(protocol) {
	case ProtocolShadowsocks:
		return []string{"tcp", "udp"}
	case ProtocolHysteria2:
		return []string{"udp"}
	case ProtocolAnyTLS:
		return []string{"tcp"}
	default:
		return nil
	}
}

func (d *Deployer) waitForDeployment(ctx context.Context, agentID, deploymentID string) (deployment.Record, error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		record, err := d.controller.LatestDeployment(ctx, agentID)
		if err == nil && record.ID == deploymentID && isTerminalDeployment(record.Status) {
			return record, nil
		}
		if err != nil && !errors.Is(err, deployment.ErrNotFound) {
			return deployment.Record{}, err
		}
		select {
		case <-ctx.Done():
			return deployment.Record{}, fmt.Errorf("timed out waiting for Agent %q deployment", agentID)
		case <-ticker.C:
		}
	}
}

func isTerminalDeployment(status deployment.Status) bool {
	switch status {
	case deployment.StatusApplied, deployment.StatusValidationFailed,
		deployment.StatusActivationFailed, deployment.StatusDeliveryFailed,
		deployment.StatusInternalError, deployment.StatusRuntimeFailed:
		return true
	default:
		return false
	}
}

func deploymentOrder(compiled CompileResult) []string {
	agents := make([]string, 0, len(compiled.Configs))
	for agentID := range compiled.Configs {
		agents = append(agents, agentID)
	}
	sort.Slice(agents, func(left, right int) bool {
		leftDepth := compiled.AgentDepth[agents[left]]
		rightDepth := compiled.AgentDepth[agents[right]]
		if leftDepth == rightDepth {
			return agents[left] < agents[right]
		}
		return leftDepth > rightDepth
	})
	return agents
}

func emptyManagedConfig() []byte {
	return singbox.DisabledManagedConfig()
}

func (d *Deployer) setJobStatus(jobID string, status FleetDeploymentStatus, message string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.job == nil || d.job.ID != jobID {
		return
	}
	d.job.Status = status
	d.job.Error = message
	d.job.UpdatedAt = d.now().UTC()
}

func (d *Deployer) updateAgent(jobID string, index int, status, deploymentID, diagnostic string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.job == nil || d.job.ID != jobID || index < 0 || index >= len(d.job.Agents) {
		return
	}
	d.job.Agents[index].Status = status
	d.job.Agents[index].DeploymentID = deploymentID
	d.job.Agents[index].Diagnostic = diagnostic
	d.job.UpdatedAt = d.now().UTC()
}

func (d *Deployer) setUserJobStatus(jobID string, status FleetDeploymentStatus, message string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.userJob == nil || d.userJob.ID != jobID {
		return
	}
	d.userJob.Status = status
	d.userJob.Error = message
	d.userJob.UpdatedAt = d.now().UTC()
}

func (d *Deployer) updateUserAgent(jobID string, index int, status, deploymentID, diagnostic string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.userJob == nil || d.userJob.ID != jobID || index < 0 || index >= len(d.userJob.Agents) {
		return
	}
	d.userJob.Agents[index].Status = status
	d.userJob.Agents[index].DeploymentID = deploymentID
	d.userJob.Agents[index].Diagnostic = diagnostic
	d.userJob.UpdatedAt = d.now().UTC()
}

func (d *Deployer) failJob(jobID string, index int, err error) {
	d.failJobMessage(jobID, index, err.Error())
}

func (d *Deployer) failJobMessage(jobID string, index int, message string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.job == nil || d.job.ID != jobID {
		return
	}
	if index >= 0 && index < len(d.job.Agents) {
		d.job.Agents[index].Status = "failed"
		d.job.Agents[index].Diagnostic = message
	}
	d.job.Status = FleetDeploymentFailed
	d.job.Error = message
	d.job.UpdatedAt = d.now().UTC()
}

func cloneFleetDeployment(job FleetDeployment) FleetDeployment {
	job.Agents = append([]AgentDeploymentProgress(nil), job.Agents...)
	return job
}
