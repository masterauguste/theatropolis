package proxynode

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

const (
	deploymentTimeout = 90 * time.Second
	pollInterval      = 250 * time.Millisecond
)

var ErrDeploymentActive = errors.New("Proxy Node fleet deployment is already active")

type DeploymentController interface {
	CanDeployProxyNodeConfiguration(agentID string) bool
	QueueDeployment(context.Context, string, string, string, []byte, time.Duration) (deployment.Record, error)
	LatestDeployment(context.Context, string) (deployment.Record, error)
}

type FleetDeploymentStatus string

const (
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
}

type Deployer struct {
	store      *Store
	resolver   AddressResolver
	controller DeploymentController
	now        func() time.Time

	mu  sync.RWMutex
	job *FleetDeployment
}

func NewDeployer(store *Store, resolver AddressResolver, controller DeploymentController) (*Deployer, error) {
	if store == nil || resolver == nil || controller == nil {
		return nil, errors.New("Proxy Node deployer dependencies are required")
	}
	return &Deployer{store: store, resolver: resolver, controller: controller, now: time.Now}, nil
}

func (d *Deployer) Preview() (CompileResult, error) {
	return Compile(d.store.Snapshot(), d.resolver)
}

func (d *Deployer) Start() (FleetDeployment, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.job != nil && (d.job.Status == FleetDeploymentQueued || d.job.Status == FleetDeploymentDeploying) {
		return cloneFleetDeployment(*d.job), ErrDeploymentActive
	}
	compiled, revision, err := d.compileCompleteFleet()
	if err != nil {
		return FleetDeployment{}, err
	}
	agents := deploymentOrder(compiled)
	for _, agentID := range agents {
		if !d.controller.CanDeployProxyNodeConfiguration(agentID) {
			return FleetDeployment{}, fmt.Errorf("Agent %q is offline or cannot deploy configuration", agentID)
		}
	}
	jobID, err := randomID("job")
	if err != nil {
		return FleetDeployment{}, err
	}
	now := d.now().UTC()
	job := &FleetDeployment{ID: jobID, Status: FleetDeploymentQueued, StartedAt: now, UpdatedAt: now}
	for _, agentID := range agents {
		job.Agents = append(job.Agents, AgentDeploymentProgress{AgentID: agentID, Status: "queued"})
	}
	d.job = job
	go d.run(jobID, compiled, agents, revision)
	return cloneFleetDeployment(*job), nil
}

func (d *Deployer) Current() (FleetDeployment, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.job == nil {
		return FleetDeployment{}, false
	}
	return cloneFleetDeployment(*d.job), true
}

func (d *Deployer) compileCompleteFleet() (CompileResult, uint64, error) {
	state := d.store.Snapshot()
	compiled, err := Compile(state, d.resolver)
	if err != nil {
		return CompileResult{}, 0, err
	}
	for _, previous := range state.ManagedAgents {
		if _, exists := compiled.Configs[previous]; exists {
			continue
		}
		compiled.Configs[previous] = emptyManagedConfig()
		compiled.AgentDepth[previous] = -1
	}
	for agentID, config := range compiled.Configs {
		if err := singbox.ValidateManagedConfig(config); err != nil {
			return CompileResult{}, 0, fmt.Errorf("compiled configuration for Agent %q violates safety policy: %w", agentID, err)
		}
	}
	return compiled, state.Revision, nil
}

func (d *Deployer) run(jobID string, compiled CompileResult, agents []string, revision uint64) {
	d.setJobStatus(jobID, FleetDeploymentDeploying, "")
	for index, agentID := range agents {
		d.updateAgent(jobID, index, "deploying", "", "")
		deploymentID, err := randomID("dep")
		if err != nil {
			d.failJob(jobID, index, err)
			return
		}
		revisionID, err := randomID("rev")
		if err != nil {
			d.failJob(jobID, index, err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), deploymentTimeout)
		record, err := d.controller.QueueDeployment(
			ctx, agentID, deploymentID, revisionID, compiled.Configs[agentID], deploymentTimeout,
		)
		if err != nil {
			cancel()
			diagnostic := err.Error()
			if record.Diagnostic != "" {
				diagnostic = record.Diagnostic
			}
			d.failJobMessage(jobID, index, diagnostic)
			return
		}
		d.updateAgent(jobID, index, "awaiting agent", record.ID, "")
		terminal, err := d.waitForDeployment(ctx, agentID, record.ID)
		cancel()
		if err != nil {
			d.failJob(jobID, index, err)
			return
		}
		if terminal.Status != deployment.StatusApplied {
			diagnostic := terminal.Diagnostic
			if diagnostic == "" {
				diagnostic = "Agent did not apply the compiled configuration"
			}
			d.failJobMessage(jobID, index, diagnostic)
			return
		}
		d.updateAgent(jobID, index, "applied", record.ID, "")
	}
	currentAgents := make([]string, 0)
	state := d.store.Snapshot()
	if state.Revision != revision {
		d.setJobStatus(jobID, FleetDeploymentFailed, "Desired Proxy Node state changed during deployment; deploy again to apply the newest revision.")
		return
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
	if err := d.store.SetManagedAgents(currentAgents); err != nil {
		d.setJobStatus(jobID, FleetDeploymentFailed, "Configurations applied, but managed-Agent state could not be recorded: "+err.Error())
		return
	}
	d.setJobStatus(jobID, FleetDeploymentApplied, "")
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
	return []byte("{\n  \"inbounds\": [],\n  \"outbounds\": [{\"type\": \"direct\", \"tag\": \"tp-direct\"}, {\"type\": \"block\", \"tag\": \"tp-reject\"}],\n  \"route\": {\"rules\": [], \"final\": \"tp-reject\"}\n}\n")
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
