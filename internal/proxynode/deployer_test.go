package proxynode

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

type applyingController struct {
	mu          sync.Mutex
	store       deployment.Store
	order       []string
	configs     [][]byte
	deployable  map[string]bool
	failNext    map[string]bool
	authorities map[string][]singbox.ManagedUserAuthorityVariant
	samples     []string
	sampleErr   map[string]error
}

func (c *applyingController) CanDeployProxyNodeConfiguration(agentID string) bool {
	return c.deployable[agentID]
}

func (c *applyingController) CanSyncManagedUserAuthority(agentID string) bool {
	return c.deployable[agentID]
}

func (c *applyingController) RequestManagedUserTraffic(_ context.Context, agentID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples = append(c.samples, agentID)
	return c.sampleErr[agentID]
}

func (c *applyingController) QueueManagedUserAuthority(
	_ context.Context,
	agentID string,
	_ uint64,
	variants []singbox.ManagedUserAuthorityVariant,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authorities == nil {
		c.authorities = make(map[string][]singbox.ManagedUserAuthorityVariant)
	}
	c.authorities[agentID] = variants
	c.order = append(c.order, agentID)
	if c.failNext[agentID] {
		delete(c.failNext, agentID)
		return errors.New("scripted user-authority failure")
	}
	return nil
}

func (c *applyingController) QueueDeployment(ctx context.Context, agentID, deploymentID, revisionID string, config []byte, _ time.Duration) (deployment.Record, error) {
	record, err := deployment.New(deploymentID, agentID, revisionID, config, time.Now().UTC())
	if err != nil {
		return deployment.Record{}, err
	}
	if err := c.store.Create(ctx, record); err != nil {
		return deployment.Record{}, err
	}
	record, err = c.store.Transition(ctx, record.ID, deployment.StatusDeploying, "", time.Now().UTC())
	if err != nil {
		return deployment.Record{}, err
	}
	c.mu.Lock()
	fail := c.failNext[agentID]
	delete(c.failNext, agentID)
	c.order = append(c.order, agentID)
	c.configs = append(c.configs, append([]byte(nil), config...))
	c.mu.Unlock()
	status := deployment.StatusApplied
	diagnostic := ""
	if fail {
		status = deployment.StatusActivationFailed
		diagnostic = "scripted activation failure"
	}
	record, err = c.store.Transition(ctx, record.ID, status, diagnostic, time.Now().UTC())
	if err != nil {
		return deployment.Record{}, err
	}
	return record, nil
}

func (c *applyingController) LatestDeployment(ctx context.Context, agentID string) (deployment.Record, error) {
	return c.store.LatestForAgent(ctx, agentID)
}

func waitForFleetDeployment(t *testing.T, deployer *Deployer) FleetDeployment {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		job, exists := deployer.Current()
		if exists && job.Status == FleetDeploymentApplied {
			return job
		}
		if exists && job.Status == FleetDeploymentFailed {
			t.Fatalf("fleet deployment failed: %s", job.Error)
		}
		if time.Now().After(deadline) {
			t.Fatal("fleet deployment did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForFailedFleetDeployment(t *testing.T, deployer *Deployer) FleetDeployment {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		job, exists := deployer.Current()
		if exists && job.Status == FleetDeploymentFailed {
			return job
		}
		if exists && job.Status == FleetDeploymentApplied {
			t.Fatal("fleet deployment unexpectedly applied")
		}
		if time.Now().After(deadline) {
			t.Fatal("fleet deployment did not fail")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestImmediateTopologyMutationAppliesAndRestoresRejectedChanges(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	controller.mu.Lock()
	initialSamples := append([]string(nil), controller.samples...)
	controller.mu.Unlock()
	if len(initialSamples) != 0 {
		t.Fatalf("initial deployment sampled nonexistent applied entrances: %v", initialSamples)
	}

	if _, err := deployer.MutateAndStart(func() error {
		return store.RenameProxyNode(node.ID, "cinema-live")
	}); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	if got, _ := store.ProxyNode(node.ID); got.Name != "cinema-live" {
		t.Fatalf("applied immediate name = %q", got.Name)
	}
	controller.deployable["edge-a"] = false
	if _, err := deployer.MutateAndStart(func() error {
		return store.RenameProxyNode(node.ID, "must-not-stick")
	}); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("offline immediate mutation error = %v", err)
	}
	if got, _ := store.ProxyNode(node.ID); got.Name != "cinema-live" {
		t.Fatalf("preflight rejection left desired name %q", got.Name)
	}

	controller.deployable["edge-a"] = true
	controller.failNext = map[string]bool{"edge-a": true}
	if _, err := deployer.MutateAndStart(func() error {
		return store.RenameProxyNode(node.ID, "runtime-failure")
	}); err != nil {
		t.Fatal(err)
	}
	failed := waitForFailedFleetDeployment(t, deployer)
	if !strings.Contains(failed.Error, "restored") {
		t.Fatalf("runtime failure omitted rollback status: %q", failed.Error)
	}
	if got, _ := store.ProxyNode(node.ID); got.Name != "cinema-live" {
		t.Fatalf("runtime failure left desired name %q", got.Name)
	}
}

func TestTopologyDeploymentSamplesChangedAppliedEntrance(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)

	updated := testTLSEndpoint(ProtocolAnyTLS, 444)
	if _, err := deployer.MutateAndStart(func() error { return store.UpdateEntrance(node.ID, updated) }); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	controller.mu.Lock()
	samples := append([]string(nil), controller.samples...)
	controller.mu.Unlock()
	if !slices.Equal(samples, []string{"edge-a"}) {
		t.Fatalf("entrance samples = %v, want [edge-a]", samples)
	}
	controller.sampleErr = map[string]error{"edge-a": errors.New("scripted accounting failure")}
	if _, err := deployer.MutateAndStart(func() error {
		return store.UpdateEntrance(node.ID, testTLSEndpoint(ProtocolAnyTLS, 445))
	}); err != nil {
		t.Fatal(err)
	}
	failed := waitForFailedFleetDeployment(t, deployer)
	if !strings.Contains(failed.Error, "sample entrance traffic") {
		t.Fatalf("sample failure diagnostic = %q", failed.Error)
	}
	restored, _ := store.ProxyNode(node.ID)
	if restored.Entrance.Endpoint.ListenPort != 444 {
		t.Fatalf("failed sample left entrance port %d", restored.Entrance.Endpoint.ListenPort)
	}
}

func TestAppliedEntranceTrafficAgentsExcludeChildOnlyChanges(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-b",
		Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a", "edge-b"}); err != nil {
		t.Fatal(err)
	}
	if got := appliedEntranceTrafficAgents(store.Snapshot(), []string{"edge-b"}); len(got) != 0 {
		t.Fatalf("child-only change selected entrance sampling: %v", got)
	}
	if got := appliedEntranceTrafficAgents(store.Snapshot(), []string{"edge-a"}); !got["edge-a"] || len(got) != 1 {
		t.Fatalf("entrance change sampling set = %v", got)
	}
}

func waitForUserSync(t *testing.T, deployer *Deployer) FleetDeployment {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		job, exists := deployer.CurrentUserSync()
		if exists && job.Status == FleetDeploymentApplied {
			return job
		}
		if exists && job.Status == FleetDeploymentFailed {
			t.Fatalf("user synchronization failed: %s", job.Error)
		}
		if time.Now().After(deadline) {
			t.Fatal("user synchronization did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDeployerAppliesReceiversBeforeSendersAndRecordsManagedAgents(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootName: "Entrance", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	first, middle, err := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Middle", ChildAgent: "edge-b", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := store.AddLink(node.ID, AddLinkInput{ParentHopID: middle.ID, ChildName: "Exit", ChildAgent: "edge-c", Endpoint: testTLSEndpoint(ProtocolHysteria2, 9443)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetLinkFallback(node.ID, first.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetLinkFallback(node.ID, second.ID, true); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true, "edge-b": true, "edge-c": true}}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11", "edge-c": "192.0.2.12"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	controller.mu.Lock()
	order := append([]string(nil), controller.order...)
	controller.mu.Unlock()
	if !slices.Equal(order, []string{"edge-c", "edge-b", "edge-a"}) {
		t.Fatalf("deployment order = %v, want receiver-first", order)
	}
	if got := store.Snapshot().ManagedAgents; !slices.Equal(got, []string{"edge-a", "edge-b", "edge-c"}) {
		t.Fatalf("managed Agents = %v", got)
	}

	bob, err := store.CreateUser("bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	controller.order = nil
	controller.mu.Unlock()
	if _, err := deployer.StartUserSync(); err != nil {
		t.Fatal(err)
	}
	waitForUserSync(t, deployer)
	controller.mu.Lock()
	order = append([]string(nil), controller.order...)
	controller.mu.Unlock()
	if !slices.Equal(order, []string{"edge-a", "edge-b", "edge-c"}) {
		t.Fatalf("user-authority order = %v, want a complete fleet revision", order)
	}

	controller.mu.Lock()
	controller.order = nil
	controller.mu.Unlock()
	controller.deployable = map[string]bool{}
	if _, err := deployer.Start(); err != nil {
		t.Fatalf("unchanged offline Agents blocked no-op deployment: %v", err)
	}
	waitForFleetDeployment(t, deployer)
	controller.mu.Lock()
	deployed := len(controller.order)
	controller.mu.Unlock()
	if deployed != 0 {
		t.Fatalf("no-op deployment restarted %d Agents", deployed)
	}
}

func TestDeployerRecoversPersistedInterruptedTopologyTransaction(t *testing.T) {
	directory := t.TempDir()
	store, err := Open(filepath.Join(directory, "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil || node.ID == "" {
		t.Fatal(err)
	}
	transaction := topologyTransaction{
		ID: "job_recovery", TopologyRevision: store.Snapshot().Revision,
		Phase: "deploying", StartedAt: time.Now().UTC(),
		Agents: []topologyTransactionAgent{{
			AgentID: "edge-a", RollbackConfig: emptyManagedConfig(), Touched: true,
		}},
	}
	if err := persistTopologyTransaction(store.topologyTransactionPath(), transaction); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		job, exists := deployer.Current()
		if exists && job.Status == FleetDeploymentFailed {
			if !strings.Contains(job.Error, "all changed Agents were restored") {
				t.Fatalf("recovery job = %#v", job)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("transaction recovery did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Lstat(store.topologyTransactionPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transaction journal still exists: %v", err)
	}
}

func TestTopologyFailureRollsBackEveryTouchedAgent(t *testing.T) {
	directory := t.TempDir()
	store, err := Open(filepath.Join(directory, "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	link, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "exit", ChildAgent: "edge-b",
		Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443),
	})
	if err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true, "edge-b": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)

	if err := store.UpdateHop(node.ID, node.Entrance.HopID, "Entrance", "edge-b"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateHop(node.ID, link.ChildHopID, "exit", "edge-a"); err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	controller.order = nil
	controller.configs = nil
	controller.failNext = map[string]bool{"edge-b": true}
	controller.mu.Unlock()
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		job, exists := deployer.Current()
		if exists && job.Status == FleetDeploymentFailed {
			if !strings.Contains(job.Error, "all changed Agents were restored") {
				t.Fatalf("rollback job = %#v", job)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed topology did not finish rollback")
		}
		time.Sleep(10 * time.Millisecond)
	}
	controller.mu.Lock()
	order := append([]string(nil), controller.order...)
	controller.mu.Unlock()
	if !slices.Equal(order, []string{"edge-a", "edge-b", "edge-b", "edge-a"}) {
		t.Fatalf("failed rollout/rollback order = %v", order)
	}
	if store.Snapshot().AppliedRevision == store.Snapshot().Revision {
		t.Fatal("failed topology was recorded as applied")
	}
	if _, err := os.Lstat(store.topologyTransactionPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled-back transaction journal still exists: %v", err)
	}
}

func TestDeployerPreflightRejectsUnavailableAgentWithoutPartialDeployment(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootName: "Entrance", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-b", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)}); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true, "edge-b": false}}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err == nil {
		t.Fatal("Start accepted an unavailable Agent")
	}
	controller.mu.Lock()
	deployed := len(controller.order)
	controller.mu.Unlock()
	if deployed != 0 {
		t.Fatalf("preflight failure partially deployed to %d Agents", deployed)
	}
}

func TestUserSyncIgnoresConcurrentTopologyDrafts(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)

	// Keep an unapplied topology rename open while granting access. The user
	// job must still reconcile against the applied topology revision.
	if err := store.RenameProxyNode(node.ID, "theater"); err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.StartUserSync(); err != nil {
		t.Fatal(err)
	}
	waitForUserSync(t, deployer)

	controller.mu.Lock()
	variants := controller.authorities["edge-a"]
	controller.mu.Unlock()
	var names []string
	for _, variant := range variants {
		for _, endpoint := range variant.Endpoints {
			for _, authorityUser := range endpoint.Users {
				names = append(names, authorityUser.Username)
			}
		}
	}
	if !slices.ContainsFunc(names, func(name string) bool { return strings.Contains(name, "cinema-bob") }) {
		t.Fatalf("applied-topology user authority missing cinema-bob: %v", names)
	}
}

func TestCommittedTopologySendsFinalEmptyAuthorityToRetiredAgent(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	link, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "exit", ChildAgent: "edge-b",
		Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetLinkFallback(node.ID, link.ID, true); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true, "edge-b": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	if err := store.DeleteLink(node.ID, link.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	controller.mu.Lock()
	controller.authorities = nil
	controller.mu.Unlock()
	if _, err := deployer.StartUserSync(); err != nil {
		t.Fatal(err)
	}
	waitForUserSync(t, deployer)
	controller.mu.Lock()
	retired := controller.authorities["edge-b"]
	controller.mu.Unlock()
	if len(retired) != 1 || len(retired[0].Endpoints) != 0 {
		t.Fatalf("retired Agent authority = %#v, want one empty topology variant", retired)
	}
}
