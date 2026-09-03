package proxynode

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

type applyingController struct {
	mu                sync.Mutex
	store             deployment.Store
	order             []string
	configs           [][]byte
	deployable        map[string]bool
	failNext          map[string]bool
	authorities       map[string][]singbox.ManagedUserAuthorityVariant
	samples           []string
	sampleErr         map[string]error
	missingIdentities map[string]bool
}

// reconnectRaceController simulates an Agent reconnect after it reports the
// candidate applied but before the fleet-wide commit. The reconnect replay is
// recorded as a newer failed deployment; the Deployer's final barrier must
// notice it instead of committing from the stale per-call success result.
type reconnectRaceController struct {
	*applyingController
	raceMu   sync.Mutex
	armed    bool
	injected bool
}

func (c *reconnectRaceController) QueueDeployment(
	ctx context.Context,
	agentID, deploymentID, revisionID string,
	config []byte,
	timeout time.Duration,
) (deployment.Record, error) {
	record, err := c.applyingController.QueueDeployment(
		ctx, agentID, deploymentID, revisionID, config, timeout,
	)
	if err == nil {
		c.raceMu.Lock()
		if !c.injected {
			c.armed = true
		}
		c.raceMu.Unlock()
	}
	return record, err
}

func (c *reconnectRaceController) LatestDeployment(
	ctx context.Context,
	agentID string,
) (deployment.Record, error) {
	record, err := c.applyingController.LatestDeployment(ctx, agentID)
	if err != nil {
		return record, err
	}
	c.raceMu.Lock()
	inject := c.armed && !c.injected && record.Status == deployment.StatusApplied
	if inject {
		c.injected = true
		c.armed = false
	}
	c.raceMu.Unlock()
	if !inject {
		return record, nil
	}
	replay, err := deployment.New(
		"reconnect-profile-replay", agentID,
		deployment.ProxyNodeTopologyRevisionPrefix+"reconnect",
		record.ConfigJSON, time.Now().UTC(),
	)
	if err != nil {
		return deployment.Record{}, err
	}
	if err := c.store.Create(ctx, replay); err != nil {
		return deployment.Record{}, err
	}
	if _, err := c.store.Transition(ctx, replay.ID, deployment.StatusDeploying, "", time.Now().UTC()); err != nil {
		return deployment.Record{}, err
	}
	if _, err := c.store.Transition(
		ctx, replay.ID, deployment.StatusActivationFailed,
		"scripted reconnect profile rejection", time.Now().UTC(),
	); err != nil {
		return deployment.Record{}, err
	}
	return record, nil
}

func (c *applyingController) CanDeployProxyNodeConfiguration(agentID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deployable[agentID]
}

func (c *applyingController) HasAgentIdentity(agentID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.missingIdentities[agentID]
}

func (c *applyingController) CanSyncManagedUserAuthority(agentID string) bool {
	return c.CanDeployProxyNodeConfiguration(agentID)
}

func (c *applyingController) setDeployable(agentID string, deployable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deployable[agentID] = deployable
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
	// A display-name-only edit no longer changes auth_user or any generated
	// sing-box field, so it remains safe while the Agent is offline.
	if _, err := deployer.MutateAndStart(func() error {
		return store.RenameProxyNode(node.ID, "cinema-offline-label")
	}); err != nil {
		t.Fatalf("offline display-name mutation error = %v", err)
	}
	waitForFleetDeployment(t, deployer)
	if got, _ := store.ProxyNode(node.ID); got.Name != "cinema-offline-label" {
		t.Fatalf("offline display-name mutation left name %q", got.Name)
	}
	pending, err := deployer.MutateAndStart(func() error {
		return store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetReject})
	})
	if err != nil {
		t.Fatalf("offline immediate mutation error = %v", err)
	}
	if pending.Status != FleetDeploymentPending {
		t.Fatalf("offline immediate mutation status = %q", pending.Status)
	}
	if got, _ := store.ProxyNode(node.ID); got.Hops[0].Final.Type != TargetReject {
		t.Fatalf("pending desired terminal = %q", got.Hops[0].Final.Type)
	}
	if got, _ := store.AppliedProxyNode(node.ID); got.Hops[0].Final.Type != TargetDirect {
		t.Fatalf("pending applied terminal = %q", got.Hops[0].Final.Type)
	}
	if snapshot := store.Snapshot(); snapshot.Revision == snapshot.AppliedRevision {
		t.Fatal("offline topology was incorrectly marked applied")
	}

	controller.deployable["edge-a"] = true
	if _, err := deployer.ReconcilePending(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	controller.failNext = map[string]bool{"edge-a": true}
	if _, err := deployer.MutateAndStart(func() error {
		return store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetDirect})
	}); err != nil {
		t.Fatal(err)
	}
	failed := waitForFailedFleetDeployment(t, deployer)
	if !strings.Contains(failed.Error, "restored") {
		t.Fatalf("runtime failure omitted rollback status: %q", failed.Error)
	}
	if got, _ := store.ProxyNode(node.ID); got.Hops[0].Final.Type != TargetDirect {
		t.Fatalf("runtime failure lost desired terminal %q", got.Hops[0].Final.Type)
	}
	if got, _ := store.AppliedProxyNode(node.ID); got.Hops[0].Final.Type != TargetReject {
		t.Fatalf("runtime failure changed applied terminal %q", got.Hops[0].Final.Type)
	}
}

func TestTopologyCommitRejectsFailedReconnectReplay(t *testing.T) {
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
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetReject}); err != nil {
		t.Fatal(err)
	}
	base := &applyingController{
		store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true},
	}
	controller := &reconnectRaceController{applyingController: base}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	job := waitForFailedFleetDeployment(t, deployer)
	if !strings.Contains(job.Error, "scripted reconnect profile rejection") {
		t.Fatalf("fleet error = %q", job.Error)
	}
	state := store.Snapshot()
	if state.Revision == state.AppliedRevision {
		t.Fatal("fleet committed despite failed reconnect profile replay")
	}
	desired, _ := store.ProxyNode(node.ID)
	applied, _ := store.AppliedProxyNode(node.ID)
	if desired.Hops[0].Final.Type != TargetReject || applied.Hops[0].Final.Type != TargetDirect {
		t.Fatalf("desired/applied terminals = %q/%q", desired.Hops[0].Final.Type, applied.Hops[0].Final.Type)
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
	desired, _ := store.ProxyNode(node.ID)
	if desired.Entrance.Endpoint.ListenPort != 445 {
		t.Fatalf("failed sample lost desired entrance port %d", desired.Entrance.Endpoint.ListenPort)
	}
	applied, _ := store.AppliedProxyNode(node.ID)
	if applied.Entrance.Endpoint.ListenPort != 444 {
		t.Fatalf("failed sample changed applied entrance port %d", applied.Entrance.Endpoint.ListenPort)
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

func TestDeletedAgentReferenceCanBeRedirectedAndPrunedLocally(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-deleted",
		Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-deleted"}); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store:             deployment.NewMemoryStore(),
		deployable:        map[string]bool{"edge-new": true},
		missingIdentities: map[string]bool{"edge-deleted": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-new": "192.0.2.20"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.MutateAndStart(func() error {
		return store.MoveHop(node.ID, node.Entrance.HopID, "edge-new")
	}); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)

	state := store.Snapshot()
	if len(state.ProxyNodes) != 1 || len(state.AppliedProxyNodes) != 1 ||
		state.ProxyNodes[0].Hops[0].AgentID != "edge-new" ||
		state.AppliedProxyNodes[0].Hops[0].AgentID != "edge-new" {
		t.Fatalf("redirected topology was not committed: desired=%#v applied=%#v", state.ProxyNodes, state.AppliedProxyNodes)
	}
	if !slices.Equal(state.ManagedAgents, []string{"edge-new"}) {
		t.Fatalf("managed Agents = %v, want only edge-new", state.ManagedAgents)
	}
	if err := store.RequireAgentUnreferenced("edge-deleted"); err != nil {
		t.Fatalf("deleted Agent reference remains after redirect: %v", err)
	}
	controller.mu.Lock()
	order := append([]string(nil), controller.order...)
	controller.mu.Unlock()
	if !slices.Equal(order, []string{"edge-new"}) {
		t.Fatalf("deployment order = %v, deleted Agent must not receive cleanup", order)
	}
}

func TestExistingDeletedAgentReferenceRemainsEditableUntilRedirected(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-deleted",
		Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-deleted"}); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store:             deployment.NewMemoryStore(),
		deployable:        map[string]bool{},
		missingIdentities: map[string]bool{"edge-deleted": true},
	}
	deployer, err := NewDeployer(store, testResolver{}, controller)
	if err != nil {
		t.Fatal(err)
	}

	job, err := deployer.MutateAndStart(func() error {
		return store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetReject})
	})
	if err != nil {
		t.Fatalf("edit through an existing deleted Agent reference: %v", err)
	}
	if job.Status != FleetDeploymentPending {
		t.Fatalf("orphan edit status = %q, want pending until redirected or removed", job.Status)
	}
	state := store.Snapshot()
	if state.ProxyNodes[0].Hops[0].Final.Type != TargetReject {
		t.Fatalf("desired edit was not retained: %#v", state.ProxyNodes[0].Hops[0].Final)
	}
	if state.AppliedProxyNodes[0].Hops[0].Final.Type != TargetDirect {
		t.Fatalf("unreachable applied configuration was falsely changed: %#v", state.AppliedProxyNodes[0].Hops[0].Final)
	}
}

func TestDeletingProxyNodePrunesAlreadyDeletedAgentReference(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-deleted",
		Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-deleted"}); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store:             deployment.NewMemoryStore(),
		deployable:        map[string]bool{},
		missingIdentities: map[string]bool{"edge-deleted": true},
	}
	deployer, err := NewDeployer(store, testResolver{}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.MutateAndStart(func() error { return store.DeleteProxyNode(node.ID) }); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	state := store.Snapshot()
	if len(state.ProxyNodes) != 0 || len(state.AppliedProxyNodes) != 0 || len(state.ManagedAgents) != 0 {
		t.Fatalf("deleted Agent references remain: desired=%d applied=%d managed=%v", len(state.ProxyNodes), len(state.AppliedProxyNodes), state.ManagedAgents)
	}
}

// TestForcedAgentRemovalUnblocksPendingDeletion reproduces the lost-hardware
// deadlock: a wiped entrance Agent keeps its Proxy Node deletion pending
// forever, while the deletion's stale applied/managed references block the
// revocation. A forced removal of the verifiably offline identity must let
// the pending revision commit locally without a remote wipe.
func TestForcedAgentRemovalUnblocksPendingDeletion(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-lost",
		Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-lost"}); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store:      deployment.NewMemoryStore(),
		deployable: map[string]bool{"edge-lost": false},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-lost": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	reconcile := make(chan struct{}, 1)
	deployer.SetTopologyDesiredHook(func() { reconcile <- struct{}{} })

	job, err := deployer.MutateAndStart(func() error { return store.DeleteProxyNode(node.ID) })
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != FleetDeploymentPending {
		t.Fatalf("deletion job status = %q, want pending for the wiped Agent", job.Status)
	}
	// MutateAndStart wakes the reconciler once for the pending revision.
	select {
	case <-reconcile:
	default:
		t.Fatal("pending deletion did not wake the pending-topology reconciler")
	}
	if err := store.RequireAgentUnreferenced("edge-lost"); !errors.Is(err, ErrAgentReferenced) {
		t.Fatalf("ordinary removal guard error = %v, want ErrAgentReferenced", err)
	}

	// The removal callback models the control plane deleting the identity
	// record after its own offline check.
	if err := deployer.GuardAgentRemoval("edge-lost", true, func() error {
		controller.mu.Lock()
		controller.missingIdentities = map[string]bool{"edge-lost": true}
		controller.mu.Unlock()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reconcile:
	default:
		t.Fatal("forced removal did not wake the pending-topology reconciler")
	}

	if _, err := deployer.ReconcilePending(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	state := store.Snapshot()
	if state.Revision != state.AppliedRevision {
		t.Fatalf("revision %d still pending after forced removal, applied %d", state.Revision, state.AppliedRevision)
	}
	if len(state.AppliedProxyNodes) != 0 || len(state.ManagedAgents) != 0 {
		t.Fatalf("wiped Agent references remain: applied=%d managed=%v", len(state.AppliedProxyNodes), state.ManagedAgents)
	}
}

func TestOfflineEnrolledAgentStillRequiresConfirmedRetirement(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-offline",
		Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-offline"}); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store:      deployment.NewMemoryStore(),
		deployable: map[string]bool{"edge-new": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-new": "192.0.2.20"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	job, err := deployer.MutateAndStart(func() error {
		return store.MoveHop(node.ID, node.Entrance.HopID, "edge-new")
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != FleetDeploymentPending {
		t.Fatalf("offline retirement status = %q, want pending", job.Status)
	}
	state := store.Snapshot()
	if state.ProxyNodes[0].Hops[0].AgentID != "edge-new" || state.AppliedProxyNodes[0].Hops[0].AgentID != "edge-offline" ||
		!slices.Equal(state.ManagedAgents, []string{"edge-offline"}) {
		t.Fatalf("offline Agent was pruned without confirmation: desired=%#v applied=%#v managed=%v", state.ProxyNodes, state.AppliedProxyNodes, state.ManagedAgents)
	}
}

func TestTopologyMutationRejectsNewDeletedAgentReference(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-current",
		Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store:             deployment.NewMemoryStore(),
		deployable:        map[string]bool{"edge-current": true},
		missingIdentities: map[string]bool{"edge-deleted": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-current": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.MutateAndStart(func() error {
		return store.MoveHop(node.ID, node.Entrance.HopID, "edge-deleted")
	}); !errors.Is(err, ErrAgentIdentityMissing) {
		t.Fatalf("new deleted reference error = %v, want ErrAgentIdentityMissing", err)
	}
	restored, _ := store.ProxyNode(node.ID)
	if restored.Hops[0].AgentID != "edge-current" {
		t.Fatalf("invalid desired reference was not restored: %#v", restored.Hops)
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
	job, err := deployer.Start()
	if err != nil {
		t.Fatalf("Start rejected a saveable unavailable topology: %v", err)
	}
	if job.Status != FleetDeploymentPending {
		t.Fatalf("Start status = %q, want pending", job.Status)
	}
	controller.mu.Lock()
	deployed := len(controller.order)
	controller.mu.Unlock()
	if deployed != 0 {
		t.Fatalf("preflight failure partially deployed to %d Agents", deployed)
	}
}

func TestOfflineRelayEditStaysPendingWithoutPartialDeployment(t *testing.T) {
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
		store:      deployment.NewMemoryStore(),
		deployable: map[string]bool{"edge-a": true, "edge-b": false},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	controller.mu.Lock()
	controller.order = nil
	controller.mu.Unlock()

	job, err := deployer.MutateAndStart(func() error {
		_, _, err := store.AddLink(node.ID, AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-b",
			Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443),
		})
		return err
	})
	if err != nil || job.Status != FleetDeploymentPending {
		t.Fatalf("offline relay mutation = %#v, %v", job, err)
	}
	controller.mu.Lock()
	deployed := append([]string(nil), controller.order...)
	controller.mu.Unlock()
	if len(deployed) != 0 {
		t.Fatalf("offline relay mutation partially deployed: %v", deployed)
	}
	if desired, _ := store.ProxyNode(node.ID); len(desired.Links) != 1 {
		t.Fatalf("desired Links = %d", len(desired.Links))
	}
	if applied, _ := store.AppliedProxyNode(node.ID); len(applied.Links) != 0 {
		t.Fatalf("applied Links = %d", len(applied.Links))
	}

	controller.setDeployable("edge-b", true)
	if _, err := deployer.ReconcilePending(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	if applied, _ := store.AppliedProxyNode(node.ID); len(applied.Links) != 1 {
		t.Fatalf("reconciled applied Links = %d", len(applied.Links))
	}
}

func TestUnchangedOfflineAgentDoesNotBlockTopologyEdit(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	first, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	_, _ = store.CreateProxyNode(CreateProxyNodeInput{
		Name: "archive", RootAgent: "edge-b", Entrance: testTLSEndpoint(ProtocolAnyTLS, 8443),
	})
	controller := &applyingController{
		store:      deployment.NewMemoryStore(),
		deployable: map[string]bool{"edge-a": true, "edge-b": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	controller.setDeployable("edge-b", false)
	controller.mu.Lock()
	controller.order = nil
	controller.mu.Unlock()

	job, err := deployer.MutateAndStart(func() error {
		return store.SetFinal(first.ID, first.Entrance.HopID, Target{Type: TargetReject})
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status == FleetDeploymentPending {
		t.Fatalf("unrelated offline Agent blocked edit: %#v", job)
	}
	waitForFleetDeployment(t, deployer)
	controller.mu.Lock()
	order := append([]string(nil), controller.order...)
	controller.mu.Unlock()
	if !slices.Equal(order, []string{"edge-a"}) {
		t.Fatalf("changed Agent order = %v, want [edge-a]", order)
	}
}

func TestMultiplePendingTopologyEditsMergeIntoNewestDesiredRevision(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
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
	controller.setDeployable("edge-a", false)

	first, err := deployer.MutateAndStart(func() error {
		return store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetReject})
	})
	if err != nil || first.Status != FleetDeploymentPending {
		t.Fatalf("first pending edit = %#v, %v", first, err)
	}
	second, err := deployer.MutateAndStart(func() error {
		return store.UpdateEntrance(node.ID, testTLSEndpoint(ProtocolAnyTLS, 444))
	})
	if err != nil || second.Status != FleetDeploymentPending {
		t.Fatalf("second pending edit = %#v, %v", second, err)
	}
	desired, _ := store.ProxyNode(node.ID)
	if desired.Hops[0].Final.Type != TargetReject || desired.Entrance.Endpoint.ListenPort != 444 {
		t.Fatalf("merged desired topology = %#v", desired)
	}
	applied, _ := store.AppliedProxyNode(node.ID)
	if applied.Hops[0].Final.Type != TargetDirect || applied.Entrance.Endpoint.ListenPort != 443 {
		t.Fatalf("applied topology changed while pending = %#v", applied)
	}

	controller.setDeployable("edge-a", true)
	if _, err := deployer.ReconcilePending(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	applied, _ = store.AppliedProxyNode(node.ID)
	if applied.Hops[0].Final.Type != TargetReject || applied.Entrance.Endpoint.ListenPort != 444 {
		t.Fatalf("reconciled topology = %#v", applied)
	}
}

func TestRetainedAddressResolverUsesTransactionRollbackConfig(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	link, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "old", ChildAgent: "edge-b",
		Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a", "edge-b"}); err != nil {
		t.Fatal(err)
	}
	addresses := testResolver{
		"edge-a": "192.0.2.10", "edge-b": "192.0.2.11", "edge-c": "192.0.2.12",
	}
	rollback, err := CompileAppliedUsers(store.Snapshot(), addresses)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReplaceLinkDestination(
		node.ID, link.ID, "edge-c", testTLSEndpoint(ProtocolAnyTLS, 9443), Target{Type: TargetDirect},
	); err != nil {
		t.Fatal(err)
	}
	candidate, err := compileTopologyDeployment(store.Snapshot(), addresses)
	if err != nil {
		t.Fatal(err)
	}
	deployments := deployment.NewMemoryStore()
	record, err := deployment.New("candidate", "edge-a", "candidate-revision", candidate.Configs["edge-a"], time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := deployments.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := deployments.Transition(context.Background(), record.ID, deployment.StatusDeploying, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := deployments.Transition(context.Background(), record.ID, deployment.StatusApplied, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{store: deployments, deployable: map[string]bool{}}
	deployer, err := NewDeployer(store, testResolver{}, controller)
	if err != nil {
		t.Fatal(err)
	}
	deployer.transaction = &topologyTransaction{
		ID: "interrupted", TopologyRevision: store.Snapshot().Revision,
		Phase: "deploying", StartedAt: time.Now().UTC(),
		Agents: []topologyTransactionAgent{{AgentID: "edge-a", RollbackConfig: rollback.Configs["edge-a"], Touched: true}},
	}

	resolver := deployer.resolverForState(store.Snapshot())
	oldAddress, ok := resolver.AgentAddressForFamily("edge-b", pool.FamilyAuto)
	if !ok || oldAddress != "192.0.2.11" {
		t.Fatalf("old applied destination fallback = %q, %v", oldAddress, ok)
	}
	if newAddress, ok := resolver.AgentAddressForFamily("edge-c", pool.FamilyAuto); ok {
		t.Fatalf("candidate destination leaked into applied fallback: %q", newAddress)
	}
}

func TestTouchedTransactionAgentReplaysLatestConfirmedProfile(t *testing.T) {
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
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetReject}); err != nil {
		t.Fatal(err)
	}
	deployer, err := NewDeployer(
		store,
		testResolver{"edge-a": "192.0.2.10"},
		&applyingController{store: deployment.NewMemoryStore(), deployable: map[string]bool{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	deployer.transaction = &topologyTransaction{
		ID: "in-flight", TopologyRevision: store.Snapshot().Revision,
		Agents: []topologyTransactionAgent{{AgentID: "edge-a", Touched: true}},
	}
	config, managed, err := deployer.AuthoritativeAppliedProfile(context.Background(), "edge-a")
	if err != nil {
		t.Fatal(err)
	}
	if managed || config != nil {
		t.Fatalf("touched Agent provider = managed %v, config %q; want retained deployment replay", managed, config)
	}

	deployer.transaction.Agents[0].Touched = false
	config, managed, err = deployer.AuthoritativeAppliedProfile(context.Background(), "edge-a")
	if err != nil {
		t.Fatal(err)
	}
	if !managed || len(config) == 0 {
		t.Fatalf("untouched Agent provider = managed %v, config %q", managed, config)
	}
}

func TestAppliedRefreshDoesNotDriveInterruptedTopologyRecovery(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true},
	}
	deployer, err := NewDeployer(store, testResolver{}, controller)
	if err != nil {
		t.Fatal(err)
	}
	deployer.transaction = &topologyTransaction{
		ID: "interrupted", TopologyRevision: store.Snapshot().Revision,
		Agents: []topologyTransactionAgent{{
			AgentID: "edge-a", RollbackConfig: emptyManagedConfig(), Touched: true,
		}},
	}
	if _, err := deployer.StartAppliedRefresh(); !errors.Is(err, ErrDeploymentActive) {
		t.Fatalf("applied refresh error = %v, want deployment active", err)
	}
	if !deployer.hasPendingTransaction() {
		t.Fatal("applied refresh consumed the topology recovery journal")
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.order) != 0 {
		t.Fatalf("applied refresh drove rollback deployments: %v", controller.order)
	}
}

func TestInterruptedRollbackWaitsForBusyProfileThenKeepsDesiredTopology(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	rollback, err := CompileAppliedUsers(store.Snapshot(), testResolver{"edge-a": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetReject}); err != nil {
		t.Fatal(err)
	}
	deployments := deployment.NewMemoryStore()
	profile, err := deployment.New("profile-sync", "edge-a", "profile-revision", rollback.Configs["edge-a"], time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := deployments.Create(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	if _, err := deployments.Transition(context.Background(), profile.ID, deployment.StatusDeploying, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store: deployments, deployable: map[string]bool{"edge-a": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	deployer.transaction = &topologyTransaction{
		ID: "interrupted", TopologyRevision: store.Snapshot().Revision,
		Phase: "deploying", StartedAt: time.Now().UTC(),
		Agents: []topologyTransactionAgent{{AgentID: "edge-a", RollbackConfig: rollback.Configs["edge-a"], Touched: true}},
	}

	job, err := deployer.Start()
	if err != nil || job.Status != FleetDeploymentPending {
		t.Fatalf("busy recovery = %#v, %v", job, err)
	}
	controller.mu.Lock()
	if len(controller.order) != 0 {
		t.Fatalf("busy recovery queued a competing deployment: %v", controller.order)
	}
	controller.mu.Unlock()
	controller.setDeployable("edge-a", false)
	editedWhileRecovering, err := deployer.MutateAndStart(func() error {
		return store.RenameProxyNode(node.ID, "cinema newest")
	})
	if err != nil || editedWhileRecovering.Status != FleetDeploymentPending {
		t.Fatalf("edit while rollback waited offline = %#v, %v", editedWhileRecovering, err)
	}
	if desired, _ := store.ProxyNode(node.ID); desired.Name != "cinema newest" || desired.Hops[0].Final.Type != TargetReject {
		t.Fatalf("latest desired edit was not preserved: %#v", desired)
	}
	controller.setDeployable("edge-a", true)
	reconciler := NewTopologyReconciler(deployer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	reconciler.debounce = 5 * time.Millisecond
	reconciler.retry = 10 * time.Millisecond
	reconciler.backstop = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reconciler.Start(ctx)
	if _, err := deployments.Transition(context.Background(), profile.ID, deployment.StatusApplied, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		state := store.Snapshot()
		if state.Revision == state.AppliedRevision && !deployer.hasPendingTransaction() {
			break
		}
		if time.Now().After(deadline) {
			job, _ := deployer.Current()
			t.Fatalf("automatic recovery/reconcile did not finish: %#v", job)
		}
		time.Sleep(10 * time.Millisecond)
	}
	desired, _ := store.ProxyNode(node.ID)
	if desired.Hops[0].Final.Type != TargetReject {
		t.Fatalf("recovery restored desired topology to %q", desired.Hops[0].Final.Type)
	}
	applied, _ := store.AppliedProxyNode(node.ID)
	if applied.Hops[0].Final.Type != TargetReject {
		t.Fatalf("post-recovery applied topology = %q", applied.Hops[0].Final.Type)
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
	membership, err := store.AddMembership(node.ID, user.ID)
	if err != nil {
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
	if !slices.Contains(names, AuthenticatedUserLabel(membership.ID)) {
		t.Fatalf("applied-topology user authority missing Membership %q: %v", membership.ID, names)
	}
}

func TestUserAuthorityExcludesNeverQueuedPendingTopology(t *testing.T) {
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
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	if err := store.MoveHop(node.ID, node.Entrance.HopID, "edge-b"); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true, "edge-b": false},
	}
	deployer, err := NewDeployer(store, testResolver{
		"edge-a": "192.0.2.10", "edge-b": "192.0.2.11",
	}, controller)
	if err != nil {
		t.Fatal(err)
	}
	authorities, err := deployer.compileUserAuthorities(store.Snapshot(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := authorities["edge-b"]; exists {
		t.Fatal("never-queued desired entrance leaked into user authority")
	}
	variants := authorities["edge-a"]
	if len(variants) != 1 || len(variants[0].Endpoints) != 1 || len(variants[0].Endpoints[0].Users) != 1 {
		t.Fatalf("applied entrance authority = %#v", variants)
	}
}

func TestInFlightAuthorityFailsClosedAfterConcurrentRevokeAndAddressLoss(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildAgent: "edge-b",
		Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443),
	}); err != nil {
		t.Fatal(err)
	}
	candidate, err := compileTopologyDeployment(store.Snapshot(), testResolver{
		"edge-a": "192.0.2.10", "edge-b": "192.0.2.11",
	})
	if err != nil {
		t.Fatal(err)
	}
	inFlight := make(map[string]singbox.ManagedUserAuthorityVariant, len(candidate.Configs))
	for agentID, config := range candidate.Configs {
		variant, buildErr := singbox.BuildManagedUserAuthorityVariant(config)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		inFlight[agentID] = variant
	}
	if err := store.RemoveMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	deployer, err := NewDeployer(
		store,
		// edge-b disappeared after its candidate shape was staged, so a fresh
		// desired compilation cannot be used for this authority sync.
		testResolver{"edge-a": "192.0.2.10"},
		&applyingController{store: deployment.NewMemoryStore(), deployable: map[string]bool{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorities, err := deployer.compileUserAuthorities(store.Snapshot(), nil, inFlight)
	if err != nil {
		t.Fatal(err)
	}
	for agentID, variants := range authorities {
		for _, variant := range variants {
			for _, endpoint := range variant.Endpoints {
				if len(endpoint.Users) != 0 {
					t.Fatalf("Agent %q retained revoked in-flight users: %#v", agentID, variants)
				}
			}
		}
	}
}

func TestPendingProxyNodeDeletionImmediatelyRevokesAppliedEntranceAuthority(t *testing.T) {
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
		ParentHopID: node.Entrance.HopID, ChildName: "exit", ChildAgent: "edge-b",
		Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443),
	}); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store:      deployment.NewMemoryStore(),
		deployable: map[string]bool{"edge-a": true, "edge-b": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFleetDeployment(t, deployer)
	controller.setDeployable("edge-b", false)
	userSyncStarted := make(chan error, 1)
	deployer.SetUserPlaneChangedHook(func() {
		_, startErr := deployer.StartUserSync()
		userSyncStarted <- startErr
	})

	job, err := deployer.MutateAndStart(func() error { return store.DeleteProxyNode(node.ID) })
	if err != nil || job.Status != FleetDeploymentPending {
		t.Fatalf("pending delete = %#v, %v", job, err)
	}
	select {
	case err := <-userSyncStarted:
		if err != nil {
			t.Fatalf("independent user sync start = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("accepted deletion did not trigger independent user sync")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		controller.mu.Lock()
		variants, synced := controller.authorities["edge-a"]
		controller.mu.Unlock()
		if synced {
			for _, variant := range variants {
				for _, endpoint := range variant.Endpoints {
					if len(endpoint.Users) != 0 {
						t.Fatalf("deleted Node authority retained users: %#v", variants)
					}
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old applied entrance did not receive empty authority")
		}
		time.Sleep(10 * time.Millisecond)
	}
	state := store.Snapshot()
	if len(state.ProxyNodes) != 0 || len(state.AppliedProxyNodes) != 1 || state.Revision == state.AppliedRevision {
		t.Fatalf("pending deletion planes = desired:%d applied:%d revisions:%d/%d",
			len(state.ProxyNodes), len(state.AppliedProxyNodes), state.Revision, state.AppliedRevision)
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
