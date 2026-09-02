package proxynode

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
)

func TestTopologyReconcilerAppliesSavedOfflineTopologyWhenAgentReturns(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	}); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": false},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	reconciler := NewTopologyReconciler(deployer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	reconciler.debounce = 5 * time.Millisecond
	reconciler.retry = 10 * time.Millisecond
	reconciler.backstop = time.Hour
	deployer.SetTopologyDesiredHook(reconciler.Trigger)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reconciler.Start(ctx)

	job, err := deployer.Start()
	if err != nil || job.Status != FleetDeploymentPending {
		t.Fatalf("offline Start = %#v, %v", job, err)
	}
	reconciler.Trigger()
	time.Sleep(25 * time.Millisecond)
	controller.mu.Lock()
	before := len(controller.order)
	controller.mu.Unlock()
	if before != 0 {
		t.Fatalf("offline retries deployed %d configurations", before)
	}

	controller.setDeployable("edge-a", true)
	waitForFleetDeployment(t, deployer)
	state := store.Snapshot()
	if state.Revision != state.AppliedRevision {
		t.Fatalf("reconnected topology remained pending: desired=%d applied=%d", state.Revision, state.AppliedRevision)
	}
}

func TestTopologyReconcilerDoesNotLoopOnDeterministicAgentRejection(t *testing.T) {
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

	reconciler := NewTopologyReconciler(deployer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	reconciler.debounce = 5 * time.Millisecond
	reconciler.retry = 5 * time.Millisecond
	reconciler.backstop = 15 * time.Millisecond
	deployer.SetTopologyDesiredHook(reconciler.Trigger)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reconciler.Start(ctx)
	// Deliberately mutate immediately. The startup wake may be processed after
	// this deployment fails, but it belongs to the previously applied revision
	// and must not authorize a retry of this newer deterministic rejection.

	controller.mu.Lock()
	controller.failNext = map[string]bool{"edge-a": true}
	controller.mu.Unlock()
	if _, err := deployer.MutateAndStart(func() error {
		return store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetReject})
	}); err != nil {
		t.Fatal(err)
	}
	waitForFailedFleetDeployment(t, deployer)
	controller.mu.Lock()
	afterFailure := len(controller.order)
	controller.mu.Unlock()
	time.Sleep(75 * time.Millisecond)
	controller.mu.Lock()
	afterBackstops := len(controller.order)
	controller.mu.Unlock()
	if afterBackstops != afterFailure {
		t.Fatalf("deterministic rejection retried without an event: order grew %d -> %d", afterFailure, afterBackstops)
	}

	// A reconnect/profile-ready notification is an explicit new readiness
	// event and is allowed to retry the still-saved desired revision.
	reconciler.Trigger()
	deadline := time.Now().Add(3 * time.Second)
	for {
		job, exists := deployer.Current()
		if exists && job.Status == FleetDeploymentApplied {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("explicit readiness event did not apply topology: %#v", job)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTopologyReconcilerDoesNotLoopOnRejectedRecovery(t *testing.T) {
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
	rollback, err := CompileAppliedUsers(store.Snapshot(), testResolver{"edge-a": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetReject}); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{
		store:      deployment.NewMemoryStore(),
		deployable: map[string]bool{"edge-a": true},
		failNext:   map[string]bool{"edge-a": true},
	}
	deployer, err := NewDeployer(store, testResolver{"edge-a": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	deployer.transaction = &topologyTransaction{
		ID: "interrupted-rejected", TopologyRevision: store.Snapshot().Revision,
		Phase: "deploying", StartedAt: time.Now().UTC(),
		Agents: []topologyTransactionAgent{{
			AgentID: "edge-a", RollbackConfig: rollback.Configs["edge-a"], Touched: true,
		}},
	}
	reconciler := NewTopologyReconciler(deployer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	reconciler.debounce = 5 * time.Millisecond
	reconciler.retry = 5 * time.Millisecond
	reconciler.backstop = 15 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reconciler.Start(ctx)
	waitForFailedFleetDeployment(t, deployer)
	controller.mu.Lock()
	afterFailure := len(controller.order)
	controller.mu.Unlock()
	time.Sleep(75 * time.Millisecond)
	controller.mu.Lock()
	afterBackstops := len(controller.order)
	controller.mu.Unlock()
	if afterBackstops != afterFailure {
		t.Fatalf("rejected recovery retried without an event: order grew %d -> %d", afterFailure, afterBackstops)
	}
	if !deployer.hasPendingTransaction() {
		t.Fatal("rejected recovery discarded its rollback journal")
	}

	// A meaningful reconnect/profile-ready event is allowed one new recovery
	// attempt. Once rollback succeeds, the saved desired topology is retried
	// and applied without losing the edit.
	reconciler.Trigger()
	deadline := time.Now().Add(3 * time.Second)
	for {
		state := store.Snapshot()
		if state.Revision == state.AppliedRevision && !deployer.hasPendingTransaction() {
			break
		}
		if time.Now().After(deadline) {
			job, _ := deployer.Current()
			t.Fatalf("explicit recovery event did not finish reconciliation: %#v", job)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
