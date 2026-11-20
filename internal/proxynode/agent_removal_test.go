package proxynode

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequireAgentUnreferencedChecksDesiredAppliedAndManagedTopology(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.RequireAgentUnreferenced("not valid"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid Agent ID error = %v, want ErrInvalidState", err)
	}
	if err := store.RequireAgentUnreferenced("edge-unused"); err != nil {
		t.Fatalf("unused Agent error = %v", err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertReferenced := func(agentID string) {
		t.Helper()
		err := store.RequireAgentUnreferenced(agentID)
		if !errors.Is(err, ErrAgentReferenced) || !errors.Is(err, ErrConflict) {
			t.Fatalf("Agent %q error = %v, want ErrAgentReferenced and ErrConflict", agentID, err)
		}
		if !strings.Contains(err.Error(), "Cinema") {
			t.Fatalf("Agent %q error omits Proxy Node name: %v", agentID, err)
		}
	}
	assertReferenced("edge-a")

	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	if err := store.MoveHop(node.ID, node.Entrance.HopID, "edge-b"); err != nil {
		t.Fatal(err)
	}
	// The new desired Agent and the old still-applied Agent are both unsafe to
	// remove until the topology transition has committed.
	assertReferenced("edge-a")
	assertReferenced("edge-b")
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-b"}); err != nil {
		t.Fatal(err)
	}
	if err := store.RequireAgentUnreferenced("edge-a"); err != nil {
		t.Fatalf("retired Agent remains referenced after applied move: %v", err)
	}
	assertReferenced("edge-b")

	if err := store.SetManagedAgents([]string{"edge-b", "edge-retirement-pending"}); err != nil {
		t.Fatal(err)
	}
	err = store.RequireAgentUnreferenced("edge-retirement-pending")
	if !errors.Is(err, ErrAgentReferenced) || !strings.Contains(err.Error(), "applied managed configuration") {
		t.Fatalf("managed retirement error = %v, want ErrAgentReferenced", err)
	}
}

func TestDeployerGuardAgentRemovalFailsBeforeCallback(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	deployer, err := NewDeployer(
		store,
		testResolver{"edge-a": "192.0.2.10"},
		&applyingController{},
	)
	if err != nil {
		t.Fatal(err)
	}

	callbackErr := errors.New("callback failed")
	called := false
	if err := deployer.GuardAgentRemoval("edge-unused", false, func() error {
		called = true
		deployer.mu.RLock()
		reserved := deployer.mutationReserved
		deployer.mu.RUnlock()
		if !reserved {
			t.Fatal("Agent removal callback ran without a topology reservation")
		}
		mutationCalled := false
		if _, err := deployer.MutateAndStart(func() error {
			mutationCalled = true
			return nil
		}); !errors.Is(err, ErrDeploymentActive) || mutationCalled {
			t.Fatalf("concurrent topology mutation called=%v error=%v", mutationCalled, err)
		}
		return callbackErr
	}); !errors.Is(err, callbackErr) || !called {
		t.Fatalf("unguarded callback called=%v error=%v", called, err)
	}
	deployer.mu.RLock()
	reserved := deployer.mutationReserved
	deployer.mu.RUnlock()
	if reserved {
		t.Fatal("Agent removal callback left topology reserved")
	}

	if _, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	}); err != nil {
		t.Fatal(err)
	}
	called = false
	if err := deployer.GuardAgentRemoval("edge-a", false, func() error {
		called = true
		return nil
	}); !errors.Is(err, ErrAgentReferenced) || called {
		t.Fatalf("referenced removal called=%v error=%v", called, err)
	}

	deployer.mutationReserved = true
	if err := deployer.GuardAgentRemoval("edge-unused", false, func() error {
		called = true
		return nil
	}); !errors.Is(err, ErrDeploymentActive) || called {
		t.Fatalf("reserved removal called=%v error=%v", called, err)
	}
}

func TestDeployerGuardAgentRemovalForceSkipsReferences(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	deployer, err := NewDeployer(
		store,
		testResolver{"edge-a": "192.0.2.10"},
		&applyingController{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	}); err != nil {
		t.Fatal(err)
	}

	// A forced removal declares the hardware permanently gone, so the
	// desired/applied reference check no longer applies. The control plane
	// independently guarantees the Agent is offline before offering this.
	called := false
	if err := deployer.GuardAgentRemoval("edge-a", true, func() error {
		called = true
		return nil
	}); err != nil || !called {
		t.Fatalf("forced referenced removal called=%v error=%v", called, err)
	}

	// An in-flight rollout or open mutation reservation still blocks it.
	deployer.mutationReserved = true
	called = false
	if err := deployer.GuardAgentRemoval("edge-a", true, func() error {
		called = true
		return nil
	}); !errors.Is(err, ErrDeploymentActive) || called {
		t.Fatalf("reserved forced removal called=%v error=%v", called, err)
	}
	deployer.mutationReserved = false

	// The reference check still applies to the ordinary path.
	if err := deployer.GuardAgentRemoval("edge-a", false, func() error {
		called = true
		return nil
	}); !errors.Is(err, ErrAgentReferenced) || called {
		t.Fatalf("unforced referenced removal called=%v error=%v", called, err)
	}
}
