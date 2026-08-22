package proxynode

import (
	"context"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
)

type applyingController struct {
	mu         sync.Mutex
	store      deployment.Store
	order      []string
	deployable map[string]bool
}

func (c *applyingController) CanDeployProxyNodeConfiguration(agentID string) bool {
	return c.deployable[agentID]
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
	record, err = c.store.Transition(ctx, record.ID, deployment.StatusApplied, "", time.Now().UTC())
	if err != nil {
		return deployment.Record{}, err
	}
	c.mu.Lock()
	c.order = append(c.order, agentID)
	c.mu.Unlock()
	return record, nil
}

func (c *applyingController) LatestDeployment(ctx context.Context, agentID string) (deployment.Record, error) {
	return c.store.LatestForAgent(ctx, agentID)
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
	if _, _, err := store.AddLink(node.ID, AddLinkInput{ParentHopID: middle.ID, ChildName: "Exit", ChildAgent: "edge-c", Endpoint: testTLSEndpoint(ProtocolHysteria2, 9443)}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetLink, LinkID: first.ID}); err != nil {
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
	deadline := time.Now().Add(3 * time.Second)
	for {
		job, exists := deployer.Current()
		if exists && job.Status == FleetDeploymentApplied {
			break
		}
		if exists && job.Status == FleetDeploymentFailed {
			t.Fatalf("fleet deployment failed: %s", job.Error)
		}
		if time.Now().After(deadline) {
			t.Fatal("fleet deployment did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	controller.mu.Lock()
	order := append([]string(nil), controller.order...)
	controller.mu.Unlock()
	if !slices.Equal(order, []string{"edge-c", "edge-b", "edge-a"}) {
		t.Fatalf("deployment order = %v, want receiver-first", order)
	}
	if got := store.Snapshot().ManagedAgents; !slices.Equal(got, []string{"edge-a", "edge-b", "edge-c"}) {
		t.Fatalf("managed Agents = %v", got)
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
