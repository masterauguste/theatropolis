package proxynode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditRelayAppliedRefreshNoOp(t *testing.T) {
	state, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	endpoint := testTLSEndpoint(ProtocolAnyTLS, 443)
	endpoint.TLS.Mode = TLSModeACME
	endpoint.TLS.Email = "operator@example.com"
	if _, err := state.CreateProxyNode(CreateProxyNodeInput{Name: "audit", RootAgent: "edge-a", Entrance: endpoint}); err != nil {
		t.Fatal(err)
	}
	controller := &applyingController{store: deployment.NewMemoryStore(), deployable: map[string]bool{"edge-a": true}}
	deployer, err := NewDeployer(state, testResolver{"edge-a": "192.0.2.10"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	compiled, _, err := deployer.compileCompleteFleet(deploymentTopology)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for agentID, logical := range compiled.Configs {
		rendered, err := singbox.ConfigureACMEHTTP01Relay(logical)
		if err != nil {
			t.Fatal(err)
		}
		record, err := deployment.New("dep-audit", agentID, "rev-audit", logical, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		record.RenderedSHA256 = sha256.Sum256(rendered)
		if err := controller.store.Create(ctx, record); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.store.Transition(ctx, record.ID, deployment.StatusDeploying, "", time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.store.Transition(ctx, record.ID, deployment.StatusApplied, "", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	changed, err := deployer.changedAgents(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 {
		t.Fatalf("unchanged relayed Agent selected for deployment: %v", changed)
	}
	compiled.Configs["edge-a"] = bytes.ReplaceAll(compiled.Configs["edge-a"], []byte(`"proxy.example.com"`), []byte(`"changed.example.com"`))
	changed, err = deployer.changedAgents(compiled)
	if err != nil || len(changed) != 1 || changed[0] != "edge-a" {
		t.Fatalf("real certificate identity change was skipped: changed=%v err=%v", changed, err)
	}
}
