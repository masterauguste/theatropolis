package proxynode

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrepareMasterCutoverQuarantinesLegacyDeploymentsOnce(t *testing.T) {
	stateDirectory := t.TempDir()
	legacy := filepath.Join(stateDirectory, "deployments")
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "edge-a.json"), []byte("legacy secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	poolContents := []byte(`{"version":1,"pool_version":0,"manual":[],"agents":{},"rendered":{}}`)
	if err := os.WriteFile(filepath.Join(stateDirectory, "outbound-pool.json"), poolContents, 0o600); err != nil {
		t.Fatal(err)
	}
	quarantine, firstCutover, err := PrepareMasterCutover(stateDirectory, time.Date(2026, 8, 23, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if quarantine == "" || !firstCutover {
		t.Fatal("legacy records were not quarantined")
	}
	if _, err := os.Stat(filepath.Join(quarantine, "deployments", "edge-a.json")); err != nil {
		t.Fatalf("quarantined record missing: %v", err)
	}
	if copied, err := os.ReadFile(filepath.Join(quarantine, "outbound-pool.json")); err != nil || string(copied) != string(poolContents) {
		t.Fatalf("quarantined outbound pool = %q, %v", copied, err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy deployment directory remains live: %v", err)
	}
	store, err := Open(filepath.Join(stateDirectory, "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser("alice"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "new.json"), []byte("new deployment"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, firstCutover, err := PrepareMasterCutover(stateDirectory, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if second != "" || firstCutover {
		t.Fatalf("valid new state triggered another cutover: %q", second)
	}
	if _, err := os.Stat(filepath.Join(legacy, "new.json")); err != nil {
		t.Fatalf("new-format deployment record was moved: %v", err)
	}
}
