package mastermigration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
	"github.com/masterauguste/theatropolis/internal/webui"
)

func testService(t *testing.T, directory, admin string) (*Service, func()) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	password := []byte("migration-test-password-123")
	if err := webui.InitializeAdminAccess(filepath.Join(directory, "web-auth.json"), admin, password); err != nil {
		t.Fatal(err)
	}
	_, users, err := webui.OpenUnifiedWebAccess(
		filepath.Join(directory, "web-auth.json"), filepath.Join(directory, "end-user-auth.json"),
		filepath.Join(directory, "web-sessions.json"), filepath.Join(directory, "end-user-sessions.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	build := proxynode.BuildInfo{Component: "master", Version: "v1.0.0", Commit: "test-commit"}
	nodes, err := proxynode.Open(filepath.Join(directory, "proxy-node-state.json"), build)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.OpenRegistry(filepath.Join(directory, "identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	deployments, err := deployment.NewDiskStore(filepath.Join(directory, "deployments"))
	if err != nil {
		t.Fatal(err)
	}
	poolRegistry, err := pool.Open(filepath.Join(directory, "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{StateDirectory: directory, Version: "v1.0.0", Build: build,
		ProxyNodes: nodes, Identities: identities, Deployments: deployments, Pool: poolRegistry,
		Now: func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) },
	}
	return service, func() { _ = users.Close(); _ = nodes.Close() }
}

func TestEncryptedMigrationPreservesNewAdministratorAndFleetData(t *testing.T) {
	source, closeSource := testService(t, filepath.Join(t.TempDir(), "source"), "old-admin")
	defer closeSource()
	user, err := source.ProxyNodes.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	_, sourceUsers, err := webui.OpenUnifiedWebAccess(
		filepath.Join(source.StateDirectory, "web-auth.json"), filepath.Join(source.StateDirectory, "end-user-auth.json"),
		filepath.Join(source.StateDirectory, "web-sessions-2.json"), filepath.Join(source.StateDirectory, "end-user-sessions-2.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sourceUsers.IssueInvitation(user.ID, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	_ = sourceUsers.Close()
	token, err := source.Identities.CreateEnrollment(context.Background(), "edge-one", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Identities.EnrollByToken(context.Background(), token, publicKey, time.Now()); err != nil {
		t.Fatal(err)
	}

	const passphrase = "correct horse battery staple"
	exported, err := source.Export(context.Background(), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(exported.Filename, ".zip") || len(exported.Data) == 0 {
		t.Fatalf("invalid export result: %#v", exported)
	}

	target, closeTarget := testService(t, filepath.Join(t.TempDir(), "target"), "new-admin")
	defer closeTarget()
	if _, err := target.StageRestore(context.Background(), exported.Data, "wrong password value"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	summary, err := target.StageRestore(context.Background(), exported.Data, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Agents != 1 || summary.Users != 1 {
		t.Fatalf("summary = %#v", summary)
	}
	if _, applied, err := ApplyPendingRestore(target.StateDirectory); err != nil || !applied {
		t.Fatalf("apply = %v, %v", applied, err)
	}

	authBytes, err := os.ReadFile(filepath.Join(target.StateDirectory, "web-auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var auth unifiedIdentityDocument
	if err := json.Unmarshal(authBytes, &auth); err != nil {
		t.Fatal(err)
	}
	roles := map[string]string{}
	for _, raw := range auth.Identities {
		var header identityHeader
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatal(err)
		}
		roles[header.Role] = header.LoginUsername
	}
	if roles["administrator"] != "new-admin" {
		t.Fatalf("administrator = %q", roles["administrator"])
	}
	restoredRegistry, err := identity.OpenRegistry(filepath.Join(target.StateDirectory, "identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	if snapshots := restoredRegistry.Snapshot(time.Now()); len(snapshots) != 1 || snapshots[0].ID != "edge-one" || snapshots[0].State != identity.AgentStateEnrolled {
		t.Fatalf("restored identities = %#v", snapshots)
	}
}

func TestRestoreRejectsNonEmptyTarget(t *testing.T) {
	service, closeService := testService(t, t.TempDir(), "admin")
	defer closeService()
	if _, err := service.ProxyNodes.CreateUser("Existing"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.StageRestore(context.Background(), []byte("not-an-archive"), "correct horse battery staple"); err != ErrTargetNotEmpty {
		t.Fatalf("error = %v, want ErrTargetNotEmpty", err)
	}
}

func TestExportAllowsPendingTopologyWithoutTransactionJournal(t *testing.T) {
	service, closeService := testService(t, t.TempDir(), "admin")
	defer closeService()
	if _, err := service.ProxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name:      "pending node",
		RootAgent: "edge-a",
		Entrance: proxynode.Endpoint{
			Protocol:   proxynode.ProtocolAnyTLS,
			Listen:     "::",
			ListenPort: 443,
			Family:     "ipv4",
			TLS: proxynode.TLSConfig{
				Mode:       proxynode.TLSModeSelfSigned,
				ServerName: "proxy.example.com",
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	state := service.ProxyNodes.Snapshot()
	if state.Revision == state.AppliedRevision {
		t.Fatalf("test setup did not create pending topology: revision %d", state.Revision)
	}

	if _, err := service.Export(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("export pending topology without transaction journal: %v", err)
	}
}

func TestExportRejectsActiveTopologyTransactionJournal(t *testing.T) {
	service, closeService := testService(t, t.TempDir(), "admin")
	defer closeService()
	journalPath := filepath.Join(service.StateDirectory, "proxy-node-topology-transaction.json")
	// Existence is sufficient: even a partial or corrupt journal means the
	// migration snapshot cannot safely choose between the old and new fleet.
	if err := os.WriteFile(journalPath, []byte("{\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := service.Export(context.Background(), "correct horse battery staple")
	if !errors.Is(err, ErrSnapshotBusy) {
		t.Fatalf("Export() error = %v, want ErrSnapshotBusy", err)
	}
}

func TestPendingRestoreResumesAfterInterruptedRename(t *testing.T) {
	source, closeSource := testService(t, filepath.Join(t.TempDir(), "source"), "old-admin")
	defer closeSource()
	if _, err := source.ProxyNodes.CreateUser("Alice"); err != nil {
		t.Fatal(err)
	}
	exported, err := source.Export(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	target, closeTarget := testService(t, filepath.Join(t.TempDir(), "target"), "new-admin")
	defer closeTarget()
	summary, err := target.StageRestore(context.Background(), exported.Data, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(target.StateDirectory, ".master-migration-backup-"+summary.MigrationID)
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	// Simulate power loss after the live state was retired but before the
	// staged replacement was installed.
	if err := os.Rename(
		filepath.Join(target.StateDirectory, "proxy-node-state.json"),
		filepath.Join(backup, "proxy-node-state.json"),
	); err != nil {
		t.Fatal(err)
	}
	if gotBackup, applied, err := ApplyPendingRestore(target.StateDirectory); err != nil || !applied || gotBackup != backup {
		t.Fatalf("resumed apply = %q, %v, %v", gotBackup, applied, err)
	}
	if _, err := os.Stat(filepath.Join(target.StateDirectory, "proxy-node-state.json")); err != nil {
		t.Fatalf("restored state missing: %v", err)
	}
	if _, applied, err := ApplyPendingRestore(target.StateDirectory); err != nil || applied {
		t.Fatalf("second apply = %v, %v", applied, err)
	}
}
