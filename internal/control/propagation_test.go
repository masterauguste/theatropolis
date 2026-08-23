package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
)

const (
	poolTestRef     = "agent/agent-a/hy2-in/alice"
	poolTestAddress = "192.0.2.10"
)

func poolSourceConfig(listenPort int) []byte {
	config := map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":        "hysteria2",
				"tag":         "hy2-in",
				"listen_port": listenPort,
				"users":       []any{map[string]any{"name": "alice", "password": "pw-alice"}},
				"tls":         map[string]any{"enabled": true, "certificate_provider": "acme-main"},
			},
		},
		"certificate_providers": []any{
			map[string]any{"tag": "acme-main", "type": "acme", "domain": []string{"hy2.example.com"}},
		},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		panic(err)
	}
	return encoded
}

func poolDependentConfig() []byte {
	return []byte(`{"outbounds":[{"type":"theatropolis-pool-ref","tag":"via-a","ref":"` +
		poolTestRef + `"}]}`)
}

func newPoolTestServer(t *testing.T) (*Server, *pool.Registry, deployment.Store) {
	t.Helper()
	registry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	store := deployment.NewMemoryStore()
	server := NewServer(
		identity.NewRegistry(),
		store,
		registry,
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	// Close is a no-op since the master-side probe scheduler was removed
	// (freshness is agent-side now); kept so pool servers shut down
	// uniformly with the other test servers.
	t.Cleanup(server.Close)
	return server, registry, store
}

// storeAppliedConfig inserts an already-applied record for agentID without
// touching sessions, standing in for a source agent's deployment.
func storeAppliedConfig(
	t *testing.T,
	ctx context.Context,
	store deployment.Store,
	agentID string,
	config []byte,
) deployment.Record {
	t.Helper()
	record, err := deployment.New(
		"dep-"+agentID,
		agentID,
		"rev-"+agentID,
		config,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(ctx, record.ID, deployment.StatusDeploying, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(ctx, record.ID, deployment.StatusApplied, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return record
}

func registerPoolSession(t *testing.T, server *Server, agentID string) *session {
	t.Helper()
	enrollTestIdentity(t, server.Identities, agentID)
	session := newSession(agentID)
	session.capabilities[ProxyNodeDeployCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Sessions.Unregister(session)
	})
	return session
}

// deployThroughServer queues a deployment and reports it applied, returning
// the command the agent received. It leaves no deployment in flight.
func deployThroughServer(
	t *testing.T,
	ctx context.Context,
	server *Server,
	session *session,
	agentID string,
	config []byte,
) *controlv1.DeployConfigCommand {
	t.Helper()
	deploymentID, err := randomOpaqueID("dep")
	if err != nil {
		t.Fatal(err)
	}
	revisionID, err := randomOpaqueID("rev")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.QueueDeployment(
		ctx,
		agentID,
		deploymentID,
		revisionID,
		config,
		5*time.Second,
	); err != nil {
		t.Fatal(err)
	}
	command := (<-session.commands).GetDeployConfig()
	if command == nil {
		t.Fatal("agent did not receive the queued deployment")
	}
	if err := server.handleDeploymentReport(ctx, agentID, &controlv1.ConfigDeploymentReport{
		DeploymentId: command.GetDeploymentId(),
		RevisionId:   command.GetRevisionId(),
		ConfigSha256: command.GetConfigSha256(),
		Status:       controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED,
	}); err != nil {
		t.Fatal(err)
	}
	return command
}

func firstOutbound(t *testing.T, command *controlv1.DeployConfigCommand) map[string]any {
	t.Helper()
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(command.GetConfigJson(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Outbounds) == 0 {
		t.Fatal("rendered configuration carries no outbounds")
	}
	return document.Outbounds[0]
}

func assertNoCommand(t *testing.T, session *session) {
	t.Helper()
	select {
	case frame := <-session.commands:
		t.Fatalf("unexpected frame queued for the agent: %+v", frame)
	default:
	}
}

func TestPoolDependentsDiscoversRefCarryingConfigs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, _, store := newPoolTestServer(t)
	storeAppliedConfig(t, ctx, store, "agent-a", poolSourceConfig(8443))
	storeAppliedConfig(t, ctx, store, "agent-b", poolDependentConfig())
	storeAppliedConfig(t, ctx, store, "agent-c", []byte(`{"outbounds":[{"type":"direct","tag":"x"}]}`))

	dependents := server.poolDependents("agent-a")
	if len(dependents) != 1 {
		t.Fatalf("poolDependents() = %v", dependents)
	}
	refs, exists := dependents["agent-b"]
	if !exists || len(refs) != 1 || refs[0] != poolTestRef {
		t.Fatalf("poolDependents()[agent-b] = %v, exists=%v", refs, exists)
	}
}

func TestQueueDeploymentRendersPoolRefsAndStampsOnApplied(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, store := newPoolTestServer(t)
	if _, err := registry.SetReported("agent-a", []string{poolTestAddress}, nil); err != nil {
		t.Fatal(err)
	}
	storeAppliedConfig(t, ctx, store, "agent-a", poolSourceConfig(8443))
	session := registerPoolSession(t, server, "agent-b")

	logical := poolDependentConfig()
	command := deployThroughServer(t, ctx, server, session, "agent-b", logical)

	// The agent received rendered JSON: no ref, concrete hysteria2 outbound.
	if bytes.Contains(command.GetConfigJson(), []byte("theatropolis-pool-ref")) {
		t.Fatal("rendered configuration still contains a pool ref")
	}
	outbound := firstOutbound(t, command)
	if outbound["type"] != "hysteria2" ||
		outbound["tag"] != "via-a" ||
		outbound["server"] != poolTestAddress ||
		outbound["server_port"] != float64(8443) ||
		outbound["password"] != "pw-alice" {
		t.Fatalf("rendered outbound = %v", outbound)
	}
	tls, ok := outbound["tls"].(map[string]any)
	if !ok || tls["enabled"] != true ||
		tls["server_name"] != "hy2.example.com" ||
		tls["insecure"] != false {
		t.Fatalf("rendered outbound TLS = %v", outbound["tls"])
	}
	digest := sha256.Sum256(command.GetConfigJson())
	if !bytes.Equal(digest[:], command.GetConfigSha256()) {
		t.Fatal("command digest does not match the rendered document")
	}

	// The record keeps the logical config plus the rendered digest.
	record, err := store.LatestForAgent(ctx, "agent-b")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.ConfigJSON, logical) {
		t.Fatalf("record config = %s, want the logical document", record.ConfigJSON)
	}
	if record.RenderedSHA256 != digest || record.RenderedSHA256 == record.ConfigSHA256 {
		t.Fatalf("record rendered digest = %x", record.RenderedSHA256)
	}

	// The applied report stamped the agent's render state at the current
	// pool version.
	version, sha, stamped := registry.RenderedVersion("agent-b")
	if !stamped || version != registry.PoolVersion() || sha != digest {
		t.Fatalf("RenderedVersion() = %d, %x, %v", version, sha, stamped)
	}
}

func TestPropagateNoOpWhenRenderedUnchanged(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, store := newPoolTestServer(t)
	if _, err := registry.SetReported("agent-a", []string{poolTestAddress}, nil); err != nil {
		t.Fatal(err)
	}
	storeAppliedConfig(t, ctx, store, "agent-a", poolSourceConfig(8443))
	session := registerPoolSession(t, server, "agent-b")
	command := deployThroughServer(t, ctx, server, session, "agent-b", poolDependentConfig())

	// Bump the pool version without affecting what agent-b renders.
	if err := registry.SetOverride("agent-unrelated", "192.0.2.99"); err != nil {
		t.Fatal(err)
	}
	server.propagatePoolChange(ctx, "test", "agent-a")

	assertNoCommand(t, session)
	latest, err := store.LatestForAgent(ctx, "agent-b")
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != command.GetDeploymentId() {
		t.Fatalf("propagation replaced the deployment with %q", latest.ID)
	}
	version, _, stamped := registry.RenderedVersion("agent-b")
	if !stamped || version != registry.PoolVersion() {
		t.Fatalf("render stamp did not advance: version %d, pool %d", version, registry.PoolVersion())
	}
}

func TestPropagateSkipsOfflineDependentAndProfileSyncCatchesUpOnReconnect(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, store := newPoolTestServer(t)
	if _, err := registry.SetReported("agent-a", []string{poolTestAddress}, nil); err != nil {
		t.Fatal(err)
	}
	storeAppliedConfig(t, ctx, store, "agent-a", poolSourceConfig(8443))
	session := registerPoolSession(t, server, "agent-b")
	command := deployThroughServer(t, ctx, server, session, "agent-b", poolDependentConfig())

	// agent-b goes offline, then the pool address changes underneath it.
	server.Sessions.Unregister(session)
	if _, err := registry.SetReported("agent-a", []string{"192.0.2.77"}, nil); err != nil {
		t.Fatal(err)
	}
	server.propagatePoolChange(ctx, "addresses", "agent-a")
	latest, err := store.LatestForAgent(ctx, "agent-b")
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != command.GetDeploymentId() {
		t.Fatal("offline dependent was redeployed")
	}

	// On reconnect authoritative profile synchronization re-renders the
	// logical configuration against the latest pool state.
	reconnected := newSession("agent-b")
	reconnected.capabilities[ProxyNodeDeployCapability] = struct{}{}
	if err := server.Sessions.Register(reconnected); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(reconnected)
	if err := server.syncProfileOnConnect(ctx, "agent-b"); err != nil {
		t.Fatal(err)
	}

	frame := <-reconnected.commands
	followup := frame.GetDeployConfig()
	if followup == nil {
		t.Fatal("reconnected dependent received no catch-up deployment")
	}
	if followup.GetDeploymentId() == command.GetDeploymentId() ||
		!strings.HasPrefix(followup.GetDeploymentId(), "dep_") {
		t.Fatalf("catch-up deployment ID = %q", followup.GetDeploymentId())
	}
	if outbound := firstOutbound(t, followup); outbound["server"] != "192.0.2.77" {
		t.Fatalf("catch-up rendered outbound = %v", outbound)
	}
	latest, err = store.LatestForAgent(ctx, "agent-b")
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != followup.GetDeploymentId() {
		t.Fatal("catch-up deployment was not stored")
	}
}

func TestRevokeAgentRedeploysDependentWithDirectFallback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, _ := newPoolTestServer(t)
	if _, err := registry.SetReported("agent-a", []string{poolTestAddress}, nil); err != nil {
		t.Fatal(err)
	}
	sessionA := registerPoolSession(t, server, "agent-a")
	sessionB := registerPoolSession(t, server, "agent-b")
	deployThroughServer(t, ctx, server, sessionA, "agent-a", poolSourceConfig(8443))
	deployThroughServer(t, ctx, server, sessionB, "agent-b", poolDependentConfig())

	if err := server.RevokeAgent(ctx, "agent-a"); err != nil {
		t.Fatal(err)
	}
	if _, exists := registry.AgentAddress("agent-a"); exists {
		t.Fatal("revoked agent kept its pool address")
	}

	frame := <-sessionB.commands
	command := frame.GetDeployConfig()
	if command == nil {
		t.Fatal("dependent was not redeployed after the revocation")
	}
	outbound := firstOutbound(t, command)
	if outbound["type"] != "direct" || outbound["tag"] != "via-a" {
		t.Fatalf("fallback outbound = %v", outbound)
	}
}

func TestHeartbeatAddressChangePropagatesToDependents(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, registry, _ := newPoolTestServer(t)
	if _, err := registry.SetReported("agent-a", []string{poolTestAddress}, nil); err != nil {
		t.Fatal(err)
	}
	storeAppliedConfig(t, ctx, server.Deployments, "agent-a", poolSourceConfig(8443))
	sessionA := registerPoolSession(t, server, "agent-a")
	sessionB := registerPoolSession(t, server, "agent-b")
	deployThroughServer(t, ctx, server, sessionB, "agent-b", poolDependentConfig())

	if err := server.handleAgentFrame(ctx, "agent-a", &controlv1.AgentFrame{
		Payload: &controlv1.AgentFrame_Heartbeat{
			Heartbeat: &controlv1.AgentHeartbeat{
				ObservedAtUnix:    time.Now().Unix(),
				ReportedAddresses: []string{"192.0.2.55"},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if address, _ := registry.AgentAddress("agent-a"); address != "192.0.2.55" {
		t.Fatalf("pool address = %q", address)
	}
	frame := <-sessionB.commands
	command := frame.GetDeployConfig()
	if command == nil {
		t.Fatal("dependent was not redeployed after the address change")
	}
	if outbound := firstOutbound(t, command); outbound["server"] != "192.0.2.55" {
		t.Fatalf("re-rendered outbound = %v", outbound)
	}
	assertNoCommand(t, sessionA)
}
