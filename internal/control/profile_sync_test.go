package control

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

func TestInitialProfileReadinessGatesOrdinaryTopologyDeployment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	const agentID = "edge-ordering"
	enrollTestIdentity(t, server.Identities, agentID)
	hello := &controlv1.AgentHello{Capabilities: []string{ProxyNodeDeployCapability, ManagedUserAuthorityCapability}}
	session := newSessionFromHello(agentID, hello)
	for _, capability := range hello.GetCapabilities() {
		session.capabilities[capability] = struct{}{}
	}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)
	if server.CanDeployProxyNodeConfiguration(agentID) || server.CanSyncManagedUserAuthority(agentID) {
		t.Fatal("new session became deployable before authoritative profile queue")
	}
	if err := server.syncProfileOnConnect(ctx, agentID); err != nil {
		t.Fatal(err)
	}
	if !server.CanDeployProxyNodeConfiguration(agentID) || !server.CanSyncManagedUserAuthority(agentID) {
		t.Fatal("session did not become ready after authoritative profile queue")
	}
	if _, err := server.QueueDeployment(
		ctx, agentID, "operator", "operator-revision", singbox.DisabledManagedConfig(), 0,
	); !errors.Is(err, deployment.ErrDeploymentInProgress) {
		t.Fatalf("ordinary topology deployment raced profile replay: %v", err)
	}
}

func TestStaleProfileSyncSessionCannotReadyReplacement(t *testing.T) {
	t.Parallel()
	server := newTestServer(deployment.NewMemoryStore(), nil)
	const agentID = "edge-session-replacement"
	hello := &controlv1.AgentHello{Capabilities: []string{ProxyNodeDeployCapability}}
	previous := newSessionFromHello(agentID, hello)
	previous.capabilities[ProxyNodeDeployCapability] = struct{}{}
	if err := server.Sessions.Register(previous); err != nil {
		t.Fatal(err)
	}
	if !server.Sessions.Disconnect(agentID) {
		t.Fatal("previous session was not disconnected")
	}
	replacement := newSessionFromHello(agentID, hello)
	replacement.capabilities[ProxyNodeDeployCapability] = struct{}{}
	if err := server.Sessions.Register(replacement); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(replacement)

	if server.Sessions.MarkProfileReady(previous) {
		t.Fatal("stale session marked its replacement ready")
	}
	if server.CanDeployProxyNodeConfiguration(agentID) {
		t.Fatal("replacement became deployable before its own profile replay")
	}
	if err := server.syncProfileOnSession(context.Background(), agentID, previous); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("stale profile sync error = %v, want Agent offline", err)
	}
	select {
	case frame := <-replacement.commands:
		t.Fatalf("stale profile sync sent command to replacement: %#v", frame)
	default:
	}
}

func TestReadySendDoesNotCrossSessionReplacement(t *testing.T) {
	t.Parallel()
	registry := NewSessionRegistry()
	const agentID = "edge-ready-send-replacement"
	previous := newSession(agentID)
	previous.capabilities[ManagedUserAuthorityCapability] = struct{}{}
	if err := registry.Register(previous); err != nil {
		t.Fatal(err)
	}
	if !registry.SupportsReady(agentID, ManagedUserAuthorityCapability) {
		t.Fatal("previous session is unexpectedly not ready")
	}
	if !registry.Disconnect(agentID) {
		t.Fatal("previous session was not disconnected")
	}
	replacement := newSessionFromHello(agentID, &controlv1.AgentHello{})
	replacement.capabilities[ManagedUserAuthorityCapability] = struct{}{}
	if err := registry.Register(replacement); err != nil {
		t.Fatal(err)
	}
	defer registry.Unregister(replacement)

	frame := &controlv1.MasterFrame{Payload: &controlv1.MasterFrame_ManagedUserAuthority{
		ManagedUserAuthority: &controlv1.ManagedUserAuthorityCommand{RequestId: "replacement-race"},
	}}
	if _, err := registry.SendReady(
		context.Background(), agentID, ManagedUserAuthorityCapability, frame,
	); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("ready send error = %v, want Agent offline", err)
	}
	select {
	case got := <-replacement.commands:
		t.Fatalf("command crossed into unready replacement session: %#v", got)
	default:
	}
}

func TestTopologyReadyNotificationDoesNotRequireManagedUserCapability(t *testing.T) {
	t.Parallel()
	server := newTestServer(deployment.NewMemoryStore(), nil)
	const agentID = "edge-topology-only"
	session := newSession(agentID)
	session.capabilities[ProxyNodeDeployCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)
	notified := make(chan struct{}, 1)
	server.SetProxyNodeTopologyHandler(func() { notified <- struct{}{} })
	server.notifyProxyNodeTopologyReady(agentID)
	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("topology-ready callback depended on managed-user capability")
	}
}

func TestProfileSyncDisablesAgentWithoutMasterProfile(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	enrollTestIdentity(t, server.Identities, "edge-empty")
	session := newSession("edge-empty")
	session.capabilities[ProxyNodeDeployCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)

	if err := server.syncProfileOnConnect(ctx, "edge-empty"); err != nil {
		t.Fatal(err)
	}
	command := (<-session.commands).GetDeployConfig()
	if command == nil {
		t.Fatal("profile synchronization sent no deployment")
	}
	if !bytes.Equal(command.GetConfigJson(), singbox.DisabledManagedConfig()) {
		t.Fatalf("disabled profile = %s", command.GetConfigJson())
	}
}

func TestProfileSyncReplaysRetainedMasterProfile(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	enrollTestIdentity(t, server.Identities, "edge-replacement")
	config := []byte(`{"inbounds":[],"outbounds":[{"type":"block","tag":"reject"}],"route":{"final":"reject"}}`)
	previous, err := deployment.New(
		"previous-deployment",
		"edge-replacement",
		"previous-revision",
		config,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, previous); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(
		ctx,
		previous.ID,
		deployment.StatusDeploying,
		"",
		time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(
		ctx,
		previous.ID,
		deployment.StatusApplied,
		"",
		time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
	session := newSession("edge-replacement")
	session.capabilities[ProxyNodeDeployCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)

	if err := server.syncProfileOnConnect(ctx, "edge-replacement"); err != nil {
		t.Fatal(err)
	}
	command := (<-session.commands).GetDeployConfig()
	if command == nil || !bytes.Equal(command.GetConfigJson(), config) {
		t.Fatalf("replayed profile = %s", command.GetConfigJson())
	}
	if command.GetDeploymentId() == previous.ID {
		t.Fatal("profile synchronization reused an old deployment ID")
	}
}

func TestProfileSyncRebuildsManagedProfileInsteadOfReplayingStaleRecord(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	const agentID = "edge-managed-upgrade"
	enrollTestIdentity(t, server.Identities, agentID)
	stale := []byte(`{"inbounds":[],"outbounds":[{"type":"block","tag":"old"}],"route":{"final":"old"}}`)
	fresh := []byte(`{"inbounds":[],"outbounds":[{"type":"block","tag":"new"}],"route":{"final":"new"}}`)
	previous, err := deployment.New(
		"stale-deployment", agentID, "old-compiler", stale, time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, previous); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(ctx, previous.ID, deployment.StatusDeploying, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(ctx, previous.ID, deployment.StatusApplied, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	server.SetAuthoritativeProfileProvider(func(_ context.Context, requested string) ([]byte, bool, error) {
		if requested != agentID {
			t.Fatalf("provider Agent = %q", requested)
		}
		return append([]byte(nil), fresh...), true, nil
	})
	session := newSession(agentID)
	session.capabilities[ProxyNodeDeployCapability] = struct{}{}
	session.capabilities[ManagedUserAuthorityCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)

	if err := server.syncProfileOnConnect(ctx, agentID); err != nil {
		t.Fatal(err)
	}
	command := (<-session.commands).GetDeployConfig()
	if command == nil || !bytes.Equal(command.GetConfigJson(), fresh) {
		t.Fatalf("replayed profile = %s, want rebuilt profile", command.GetConfigJson())
	}
	if deployment.ClassifyRevision(command.GetRevisionId()) != deployment.RevisionPlaneProxyNodeTopology {
		t.Fatalf("rebuilt profile revision = %q, want topology plane", command.GetRevisionId())
	}
}

func TestProfileSyncReclassifiesLegacyUsersRecordForAuthorityCapableReplacement(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	const agentID = "edge-authority-replacement"
	enrollTestIdentity(t, server.Identities, agentID)
	config := []byte(`{"inbounds":[],"outbounds":[{"type":"block","tag":"reject"}],"route":{"final":"reject"}}`)
	previous, err := deployment.New(
		"previous-users-deployment", agentID,
		deployment.ProxyNodeUsersRevisionPrefix+"previous", config, time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, previous); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(ctx, previous.ID, deployment.StatusDeploying, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(ctx, previous.ID, deployment.StatusApplied, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	session := newSession(agentID)
	session.capabilities[ProxyNodeDeployCapability] = struct{}{}
	session.capabilities[ManagedUserAuthorityCapability] = struct{}{}
	if err := server.Sessions.Register(session); err != nil {
		t.Fatal(err)
	}
	defer server.Sessions.Unregister(session)
	if err := server.syncProfileOnConnect(ctx, agentID); err != nil {
		t.Fatal(err)
	}
	command := (<-session.commands).GetDeployConfig()
	if command == nil || deployment.ClassifyRevision(command.GetRevisionId()) != deployment.RevisionPlaneProxyNodeTopology {
		t.Fatalf("replacement replay revision = %q, want topology safety filtering", command.GetRevisionId())
	}
}
