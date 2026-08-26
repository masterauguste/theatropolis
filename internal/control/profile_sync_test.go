package control

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

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
