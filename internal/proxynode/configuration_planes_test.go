package proxynode

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/masterauguste/theatropolis/internal/singbox"
)

func TestConfigurationPlanesKeepDraftTopologyOutOfImmediateUserSync(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	link, _, rule, err := store.AddBranch(node.ID, AddBranchInput{
		AddLinkInput: AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildName: "exit", ChildAgent: "edge-b",
			Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443), Final: Target{Type: TargetDirect},
		},
		Match: MatchDomain, Values: []string{"applied.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := store.AddMembership(node.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	authLabel := AuthenticatedUserLabel(membership.ID)
	linkLabel := linkUserLabel(link.ID)
	resolver := testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"}
	topology, err := CompileTopology(store.Snapshot(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(topology.Configs["edge-a"], []byte(authLabel)) {
		t.Fatal("topology plane contained an end-user credential")
	}
	if !bytes.Contains(topology.Configs["edge-b"], []byte(linkLabel)) {
		t.Fatal("topology plane omitted its Link credential")
	}
	deploymentPayload, err := compileTopologyDeployment(store.Snapshot(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(deploymentPayload.Configs["edge-a"], []byte(authLabel)) {
		t.Fatal("topology deployment did not preserve the current live user plane")
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a", "edge-b"}); err != nil {
		t.Fatal(err)
	}

	before := store.Snapshot()
	if err := store.UpdateRule(node.ID, rule.ID, UpdateRuleInput{
		LinkID: link.ID, Match: MatchDomain, Values: []string{"draft.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RenameUser(user.ID, "ally"); err != nil {
		t.Fatal(err)
	}
	after := store.Snapshot()
	if after.Revision != before.Revision+1 {
		t.Fatalf("topology revision = %d, want %d", after.Revision, before.Revision+1)
	}
	if after.UserRevision != before.UserRevision+1 {
		t.Fatalf("user revision = %d, want %d", after.UserRevision, before.UserRevision+1)
	}

	users, err := CompileAppliedUsers(after, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(users.Configs["edge-a"], []byte(authLabel)) {
		t.Fatal("immediate user plane did not preserve the Membership auth_user")
	}
	if bytes.Contains(users.Configs["edge-a"], []byte("draft.example")) ||
		!bytes.Contains(users.Configs["edge-a"], []byte("applied.example")) {
		t.Fatal("immediate user plane leaked draft routing state")
	}

	draft, err := CompileTopology(after, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(draft.Configs["edge-a"], []byte("draft.example")) ||
		bytes.Contains(draft.Configs["edge-a"], []byte(authLabel)) {
		t.Fatal("topology plane did not remain user-agnostic")
	}
}

func TestProxyNodeRenameLeavesAuthUsersStableAcrossAppliedTopology(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("用户 一")
	if err != nil {
		t.Fatal(err)
	}
	lateUser, err := store.CreateUser("用户 二")
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := store.AddMembership(node.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}

	resolver := testResolver{"edge-a": "192.0.2.10"}
	authLabel := AuthenticatedUserLabel(membership.ID)
	before := store.Snapshot()
	if err := store.RenameProxyNode(node.ID, "剧院 节点"); err != nil {
		t.Fatal(err)
	}
	renamed := store.Snapshot()
	if renamed.Revision != before.Revision+1 || renamed.UserRevision != before.UserRevision {
		t.Fatalf(
			"rename revisions = topology %d, users %d; want %d, %d",
			renamed.Revision,
			renamed.UserRevision,
			before.Revision+1,
			before.UserRevision,
		)
	}
	lateMembership, err := store.AddMembership(node.ID, lateUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	draft := store.Snapshot()
	if draft.Revision != renamed.Revision || draft.UserRevision != renamed.UserRevision+1 {
		t.Fatalf(
			"concurrent Membership revisions = topology %d, users %d; want %d, %d",
			draft.Revision,
			draft.UserRevision,
			renamed.Revision,
			renamed.UserRevision+1,
		)
	}
	lateAuthLabel := AuthenticatedUserLabel(lateMembership.ID)

	appliedUsers, err := CompileAppliedUsers(draft, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(appliedUsers.Configs["edge-a"], []byte(authLabel)) ||
		!bytes.Contains(appliedUsers.Configs["edge-a"], []byte(lateAuthLabel)) {
		t.Fatal("still-applied topology omitted an immutable Membership auth_user")
	}
	deployment, err := compileTopologyDeployment(draft, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(deployment.Configs["edge-a"], []byte(authLabel)) ||
		!bytes.Contains(deployment.Configs["edge-a"], []byte(lateAuthLabel)) {
		t.Fatal("candidate topology changed an immutable Membership auth_user")
	}

	if err := store.MarkTopologyApplied(draft.Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	committed := store.Snapshot()
	if committed.UserRevision != draft.UserRevision+1 {
		t.Fatalf(
			"committed user revision = %d, want %d",
			committed.UserRevision,
			draft.UserRevision+1,
		)
	}
	committedUsers, err := CompileAppliedUsers(committed, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(committedUsers.Configs["edge-a"], []byte(authLabel)) ||
		!bytes.Contains(committedUsers.Configs["edge-a"], []byte(lateAuthLabel)) {
		t.Fatal("committed authority changed an immutable Membership auth_user")
	}
	for _, config := range [][]byte{
		appliedUsers.Configs["edge-a"],
		deployment.Configs["edge-a"],
		committedUsers.Configs["edge-a"],
	} {
		for _, displayName := range []string{"Cinema", "剧院 节点", user.Name, lateUser.Name} {
			if bytes.Contains(config, []byte(displayName)) {
				t.Fatalf("compiled auth authority contains mutable display name %q", displayName)
			}
		}
	}
}

func TestMarkTopologyAppliedReservesRevisionForTopologyOnlyAuthorityChanges(t *testing.T) {
	t.Run("entrance Agent move", func(t *testing.T) {
		store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		node, err := store.CreateProxyNode(CreateProxyNodeInput{
			Name: "Cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
			t.Fatal(err)
		}

		before := store.Snapshot()
		if err := store.MoveHop(node.ID, node.Entrance.HopID, "edge-b"); err != nil {
			t.Fatal(err)
		}
		draft := store.Snapshot()
		if draft.UserRevision != before.UserRevision {
			t.Fatalf("draft move changed user revision from %d to %d", before.UserRevision, draft.UserRevision)
		}
		if err := store.MarkTopologyApplied(draft.Revision+1, []string{"edge-b"}); err != ErrConflict {
			t.Fatalf("stale topology commit error = %v, want ErrConflict", err)
		}
		if failed := store.Snapshot(); failed.UserRevision != draft.UserRevision || failed.AppliedRevision != before.AppliedRevision {
			t.Fatalf(
				"failed topology commit changed applied/user revisions to %d/%d, want %d/%d",
				failed.AppliedRevision,
				failed.UserRevision,
				before.AppliedRevision,
				draft.UserRevision,
			)
		}
		if err := store.MarkTopologyApplied(draft.Revision, []string{"edge-b"}); err != nil {
			t.Fatal(err)
		}
		applied := store.Snapshot()
		if applied.UserRevision != draft.UserRevision+1 {
			t.Fatalf("applied move user revision = %d, want %d", applied.UserRevision, draft.UserRevision+1)
		}
		compiled, err := CompileAppliedUsers(applied, testResolver{"edge-b": "192.0.2.11"})
		if err != nil {
			t.Fatal(err)
		}
		if compiled.Configs["edge-b"] == nil || compiled.Configs["edge-a"] != nil {
			t.Fatalf("applied entrance authority did not move exclusively to edge-b: %#v", compiled.Configs)
		}
	})

	t.Run("new empty entrance on an existing Agent", func(t *testing.T) {
		store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		if _, err := store.CreateProxyNode(CreateProxyNodeInput{
			Name: "Cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
			t.Fatal(err)
		}

		before := store.Snapshot()
		if _, err := store.CreateProxyNode(CreateProxyNodeInput{
			Name: "Theater", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 444),
		}); err != nil {
			t.Fatal(err)
		}
		draft := store.Snapshot()
		if draft.UserRevision != before.UserRevision {
			t.Fatalf("draft empty entrance changed user revision from %d to %d", before.UserRevision, draft.UserRevision)
		}
		if err := store.MarkTopologyApplied(draft.Revision, []string{"edge-a"}); err != nil {
			t.Fatal(err)
		}
		applied := store.Snapshot()
		if applied.UserRevision != draft.UserRevision+1 {
			t.Fatalf("applied empty entrance user revision = %d, want %d", applied.UserRevision, draft.UserRevision+1)
		}
		compiled, err := CompileAppliedUsers(applied, testResolver{"edge-a": "192.0.2.10"})
		if err != nil {
			t.Fatal(err)
		}
		variant, err := singbox.BuildManagedUserAuthorityVariant(compiled.Configs["edge-a"])
		if err != nil {
			t.Fatal(err)
		}
		if len(variant.Endpoints) != 2 {
			t.Fatalf("managed authority endpoints = %d, want 2", len(variant.Endpoints))
		}
	})
}

func TestEntranceCredentialShapeChangesOnlyWhenTopologyIsApplied(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	membership, _ := store.AddMembership(node.ID, user.ID)
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	shadowsocks := Endpoint{
		Protocol: ProtocolShadowsocks, Listen: "::", ListenPort: 443, Family: "ipv4",
		Method: "2022-blake3-aes-128-gcm",
	}
	if err := store.UpdateEntrance(node.ID, shadowsocks); err != nil {
		t.Fatal(err)
	}
	pending, _ := store.ProxyNode(node.ID)
	if pending.Memberships[0].Credential.Secret != membership.Credential.Secret ||
		pending.Memberships[0].PendingCredential == nil {
		t.Fatalf("pending entrance edit changed the active credential: %#v", pending.Memberships[0])
	}
	pendingSecret := pending.Memberships[0].PendingCredential.Secret
	deploymentPayload, err := compileTopologyDeployment(store.Snapshot(), testResolver{"edge-a": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(deploymentPayload.Configs["edge-a"], []byte(pendingSecret)) ||
		bytes.Contains(deploymentPayload.Configs["edge-a"], []byte(membership.Credential.Secret)) {
		t.Fatal("topology deployment did not use the staged entrance credential")
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	applied, _ := store.ProxyNode(node.ID)
	if applied.Memberships[0].PendingCredential != nil || applied.Memberships[0].Credential.Secret != pendingSecret {
		t.Fatalf("pending credential was not promoted with topology: %#v", applied.Memberships[0])
	}
}
