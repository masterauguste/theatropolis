package proxynode

import (
	"bytes"
	"path/filepath"
	"testing"
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
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	resolver := testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"}
	topology, err := CompileTopology(store.Snapshot(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(topology.Configs["edge-a"], []byte("cinema-alice")) {
		t.Fatal("topology plane contained an end-user credential")
	}
	if !bytes.Contains(topology.Configs["edge-b"], []byte("cinema-link-")) {
		t.Fatal("topology plane omitted its Link credential")
	}
	deploymentPayload, err := compileTopologyDeployment(store.Snapshot(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(deploymentPayload.Configs["edge-a"], []byte("cinema-alice")) {
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
	if !bytes.Contains(users.Configs["edge-a"], []byte("cinema-ally")) {
		t.Fatal("immediate user plane did not contain the renamed user")
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
		bytes.Contains(draft.Configs["edge-a"], []byte("cinema-ally")) {
		t.Fatal("topology plane did not remain user-agnostic")
	}
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
