package proxynode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUserSubscriptionLifecycleIsDurableAndIndependent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.Subscription.Token == "" {
		t.Fatal("new user did not receive a subscription token")
	}
	created, err := store.RotateUserSubscription(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if created.Token == "" || created.Token == user.Subscription.Token {
		t.Fatalf("created subscription = %#v", created)
	}
	if _, exists := store.UserBySubscriptionToken(user.Subscription.Token); exists {
		t.Fatal("rotated subscription token remained in the lookup index")
	}
	if indexed, exists := store.UserBySubscriptionToken(created.Token); !exists || indexed.ID != user.ID {
		t.Fatalf("new subscription token lookup = %#v, exists=%v", indexed, exists)
	}
	rule, err := store.AddSubscriptionRule(SubscriptionRuleInput{
		Match: SubscriptionMatchGeosite, Values: []string{"category-ads-all"}, Action: SubscriptionReject,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddSubscriptionRule(SubscriptionRuleInput{
		Match: SubscriptionMatchDomainSuffix, Values: []string{"example.com"}, Action: SubscriptionProxy,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MoveSubscriptionRule(rule.ID, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.accounting.db.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reloaded.accounting.db.Close() })
	got, exists := reloaded.UserBySubscriptionToken(created.Token)
	policy := reloaded.SubscriptionPolicy()
	if !exists || got.ID != user.ID || len(policy.Rules) != 2 || policy.Rules[1].ID != rule.ID {
		t.Fatalf("reloaded subscription = %#v, exists=%v", got.Subscription, exists)
	}
	if err := reloaded.RevokeUserSubscription(user.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = reloaded.User(user.ID)
	policy = reloaded.SubscriptionPolicy()
	if got.Subscription.Token != "" || len(policy.Rules) != 2 || len(policy.Providers) != 0 {
		t.Fatalf("revoking a bearer link changed the universal policy: user=%#v policy=%#v", got.Subscription, policy)
	}
}

func TestProxyNodeSubscriptionAddressModeIsUserPlaneMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	if EffectiveSubscriptionAddressMode(node.SubscriptionAddressMode) != SubscriptionAddressDual {
		t.Fatalf("legacy/default mode = %q, want dual", node.SubscriptionAddressMode)
	}
	if err := store.SetProxyNodeSubscriptionAddressMode(node.ID, SubscriptionAddressIPv6); err != nil {
		t.Fatal(err)
	}
	after := store.Snapshot()
	if after.Revision != before.Revision || after.UserRevision != before.UserRevision+1 {
		t.Fatalf("revisions = topology %d user %d, want %d/%d", after.Revision, after.UserRevision, before.Revision, before.UserRevision+1)
	}
	updated, exists := store.ProxyNode(node.ID)
	if !exists || updated.SubscriptionAddressMode != SubscriptionAddressIPv6 {
		t.Fatalf("updated Proxy Node = %#v, exists=%v", updated, exists)
	}
	if len(after.AppliedProxyNodes) != 1 || after.AppliedProxyNodes[0].SubscriptionAddressMode != "" {
		t.Fatalf("subscription metadata leaked into applied topology: %#v", after.AppliedProxyNodes)
	}
	if err := store.accounting.db.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reloaded.accounting.db.Close() })
	updated, exists = reloaded.ProxyNode(node.ID)
	if !exists || updated.SubscriptionAddressMode != SubscriptionAddressIPv6 {
		t.Fatalf("reloaded Proxy Node = %#v, exists=%v", updated, exists)
	}
	if err := reloaded.SetProxyNodeSubscriptionAddressMode(node.ID, "invalid"); err == nil {
		t.Fatal("invalid subscription address mode was accepted")
	}
}

func TestUserCredentialAndSubscriptionResetsAreAtomicAndScoped(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.accounting.db.Close() })
	alice, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.CreateUser("bob")
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "archive", RootAgent: "edge-b", Entrance: testTLSEndpoint(ProtocolHysteria2, 8443),
	})
	if err != nil {
		t.Fatal(err)
	}
	firstAlice, err := store.AddMembership(first.ID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	secondAlice, err := store.AddMembership(second.ID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	firstBob, err := store.AddMembership(first.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}

	before := store.Snapshot()
	rotated, err := store.ResetUserCredentials(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	afterCredentials := store.Snapshot()
	if rotated != 2 || afterCredentials.UserRevision != before.UserRevision+1 {
		t.Fatalf("credential reset count/revision = %d/%d, want 2/%d", rotated, afterCredentials.UserRevision, before.UserRevision+1)
	}
	firstAfter, _ := store.ProxyNode(first.ID)
	secondAfter, _ := store.ProxyNode(second.ID)
	if got := membershipForUser(&firstAfter, alice.ID); got == nil || got.Credential.Secret == firstAlice.Credential.Secret {
		t.Fatalf("first Alice credential was not reset: %#v", got)
	}
	if got := membershipForUser(&secondAfter, alice.ID); got == nil || got.Credential.Secret == secondAlice.Credential.Secret {
		t.Fatalf("second Alice credential was not reset: %#v", got)
	}
	if got := membershipForUser(&firstAfter, bob.ID); got == nil || got.Credential.Secret != firstBob.Credential.Secret {
		t.Fatalf("Bob credential changed during Alice reset: %#v", got)
	}
	aliceAfterCredentials, _ := store.User(alice.ID)
	if aliceAfterCredentials.Subscription.Token != alice.Subscription.Token {
		t.Fatal("credential-only reset changed the subscription token")
	}

	firstCredential := membershipForUser(&firstAfter, alice.ID).Credential.Secret
	secondCredential := membershipForUser(&secondAfter, alice.ID).Credential.Secret
	beforeSubscription := store.Snapshot()
	resetSubscription, resetCount, err := store.ResetUserSubscriptionAndCredentials(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	afterSubscription := store.Snapshot()
	if resetCount != 2 || resetSubscription.Token == "" || resetSubscription.Token == alice.Subscription.Token ||
		afterSubscription.UserRevision != beforeSubscription.UserRevision+1 {
		t.Fatalf("subscription reset = %#v count=%d revision=%d", resetSubscription, resetCount, afterSubscription.UserRevision)
	}
	firstAfter, _ = store.ProxyNode(first.ID)
	secondAfter, _ = store.ProxyNode(second.ID)
	if membershipForUser(&firstAfter, alice.ID).Credential.Secret == firstCredential ||
		membershipForUser(&secondAfter, alice.ID).Credential.Secret == secondCredential {
		t.Fatal("subscription reset did not rotate every Alice credential")
	}
	if membershipForUser(&firstAfter, bob.ID).Credential.Secret != firstBob.Credential.Secret {
		t.Fatal("subscription reset changed another user's credential")
	}
}

func TestStatePersistenceFailureRollsBackPreparedAccountingMutation(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.accounting.db.Close() })
	user, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := store.AddMembership(node.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}

	next := store.Snapshot()
	next.ProxyNodes[0].Memberships = nil
	next.UserRevision++
	if err := validateState(next); err != nil {
		t.Fatal(err)
	}
	originalPath := store.path
	store.path = t.TempDir() // Atomic rename onto a directory must fail.
	err = store.persistStateAndAccountingLocked(next, normalizeBuild(store.build, store.now()))
	store.path = originalPath
	if err == nil {
		t.Fatal("state persistence unexpectedly succeeded")
	}
	var count int
	if err := store.accounting.db.QueryRow(
		`SELECT COUNT(*) FROM membership_usage WHERE membership_id = ?`, membership.ID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("membership accounting row count = %d, want 1 after JSON failure", count)
	}
	if current, exists := store.ProxyNode(node.ID); !exists || len(current.Memberships) != 1 {
		t.Fatalf("in-memory state changed after failed atomic commit: %#v", current)
	}
}

func TestUserSubscriptionRejectsInvalidRuleValues(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.accounting.db.Close() })
	_, _ = store.CreateUser("alice")
	if _, err := store.AddSubscriptionRule(SubscriptionRuleInput{
		Match: SubscriptionMatchIPCIDR, Values: []string{"not-a-network"}, Action: SubscriptionDirect,
	}); err == nil {
		t.Fatal("invalid CIDR was accepted")
	}
	if _, err := store.AddSubscriptionRule(SubscriptionRuleInput{
		Match: SubscriptionMatchGeosite, Values: []string{"not/a/category"}, Action: SubscriptionDirect,
	}); err == nil {
		t.Fatal("invalid Geosite category was accepted")
	}
	if _, err := store.AddSubscriptionRule(SubscriptionRuleInput{
		Match: SubscriptionMatchGeosite, Values: []string{"geolocation-!cn", "steam@cn"}, Action: SubscriptionDirect,
	}); err != nil {
		t.Fatalf("valid Geosite categories were rejected: %v", err)
	}
}

func TestSchemaV12DropsRuleProvidersAndProviderRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	build := testBuild()
	build.RecordedAt = now
	legacy := envelope{Schema: SchemaID, SchemaVersion: 12, LastUsedBy: build, Data: State{
		UserRevision: 1, Users: []User{}, ProxyNodes: []ProxyNode{}, AppliedProxyNodes: []ProxyNode{},
		SubscriptionPolicy: SubscriptionPolicy{DefaultAction: SubscriptionProxy, UpdatedAt: now,
			Providers: []SubscriptionProvider{{ID: "spr_12345678901234567890", Name: "legacy", Behavior: SubscriptionProviderDomain, DefaultURL: "https://rules.example/list", UpdateInterval: 86400}},
			Rules: []SubscriptionRule{
				{ID: "sru_12345678901234567890", Order: 0, Match: SubscriptionMatchProvider, Provider: "spr_12345678901234567890", Action: SubscriptionReject},
				{ID: "sru_09876543210987654321", Order: 1, Match: SubscriptionMatchDomainSuffix, Values: []string{"example.com"}, Action: SubscriptionDirect},
			}},
	}}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.accounting.db.Close() })
	policy := store.SubscriptionPolicy()
	if len(policy.Providers) != 0 || len(policy.Rules) != 1 || policy.Rules[0].Order != 0 || policy.Rules[0].Match != SubscriptionMatchDomainSuffix {
		t.Fatalf("migrated policy = %#v", policy)
	}
}

func TestSchemaV11PromotesOneUniversalPolicyAndEnablesExistingUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	build := testBuild()
	build.RecordedAt = now
	legacy := envelope{Schema: SchemaID, SchemaVersion: 11, LastUsedBy: build, Data: State{
		UserRevision: 1, Users: []User{
			{ID: "usr_12345678901234567890", Name: "alice", CreatedAt: now, UpdatedAt: now,
				Subscription: UserSubscription{Token: "sub_12345678901234567890", UpdatedAt: now, DefaultAction: SubscriptionDirect,
					Rules: []SubscriptionRule{{ID: "sru_12345678901234567890", Match: SubscriptionMatchDomainSuffix, Values: []string{"example.com"}, Action: SubscriptionDirect}}}},
			{ID: "usr_09876543210987654321", Name: "bob", CreatedAt: now, UpdatedAt: now},
		}, ProxyNodes: []ProxyNode{}, AppliedProxyNodes: []ProxyNode{},
	}}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.accounting.db.Close() })
	policy := store.SubscriptionPolicy()
	if policy.DefaultAction != SubscriptionDirect || len(policy.Rules) != 1 {
		t.Fatalf("migrated policy = %#v", policy)
	}
	for _, user := range store.Snapshot().Users {
		if user.Subscription.Token == "" || len(user.Subscription.Rules) != 0 || len(user.Subscription.Providers) != 0 || user.Subscription.DefaultAction != "" {
			t.Fatalf("migrated user = %#v", user)
		}
	}
}
