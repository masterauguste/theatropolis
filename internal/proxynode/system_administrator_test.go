package proxynode

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAdministratorProxyAccessDefaultsOffAndIsProtectedWhileEnabled(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	if state.AdministratorProxyAccessEnabled || len(state.Users) != 0 {
		t.Fatalf("initial users = %#v", state.Users)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	created, _ := store.ProxyNode(node.ID)
	if membershipForUser(&created, SystemAdministratorUserID) != nil {
		t.Fatalf("disabled administrator Membership = %#v", created.Memberships)
	}
	beforeRevision := store.Snapshot().UserRevision
	changed, err := store.SetAdministratorProxyAccess(true)
	if err != nil || !changed {
		t.Fatalf("enable administrator access changed=%v err=%v", changed, err)
	}
	state = store.Snapshot()
	if !state.AdministratorProxyAccessEnabled || state.UserRevision != beforeRevision+1 ||
		len(state.Users) != 1 || !IsSystemAdministrator(state.Users[0]) || state.Users[0].Subscription.Token == "" {
		t.Fatalf("enabled state = %#v", state)
	}
	created, _ = store.ProxyNode(node.ID)
	administrator := membershipForUser(&created, SystemAdministratorUserID)
	if administrator == nil || administrator.MonthlyQuotaBytes != 0 || !administrator.SubscriptionEndsAfter.IsZero() ||
		administrator.DisabledReason != MembershipEnabled || administrator.Credential.Secret == "" {
		t.Fatalf("administrator Membership = %#v", administrator)
	}

	conflict := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("%s error = %v, want ErrConflict", name, err)
		}
	}
	conflict("rename", store.RenameUser(SystemAdministratorUserID, "operator"))
	conflict("delete", store.DeleteUser(SystemAdministratorUserID))
	conflict("remove Membership", store.RemoveMembership(node.ID, SystemAdministratorUserID))
	conflict("update plan", store.UpdateMembershipPlan(node.ID, SystemAdministratorUserID, MembershipPlan{MonthlyQuotaBytes: 1}))
	_, err = store.ResetMembershipTraffic(node.ID, SystemAdministratorUserID)
	conflict("reset traffic", err)
	conflict("reset credential", store.ResetMembershipCredential(node.ID, SystemAdministratorUserID))
	_, err = store.RotateUserSubscription(SystemAdministratorUserID)
	conflict("rotate subscription", err)
	conflict("revoke subscription", store.RevokeUserSubscription(SystemAdministratorUserID))

	future, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "archive", RootAgent: "edge-b", Entrance: testTLSEndpoint(ProtocolAnyTLS, 8443),
	})
	if err != nil {
		t.Fatal(err)
	}
	future, _ = store.ProxyNode(future.ID)
	if membershipForUser(&future, SystemAdministratorUserID) == nil {
		t.Fatalf("future Proxy Node has no administrator Membership: %#v", future.Memberships)
	}
	changed, err = store.SetAdministratorProxyAccess(false)
	if err != nil || !changed {
		t.Fatalf("disable administrator access changed=%v err=%v", changed, err)
	}
	state = store.Snapshot()
	if state.AdministratorProxyAccessEnabled || len(state.Users) != 0 {
		t.Fatalf("disabled state = %#v", state)
	}
	for _, current := range state.ProxyNodes {
		if membershipForUser(&current, SystemAdministratorUserID) != nil {
			t.Fatalf("disabled Proxy Node retains administrator Membership: %#v", current)
		}
	}
	beforeRevision = state.UserRevision
	changed, err = store.SetAdministratorProxyAccess(false)
	if err != nil || changed || store.Snapshot().UserRevision != beforeRevision {
		t.Fatalf("no-op disable changed=%v err=%v revision=%d", changed, err, store.Snapshot().UserRevision)
	}
}

func TestSchemaFourteenMigrationKeepsAdministratorProxyAccessOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
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
	state := store.Snapshot()
	beforeRevision := state.UserRevision
	legacy := envelope{
		Schema: SchemaID, SchemaVersion: 14,
		LastUsedBy: normalizeBuild(testBuild(), time.Now()), Data: state,
	}
	encoded, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	migratedState := migrated.Snapshot()
	if migratedState.UserRevision != beforeRevision+1 || migratedState.AdministratorProxyAccessEnabled {
		t.Fatalf("migrated state = %#v", migratedState)
	}
	if administrator, exists := migrated.User(SystemAdministratorUserID); exists {
		t.Fatalf("migrated administrator = %#v", administrator)
	}
	migratedNode, _ := migrated.ProxyNode(node.ID)
	if membershipForUser(&migratedNode, SystemAdministratorUserID) != nil {
		t.Fatalf("migrated Proxy Node has administrator Membership: %#v", migratedNode.Memberships)
	}
	if err := migrated.MarkReady(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted envelope
	if err := json.Unmarshal(contents, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.SchemaVersion != SchemaVersion {
		t.Fatalf("persisted schema = %d, want %d", persisted.SchemaVersion, SchemaVersion)
	}
}

func TestSchemaFifteenPreviewPreservesEnabledAdministratorAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
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
	if _, err := store.SetAdministratorProxyAccess(true); err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	state.AdministratorProxyAccessEnabled = false
	legacy := envelope{
		Schema: SchemaID, SchemaVersion: 15,
		LastUsedBy: normalizeBuild(testBuild(), time.Now()), Data: state,
	}
	encoded, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	migratedState := migrated.Snapshot()
	if !migratedState.AdministratorProxyAccessEnabled {
		t.Fatal("schema v15 administrator access was disabled")
	}
	migratedNode, _ := migrated.ProxyNode(node.ID)
	if membershipForUser(&migratedNode, SystemAdministratorUserID) == nil {
		t.Fatalf("migrated Proxy Node has no administrator Membership: %#v", migratedNode.Memberships)
	}
}

func TestEntranceUsageForAgentExcludesUnlimitedTrafficAndDeduplicatesUsers(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := store.CreateUser("alice")
	bob, _ := store.CreateUser("bob")
	carol, _ := store.CreateUser("carol")
	first, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	second, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "archive", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 8443),
	})
	third, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "remote", RootAgent: "edge-b", Entrance: testTLSEndpoint(ProtocolAnyTLS, 9443),
	})
	firstFinite, _ := store.AddMembershipWithPlan(first.ID, alice.ID, MembershipPlan{MonthlyQuotaBytes: 100})
	secondFinite, _ := store.AddMembershipWithPlan(second.ID, alice.ID, MembershipPlan{MonthlyQuotaBytes: 200})
	_, _ = store.AddMembership(first.ID, bob.ID)
	_, _ = store.AddMembership(second.ID, bob.ID)
	_, _ = store.AddMembershipWithPlan(third.ID, carol.ID, MembershipPlan{MonthlyQuotaBytes: 900})
	if err := store.mutateBilling(func(state *State) (bool, error) {
		for nodeIndex := range state.ProxyNodes {
			for membershipIndex := range state.ProxyNodes[nodeIndex].Memberships {
				membership := &state.ProxyNodes[nodeIndex].Memberships[membershipIndex]
				switch membership.ID {
				case firstFinite.ID:
					membership.UsedBytes = 40
				case secondFinite.ID:
					membership.UsedBytes = 70
				default:
					if membership.MonthlyQuotaBytes == 0 {
						membership.UsedBytes = 999
					}
				}
			}
		}
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a", "edge-b"}); err != nil {
		t.Fatal(err)
	}

	usage, err := store.EntranceUsageForAgent("edge-a")
	if err != nil {
		t.Fatal(err)
	}
	if usage.AllocatedBytes != 300 || usage.UsedBytes != 110 || usage.UnlimitedUsers != 1 {
		t.Fatalf("edge-a usage = %#v", usage)
	}
	other, err := store.EntranceUsageForAgent("edge-b")
	if err != nil {
		t.Fatal(err)
	}
	if other.AllocatedBytes != 900 || other.UsedBytes != 0 || other.UnlimitedUsers != 0 {
		t.Fatalf("edge-b usage = %#v", other)
	}
	if _, err := store.SetAdministratorProxyAccess(true); err != nil {
		t.Fatal(err)
	}
	usage, _ = store.EntranceUsageForAgent("edge-a")
	other, _ = store.EntranceUsageForAgent("edge-b")
	if usage.UnlimitedUsers != 2 || other.UnlimitedUsers != 1 {
		t.Fatalf("enabled administrator usage edge-a=%#v edge-b=%#v", usage, other)
	}
	if _, err := store.EntranceUsageForAgent("invalid agent id!"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid Agent ID error = %v", err)
	}
}

func TestEntranceUsageFollowsAppliedEntranceDuringPendingMove(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
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
	if _, err := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{MonthlyQuotaBytes: 100}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	if err := store.MoveHop(node.ID, node.Entrance.HopID, "edge-b"); err != nil {
		t.Fatal(err)
	}

	oldUsage, err := store.EntranceUsageForAgent("edge-a")
	if err != nil {
		t.Fatal(err)
	}
	newUsage, err := store.EntranceUsageForAgent("edge-b")
	if err != nil {
		t.Fatal(err)
	}
	if oldUsage.AllocatedBytes != 100 || newUsage.AllocatedBytes != 0 {
		t.Fatalf("pending move usage old=%#v new=%#v", oldUsage, newUsage)
	}

	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-b"}); err != nil {
		t.Fatal(err)
	}
	oldUsage, _ = store.EntranceUsageForAgent("edge-a")
	newUsage, _ = store.EntranceUsageForAgent("edge-b")
	if oldUsage.AllocatedBytes != 0 || newUsage.AllocatedBytes != 100 {
		t.Fatalf("committed move usage old=%#v new=%#v", oldUsage, newUsage)
	}
}
