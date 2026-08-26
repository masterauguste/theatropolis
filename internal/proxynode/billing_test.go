package proxynode

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSchemaSevenAccountingMigratesOnceIntoSQLite(t *testing.T) {
	directory := t.TempDir()
	seedPath := filepath.Join(directory, "seed.json")
	seed, err := Open(seedPath, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2028, time.February, 2, 12, 0, 0, 0, time.UTC)
	seed.now = func() time.Time { return now }
	user, _ := seed.CreateUser("alice")
	node, _ := seed.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if _, err := seed.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{MonthlyQuotaBytes: 1000}); err != nil {
		t.Fatal(err)
	}
	state := seed.Snapshot()
	state.ProxyNodes[0].Memberships[0].UsedBytes = 321
	state.AccountingFailures = []AccountingFailure{{
		AgentID: "edge-a", Reason: AccountingFailureCollection, OccurredAt: now,
	}}
	legacy := envelope{
		Schema: SchemaID, SchemaVersion: 7,
		LastUsedBy: normalizeBuild(testBuild(), now), Data: state,
	}
	contents, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(directory, "legacy.json")
	if err := os.WriteFile(legacyPath, append(contents, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(legacyPath, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	migratedNode, _ := migrated.ProxyNode(node.ID)
	if migratedNode.Memberships[0].UsedBytes != 321 || len(migrated.Snapshot().AccountingFailures) != 1 {
		t.Fatalf("migrated accounting state = %#v", migrated.Snapshot())
	}
	if err := migrated.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if err := migrated.accounting.db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(legacyPath, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if failures := reopened.Snapshot().AccountingFailures; len(failures) != 1 {
		t.Fatalf("accounting failures were imported more than once: %#v", failures)
	}
}

func TestCorruptAccountingDatabaseFailsClosed(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(statePath, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.accounting.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accountingPath(statePath), []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(statePath, testBuild()); err == nil {
		t.Fatal("corrupt accounting database was silently replaced or accepted")
	}
}

func TestRetiredMembershipAccountingIsDeleted(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
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
		Name: "theatre", RootAgent: "edge-b", Entrance: testTLSEndpoint(ProtocolAnyTLS, 8443),
	})
	aliceGrant, err := store.AddMembership(first.ID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	bobGrant, err := store.AddMembership(first.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	carolGrant, err := store.AddMembership(second.ID, carol.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{aliceGrant.ID, bobGrant.ID, carolGrant.ID} {
		if got := accountingMembershipRowCount(t, store, id); got != 1 {
			t.Fatalf("accounting rows for live membership %q = %d", id, got)
		}
	}

	if err := store.RemoveMembership(first.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	if got := accountingMembershipRowCount(t, store, aliceGrant.ID); got != 0 {
		t.Fatalf("revoked membership retained %d accounting rows", got)
	}
	if err := store.DeleteUser(bob.ID); err != nil {
		t.Fatal(err)
	}
	if got := accountingMembershipRowCount(t, store, bobGrant.ID); got != 0 {
		t.Fatalf("deleted user's membership retained %d accounting rows", got)
	}
	if err := store.DeleteProxyNode(second.ID); err != nil {
		t.Fatal(err)
	}
	if got := accountingMembershipRowCount(t, store, carolGrant.ID); got != 0 {
		t.Fatalf("deleted Proxy Node membership retained %d accounting rows", got)
	}
}

func TestStartupPrunesInterruptedMembershipCleanup(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(statePath, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.accounting.db.Exec(
		`INSERT INTO membership_usage(membership_id, used_bytes, period_started_at, resets_after, updated_at)
		 VALUES ('mem_retired', '12', 1, 2, 3)`,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.accounting.db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(statePath, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if got := accountingMembershipRowCount(t, reopened, "mem_retired"); got != 0 {
		t.Fatalf("startup retained %d interrupted accounting rows", got)
	}
}

func accountingMembershipRowCount(t *testing.T, store *Store, membershipID string) int {
	t.Helper()
	var count int
	if err := store.accounting.db.QueryRow(
		`SELECT COUNT(*) FROM membership_usage WHERE membership_id = ?`, membershipID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestAccountingPersistsInSQLiteWithoutRewritingTopologyJSON(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "proxy-node-state.json")
	store, err := Open(statePath, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2028, time.February, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if _, err := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{MonthlyQuotaBytes: 100}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := listenerKeys("edge-a", node.Entrance.Endpoint)
	path := "/tp-in-" + shortDigest(key)
	if err := store.RecordAccountingFailure("edge-a", AccountingFailureCollection, now); err != nil {
		t.Fatal(err)
	}
	changed, err := store.ApplyTrafficDeltaReport("edge-a", now, []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 101,
	}})
	if err != nil || !changed {
		t.Fatalf("traffic delta changed=%v err=%v", changed, err)
	}
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("high-frequency accounting rewrote the topology JSON")
	}
	if info, err := os.Stat(accountingPath(statePath)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("accounting database info=%v err=%v", info, err)
	}
	wantRevision := store.Snapshot().UserRevision
	if err := store.accounting.db.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(statePath, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	reloadedNode, _ := reloaded.ProxyNode(node.ID)
	if reloadedNode.Memberships[0].UsedBytes != 101 ||
		reloadedNode.Memberships[0].DisabledReason != MembershipQuotaReached ||
		reloaded.Snapshot().UserRevision != wantRevision ||
		len(reloaded.Snapshot().AccountingFailures) != 1 {
		t.Fatalf("reloaded SQL accounting state = %#v", reloaded.Snapshot())
	}
}

func TestRemnawaveStyleTrafficResetRunsAtTenMinutesAfterMidnight(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2028, time.February, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if _, err := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	key, _, _ := listenerKeys("edge-a", node.Entrance.Endpoint)
	path := "/tp-in-" + shortDigest(key)
	if _, err := store.ApplyTrafficDeltaReport("edge-a", now, []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 50,
	}}); err != nil {
		t.Fatal(err)
	}
	resetDay := time.Date(2028, time.March, 3, 0, 0, 0, 0, time.UTC)
	if changed, err := store.advanceSubscriptions(resetDay); err != nil || changed {
		t.Fatalf("midnight subscription pass changed=%v err=%v", changed, err)
	}
	current, _ := store.ProxyNode(node.ID)
	if current.Memberships[0].UsedBytes != 50 {
		t.Fatal("midnight subscription pass reset traffic before 00:10")
	}
	if _, err := store.advanceTrafficPeriods(resetDay.Add(10 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	current, _ = store.ProxyNode(node.ID)
	if current.Memberships[0].UsedBytes != 0 {
		t.Fatal("00:10 traffic pass did not reset the rolling period")
	}
}

func TestTrafficAtPeriodBoundaryIsAttributedOnlyToCurrentPeriod(t *testing.T) {
	boundary := time.Date(2028, time.April, 1, 0, 0, 0, 0, time.UTC)
	previous := boundary.Add(-time.Hour)
	current := boundary.Add(time.Hour)
	if got := trafficInsideCurrentPeriod(1000, previous, current, boundary); got != 500 {
		t.Fatalf("cross-boundary traffic = %d, want 500", got)
	}
	if got := trafficInsideCurrentPeriod(1000, previous, boundary, boundary); got != 0 {
		t.Fatalf("pre-boundary traffic = %d, want 0", got)
	}
	if got := trafficInsideCurrentPeriod(1000, boundary, current, boundary); got != 1000 {
		t.Fatalf("current-period traffic = %d, want 1000", got)
	}
}

func TestAuthenticatedUserLabelsAreBoundedAndMembershipStable(t *testing.T) {
	left := AuthenticatedUserLabel(strings.Repeat("p", 96), strings.Repeat("u", 96), "mem_AAAAAAAAAAAA11111111")
	right := AuthenticatedUserLabel(strings.Repeat("p", 96), strings.Repeat("u", 96), "mem_BBBBBBBBBBBB22222222")
	if len(left) > 128 || len(right) > 128 || left == right ||
		!strings.HasSuffix(left, "-m-AAAAAAAAAAAA") || !strings.HasSuffix(right, "-m-BBBBBBBBBBBB") {
		t.Fatalf("authenticated labels = %q, %q", left, right)
	}
}

func TestTrafficQuotaDisablesMembershipAndCalendarResetReenablesIt(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2028, time.February, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	membership, err := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{MonthlyQuotaBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	key, _, _ := listenerKeys("edge-a", node.Entrance.Endpoint)
	path := "/tp-in-" + shortDigest(key)
	changed, err := store.ApplyTrafficReport("edge-a", "epoch-1", now, []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 400, DownlinkBytes: 100,
	}})
	if err != nil || changed {
		t.Fatalf("first report changed=%v err=%v", changed, err)
	}
	changed, err = store.ApplyTrafficReport("edge-a", "epoch-1", now.Add(time.Minute), []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 900, DownlinkBytes: 300,
	}})
	if err != nil || !changed {
		t.Fatalf("quota report changed=%v err=%v", changed, err)
	}
	updated, _ := store.ProxyNode(node.ID)
	if updated.Memberships[0].UsedBytes != 1200 || updated.Memberships[0].DisabledReason != MembershipQuotaReached {
		t.Fatalf("membership after quota = %#v", updated.Memberships[0])
	}
	compiled, err := Compile(store.Snapshot(), testResolver{"edge-a": "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(compiled.Configs["edge-a"], []byte("cinema-alice")) {
		t.Fatal("quota-disabled user remained in compiled configuration")
	}

	changed, err = store.AdvanceBilling(time.Date(2028, time.March, 3, 0, 0, 0, 0, time.UTC))
	if err != nil || !changed {
		t.Fatalf("calendar reset changed=%v err=%v", changed, err)
	}
	updated, _ = store.ProxyNode(node.ID)
	if updated.Memberships[0].UsedBytes != 0 || updated.Memberships[0].DisabledReason != MembershipEnabled {
		t.Fatalf("membership after reset = %#v; original=%#v", updated.Memberships[0], membership)
	}
}

func TestTrafficDeltaReportsAreAddedDirectlyAndRetireLegacyBaseline(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2028, time.February, 2, 12, 0, 0, 0, time.UTC)
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if _, err := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{MonthlyQuotaBytes: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	key, _, _ := listenerKeys("edge-a", node.Entrance.Endpoint)
	path := "/tp-in-" + shortDigest(key)
	if _, err := store.ApplyTrafficReport("edge-a", "legacy-epoch", now, []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 100,
	}}); err != nil {
		t.Fatal(err)
	}
	changed, err := store.ApplyTrafficDeltaReport("edge-a", now.Add(30*time.Second), []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 400, DownlinkBytes: 100,
	}})
	if err != nil || changed {
		t.Fatalf("first delta changed=%v err=%v", changed, err)
	}
	changed, err = store.ApplyTrafficDeltaReport("edge-a", now.Add(time.Minute), []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 300, DownlinkBytes: 200,
	}})
	if err != nil || !changed {
		t.Fatalf("second delta changed=%v err=%v", changed, err)
	}
	updated, _ := store.ProxyNode(node.ID)
	if updated.Memberships[0].UsedBytes != 1100 || updated.Memberships[0].DisabledReason != MembershipQuotaReached {
		t.Fatalf("membership after deltas = %#v", updated.Memberships[0])
	}
	if observations := store.Snapshot().TrafficObservations; len(observations) != 0 {
		t.Fatalf("legacy observations after delta cutover = %#v", observations)
	}
}

func TestAccountingFailureHistoryIsNonSensitiveAndRevisionNeutral(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	now := time.Date(2028, time.April, 5, 0, 0, 0, 0, time.UTC)
	if err := store.RecordAccountingFailure("edge-a", AccountingFailureCollection, now); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAccountingFailure("edge-a", AccountingFailurePersistence, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	after := store.Snapshot()
	if after.Revision != before.Revision || after.UserRevision != before.UserRevision ||
		len(after.AccountingFailures) != 2 || after.AccountingFailures[0].Reason != AccountingFailureCollection ||
		after.AccountingFailures[1].Reason != AccountingFailurePersistence {
		t.Fatalf("accounting failure history = %#v", after.AccountingFailures)
	}
	if err := store.RecordAccountingFailure("edge-a", "raw secret-bearing diagnostic", now); err == nil {
		t.Fatal("arbitrary accounting diagnostic was persisted")
	}
}

func TestAccountingFailureIgnoresEmptyEntrancesAndChildOnlyAgents(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if _, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID,
		ChildName:   "relay",
		ChildAgent:  "edge-b",
		Endpoint:    testTLSEndpoint(ProtocolAnyTLS, 8443),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a", "edge-b"}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2028, time.April, 5, 0, 0, 0, 0, time.UTC)
	if err := store.RecordAccountingFailure("edge-a", AccountingFailureCollection, now); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAccountingFailure("edge-b", AccountingFailureCollection, now); err != nil {
		t.Fatal(err)
	}
	if failures := store.Snapshot().AccountingFailures; len(failures) != 0 {
		t.Fatalf("empty topology accounting failures = %#v", failures)
	}

	user, _ := store.CreateUser("alice")
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAccountingFailure("edge-b", AccountingFailureCollection, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAccountingFailure("edge-a", AccountingFailureCollection, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	failures := store.Snapshot().AccountingFailures
	if len(failures) != 1 || failures[0].AgentID != "edge-a" {
		t.Fatalf("membership topology accounting failures = %#v", failures)
	}
}

func TestRegrantContinuesTrafficBaselineWithoutRechargingHistory(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2028, time.February, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	key, _, _ := listenerKeys("edge-a", node.Entrance.Endpoint)
	path := "/tp-in-" + shortDigest(key)
	if _, err := store.ApplyTrafficReport("edge-a", "epoch-1", now, []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 50,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyTrafficReport("edge-a", "epoch-1", now.Add(time.Minute), []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 50,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyTrafficReport("edge-a", "epoch-1", now.Add(2*time.Minute), []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 70,
	}}); err != nil {
		t.Fatal(err)
	}
	updated, _ := store.ProxyNode(node.ID)
	if updated.Memberships[0].UsedBytes != 20 {
		t.Fatalf("re-granted membership usage = %d, want only the 20-byte delta", updated.Memberships[0].UsedBytes)
	}
}

func TestTrafficObservationsPruneAfterRetiredIdentityLeavesAgentReport(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2028, time.February, 2, 12, 0, 0, 0, time.UTC)
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	key, _, _ := listenerKeys("edge-a", node.Entrance.Endpoint)
	path := "/tp-in-" + shortDigest(key)
	usage := []UserTraffic{{InboundPath: path, Username: "cinema-alice", UplinkBytes: 50}}
	if _, err := store.ApplyTrafficReport("edge-a", "epoch-1", now, usage); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyTrafficReport("edge-a", "epoch-1", now.Add(time.Minute), usage); err != nil {
		t.Fatal(err)
	}
	if len(store.Snapshot().TrafficObservations) != 1 {
		t.Fatal("retired identity baseline disappeared before Agent acknowledgement")
	}
	if _, err := store.ApplyTrafficReport("edge-a", "epoch-1", now.Add(2*time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	if observations := store.Snapshot().TrafficObservations; len(observations) != 0 {
		t.Fatalf("retired traffic observations = %#v, want none", observations)
	}
}

func TestRoutingMutationCannotReactivateQuotaDisabledMembership(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2028, time.February, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	_, _, rule, err := store.AddBranch(node.ID, AddBranchInput{
		AddLinkInput: AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildName: "exit", ChildAgent: "edge-b",
			Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443), Final: Target{Type: TargetDirect},
		},
		Match: MatchDomain, Values: []string{"old.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{MonthlyQuotaBytes: 100}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a", "edge-b"}); err != nil {
		t.Fatal(err)
	}
	key, _, _ := listenerKeys("edge-a", node.Entrance.Endpoint)
	path := "/tp-in-" + shortDigest(key)
	if changed, err := store.ApplyTrafficReport("edge-a", "epoch-1", now, []UserTraffic{{
		InboundPath: path, Username: "cinema-alice", UplinkBytes: 101,
	}}); err != nil || !changed {
		t.Fatalf("quota report changed=%v err=%v", changed, err)
	}

	// Routing forms contain only routing fields. Their mutation is applied to
	// a clone of the latest locked state, so an edit begun before the traffic
	// report cannot overwrite the newer membership status.
	if err := store.UpdateRule(node.ID, rule.ID, UpdateRuleInput{
		LinkID: findRuleLinkID(store.Snapshot(), node.ID, rule.ID),
		Match:  MatchDomain, Values: []string{"new.example"},
	}); err != nil {
		t.Fatal(err)
	}
	updated, _ := store.ProxyNode(node.ID)
	if updated.Memberships[0].DisabledReason != MembershipQuotaReached {
		t.Fatalf("routing edit changed membership status to %q", updated.Memberships[0].DisabledReason)
	}
	compiled, err := compileTopologyDeployment(store.Snapshot(), testResolver{
		"edge-a": "203.0.113.10", "edge-b": "203.0.113.11",
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(compiled.Configs["edge-a"], []byte("cinema-alice")) {
		t.Fatal("routing deployment reintroduced quota-disabled user")
	}
}

func findRuleLinkID(state State, nodeID, ruleID string) string {
	for _, node := range state.ProxyNodes {
		if node.ID != nodeID {
			continue
		}
		for _, link := range node.Links {
			for _, rule := range link.Rules {
				if rule.ID == ruleID {
					return link.ID
				}
			}
		}
	}
	return ""
}

func TestSubscriptionEndsAfterInclusiveCalendarDate(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	now := time.Date(2028, time.March, 4, 9, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	membership, err := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{SubscriptionMonths: 1})
	if err != nil {
		t.Fatal(err)
	}
	wantEnd := time.Date(2028, time.April, 4, 0, 0, 0, 0, time.UTC)
	if !membership.SubscriptionEndsAfter.Equal(wantEnd) {
		t.Fatalf("subscription ends after %v, want %v", membership.SubscriptionEndsAfter, wantEnd)
	}
	changed, err := store.AdvanceBilling(wantEnd.Add(23 * time.Hour))
	if err != nil || changed {
		t.Fatalf("end-date check changed=%v err=%v", changed, err)
	}
	changed, err = store.AdvanceBilling(wantEnd.AddDate(0, 0, 1))
	if err != nil || !changed {
		t.Fatalf("next-midnight check changed=%v err=%v", changed, err)
	}
	updated, _ := store.ProxyNode(node.ID)
	if updated.Memberships[0].DisabledReason != MembershipExpired {
		t.Fatalf("membership status = %q", updated.Memberships[0].DisabledReason)
	}
}

func TestCalendarMonthClampsEndOfMonth(t *testing.T) {
	start := time.Date(2028, time.January, 31, 0, 0, 0, 0, time.UTC)
	if got, want := addCalendarMonths(start, 1), time.Date(2028, time.February, 29, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("January 31 + one month = %v, want %v", got, want)
	}
	if got, want := addCalendarMonthsAnchored(time.Date(2028, time.February, 29, 0, 0, 0, 0, time.UTC), 1, 31), time.Date(2028, time.March, 31, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("next anchored month = %v, want %v", got, want)
	}
}
