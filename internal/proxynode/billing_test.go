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

func TestAccountingSchemaOnePeriodsMigrateToUTCPlusEight(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(statePath, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	membership, err := store.AddMembership(node.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	legacyStart := time.Date(2028, time.February, 2, 0, 0, 0, 0, time.UTC)
	legacyReset := time.Date(2028, time.March, 2, 0, 0, 0, 0, time.UTC)
	if _, err := store.accounting.db.Exec(
		`UPDATE membership_usage SET period_started_at = ?, resets_after = ? WHERE membership_id = ?`,
		legacyStart.Unix(), legacyReset.Unix(), membership.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.accounting.db.Exec(
		`UPDATE accounting_meta SET value = '1' WHERE key = 'schema_version'`,
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
	updated, _ := reopened.ProxyNode(node.ID)
	got := updated.Memberships[0]
	if want := time.Date(2028, time.February, 2, 0, 0, 0, 0, billingLocation); !got.QuotaPeriodStartedOn.Equal(want) {
		t.Fatalf("period start = %v, want %v", got.QuotaPeriodStartedOn, want)
	}
	if want := time.Date(2028, time.March, 2, 0, 0, 0, 0, billingLocation); !got.QuotaResetsAfter.Equal(want) {
		t.Fatalf("reset boundary = %v, want %v", got.QuotaResetsAfter, want)
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

func TestDailyUsageUsesUTCPlusEightAndSurvivesTrafficReset(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2028, time.February, 3, 2, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	membership, err := store.AddMembership(node.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"edge-a"}); err != nil {
		t.Fatal(err)
	}
	key, _, _ := listenerKeys("edge-a", node.Entrance.Endpoint)
	path := "/tp-in-" + shortDigest(key)
	report := func(at time.Time, bytes uint64) {
		t.Helper()
		if _, err := store.ApplyTrafficDeltaReport("edge-a", at, []UserTraffic{{
			InboundPath: path, Username: "cinema-alice", UplinkBytes: bytes,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	report(time.Date(2028, time.February, 2, 15, 59, 0, 0, time.UTC), 100)
	report(time.Date(2028, time.February, 2, 16, 1, 0, 0, time.UTC), 200)
	report(time.Date(2028, time.February, 2, 18, 0, 0, 0, time.UTC), 50)

	usage, err := store.UserDailyUsage(user.ID, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 2 || usage[0].Date.Day() != 3 || usage[0].UsedBytes != 250 ||
		usage[1].Date.Day() != 2 || usage[1].UsedBytes != 100 {
		t.Fatalf("daily usage = %#v", usage)
	}
	if _, err := store.ResetMembershipTraffic(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	usage, err = store.UserDailyUsage(user.ID, 30)
	if err != nil || len(usage) != 2 || usage[0].UsedBytes != 250 {
		t.Fatalf("daily usage after reset = %#v err=%v", usage, err)
	}
	if err := store.RemoveMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := store.accounting.db.QueryRow(
		`SELECT COUNT(*) FROM daily_membership_usage WHERE membership_id = ?`, membership.ID,
	).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("retired membership retained %d daily rows", rows)
	}
}

func TestClearAccountingFailuresIsDurableAndRevisionNeutral(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(statePath, testBuild())
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
	if err := store.RecordAccountingFailure("edge-a", AccountingFailureCollection, now); err != nil {
		t.Fatal(err)
	}
	revision := store.Snapshot().UserRevision
	if err := store.ClearAccountingFailures(); err != nil {
		t.Fatal(err)
	}
	if snapshot := store.Snapshot(); len(snapshot.AccountingFailures) != 0 || snapshot.UserRevision != revision {
		t.Fatalf("cleared accounting state = %#v", snapshot)
	}
	if err := store.accounting.db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(statePath, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if failures := reopened.Snapshot().AccountingFailures; len(failures) != 0 {
		t.Fatalf("cleared failures returned after reopen: %#v", failures)
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
	resetDay := time.Date(2028, time.March, 3, 0, 0, 0, 0, billingLocation)
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
	if updated.Memberships[0].Credential != membership.Credential {
		t.Fatalf("quota enforcement rotated credential: got %#v want %#v", updated.Memberships[0].Credential, membership.Credential)
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
	if updated.Memberships[0].Credential != membership.Credential {
		t.Fatalf("quota reset rotated credential: got %#v want %#v", updated.Memberships[0].Credential, membership.Credential)
	}
	restored, err := Compile(store.Snapshot(), testResolver{"edge-a": "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(restored.Configs["edge-a"], []byte(membership.Credential.Secret)) {
		t.Fatal("quota reset did not restore the stable credential")
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

func TestCalendarMonthSubscriptionExpiresAfterInclusiveEndDate(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	now := time.Date(2028, time.March, 4, 9, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	membership, err := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{
		SubscriptionValue: 1, SubscriptionUnit: SubscriptionMonths,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantEnd := time.Date(2028, time.April, 5, 0, 0, 0, 0, billingLocation)
	if !membership.SubscriptionEndsAfter.Equal(wantEnd) {
		t.Fatalf("subscription ends after %v, want %v", membership.SubscriptionEndsAfter, wantEnd)
	}
	changed, err := store.AdvanceBilling(wantEnd.Add(-time.Second))
	if err != nil || changed {
		t.Fatalf("end-date check changed=%v err=%v", changed, err)
	}
	changed, err = store.AdvanceBilling(wantEnd)
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
	if got, want := addCalendarMonths(start, 1), time.Date(2028, time.February, 29, 0, 0, 0, 0, billingLocation); !got.Equal(want) {
		t.Fatalf("January 31 + one month = %v, want %v", got, want)
	}
	if got, want := addCalendarMonthsAnchored(time.Date(2028, time.February, 29, 0, 0, 0, 0, billingLocation), 1, 31), time.Date(2028, time.March, 31, 0, 0, 0, 0, billingLocation); !got.Equal(want) {
		t.Fatalf("next anchored month = %v, want %v", got, want)
	}
}

func TestSubscriptionDurationUnits(t *testing.T) {
	now := time.Date(2028, time.March, 4, 9, 17, 23, 0, time.UTC)
	tests := []struct {
		name  string
		value int
		unit  SubscriptionUnit
		want  time.Time
	}{
		{name: "minutes", value: 15, unit: SubscriptionMinutes, want: now.Add(15 * time.Minute)},
		{name: "hours", value: 6, unit: SubscriptionHours, want: now.Add(6 * time.Hour)},
		{name: "days", value: 3, unit: SubscriptionDays, want: now.Add(72 * time.Hour)},
		{name: "months", value: 1, unit: SubscriptionMonths, want: time.Date(2028, time.April, 5, 0, 0, 0, 0, billingLocation)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, _ := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
			store.now = func() time.Time { return now }
			user, _ := store.CreateUser("alice")
			node, _ := store.CreateProxyNode(CreateProxyNodeInput{
				Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
			})
			membership, err := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{
				SubscriptionValue: test.value, SubscriptionUnit: test.unit,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !membership.SubscriptionEndsAfter.Equal(test.want) ||
				membership.SubscriptionValue != test.value || membership.SubscriptionUnit != test.unit {
				t.Fatalf("subscription = %#v, want deadline %v and %d %s", membership, test.want, test.value, test.unit)
			}
			if changed, err := store.AdvanceBilling(test.want.Add(-time.Second)); err != nil || changed {
				t.Fatalf("subscription changed before deadline: changed=%v err=%v", changed, err)
			}
			if changed, err := store.AdvanceBilling(test.want); err != nil || !changed {
				t.Fatalf("subscription did not expire at deadline: changed=%v err=%v", changed, err)
			}
		})
	}
}

func TestSchemaEightSubscriptionMigrationPreservesLastValidDay(t *testing.T) {
	state := State{ProxyNodes: []ProxyNode{{Memberships: []Membership{{
		LegacySubscriptionMonths: 1,
		CreatedAt:                time.Date(2028, time.March, 4, 9, 0, 0, 0, time.UTC),
		SubscriptionEndsAfter:    time.Date(2028, time.April, 4, 0, 0, 0, 0, time.UTC),
	}}}}}
	migrateSchemaV8(&state)
	membership := state.ProxyNodes[0].Memberships[0]
	if membership.LegacySubscriptionMonths != 0 || membership.SubscriptionValue != 1 ||
		membership.SubscriptionUnit != SubscriptionMonths ||
		!membership.SubscriptionStartedAt.Equal(time.Date(2028, time.March, 4, 9, 0, 0, 0, time.UTC)) ||
		!membership.SubscriptionEndsAfter.Equal(time.Date(2028, time.April, 5, 0, 0, 0, 0, billingLocation)) {
		t.Fatalf("migrated subscription = %#v", membership)
	}
}

func TestExtendSubscriptionPreservesTrafficPeriod(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	now := time.Date(2028, time.March, 4, 9, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	membership, err := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{
		MonthlyQuotaBytes: 100, SubscriptionValue: 2, SubscriptionUnit: SubscriptionHours,
	})
	if err != nil {
		t.Fatal(err)
	}
	periodStart, resetAt := membership.QuotaPeriodStartedOn, membership.QuotaResetsAfter
	now = now.Add(30 * time.Minute)
	if err := store.ExtendMembershipSubscription(node.ID, user.ID, 3, SubscriptionDays); err != nil {
		t.Fatal(err)
	}
	updated, _ := store.ProxyNode(node.ID)
	membership = updated.Memberships[0]
	if want := time.Date(2028, time.March, 7, 11, 0, 0, 0, time.UTC); !membership.SubscriptionEndsAfter.Equal(want) {
		t.Fatalf("extended deadline = %v, want %v", membership.SubscriptionEndsAfter, want)
	}
	if !membership.QuotaPeriodStartedOn.Equal(periodStart) || !membership.QuotaResetsAfter.Equal(resetAt) {
		t.Fatalf("extension changed traffic period: %#v", membership)
	}
}

func TestProxyNodeCompensationExtendsOnlyFiniteSubscriptions(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	now := time.Date(2028, time.March, 4, 9, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	finiteUser, _ := store.CreateUser("finite")
	unselectedUser, _ := store.CreateUser("unselected")
	unlimitedUser, _ := store.CreateUser("unlimited")
	expiredUser, _ := store.CreateUser("expired")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	finite, _ := store.AddMembershipWithPlan(node.ID, finiteUser.ID, MembershipPlan{
		SubscriptionValue: 2, SubscriptionUnit: SubscriptionHours,
	})
	unselected, _ := store.AddMembershipWithPlan(node.ID, unselectedUser.ID, MembershipPlan{
		SubscriptionValue: 2, SubscriptionUnit: SubscriptionHours,
	})
	unlimited, _ := store.AddMembershipWithPlan(node.ID, unlimitedUser.ID, MembershipPlan{})
	expired, _ := store.AddMembershipWithPlan(node.ID, expiredUser.ID, MembershipPlan{
		SubscriptionValue: 1, SubscriptionUnit: SubscriptionMinutes,
	})
	now = now.Add(10 * time.Minute)
	if changed, err := store.advanceSubscriptions(now); err != nil || !changed {
		t.Fatalf("expire short subscription changed=%v err=%v", changed, err)
	}

	extended, err := store.ExtendProxyNodeSubscriptions(
		node.ID, []string{finite.ID, expired.ID}, 1, SubscriptionHours,
	)
	if err != nil || extended != 2 {
		t.Fatalf("ExtendProxyNodeSubscriptions() extended=%d err=%v", extended, err)
	}
	updated, _ := store.ProxyNode(node.ID)
	byUser := make(map[string]Membership, len(updated.Memberships))
	for _, membership := range updated.Memberships {
		byUser[membership.UserID] = membership
	}
	if got := byUser[finiteUser.ID]; !got.SubscriptionEndsAfter.Equal(finite.SubscriptionEndsAfter.Add(time.Hour)) {
		t.Fatalf("finite deadline = %v", got.SubscriptionEndsAfter)
	}
	if got := byUser[unselectedUser.ID]; !got.SubscriptionEndsAfter.Equal(unselected.SubscriptionEndsAfter) {
		t.Fatalf("unselected finite membership changed = %#v", got)
	}
	if got := byUser[unlimitedUser.ID]; !got.SubscriptionEndsAfter.IsZero() || got.Credential != unlimited.Credential {
		t.Fatalf("unlimited membership changed = %#v", got)
	}
	if got := byUser[expiredUser.ID]; !got.SubscriptionEndsAfter.Equal(expired.SubscriptionEndsAfter.Add(time.Hour)) ||
		got.DisabledReason != MembershipEnabled {
		t.Fatalf("expired compensated membership = %#v", got)
	}
	for _, membership := range updated.Memberships {
		var original Membership
		switch membership.UserID {
		case finiteUser.ID:
			original = finite
		case unlimitedUser.ID:
			original = unlimited
		case unselectedUser.ID:
			original = unselected
		case expiredUser.ID:
			original = expired
		}
		if !membership.QuotaPeriodStartedOn.Equal(original.QuotaPeriodStartedOn) ||
			!membership.QuotaResetsAfter.Equal(original.QuotaResetsAfter) {
			t.Fatalf("compensation moved quota timing for %s", membership.UserID)
		}
	}
}

func TestResetMembershipTrafficPreservesResetTiming(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	store, _ := Open(path, testBuild())
	now := time.Date(2028, time.March, 4, 9, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	membership, _ := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{MonthlyQuotaBytes: 100})
	if err := store.mutateBilling(func(state *State) (bool, error) {
		member := &state.ProxyNodes[0].Memberships[0]
		member.UsedBytes = 100
		member.DisabledReason = MembershipQuotaReached
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	changed, err := store.ResetMembershipTraffic(node.ID, user.ID)
	if err != nil || !changed {
		t.Fatalf("ResetMembershipTraffic() changed=%v err=%v", changed, err)
	}
	updated, _ := store.ProxyNode(node.ID)
	got := updated.Memberships[0]
	if got.UsedBytes != 0 || got.DisabledReason != MembershipEnabled ||
		!got.QuotaPeriodStartedOn.Equal(membership.QuotaPeriodStartedOn) || !got.QuotaResetsAfter.Equal(membership.QuotaResetsAfter) {
		t.Fatalf("reset membership = %#v", got)
	}
	if err := store.accounting.db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	reloaded, _ := reopened.ProxyNode(node.ID)
	if reloaded.Memberships[0].UsedBytes != 0 {
		t.Fatalf("durable reset usage = %d", reloaded.Memberships[0].UsedBytes)
	}
}

func TestResetMembershipCredentialRotatesOnlySecret(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	user, _ := store.CreateUser("alice")
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	membership, _ := store.AddMembershipWithPlan(node.ID, user.ID, MembershipPlan{MonthlyQuotaBytes: 100})
	if err := store.ResetMembershipCredential(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	updated, _ := store.ProxyNode(node.ID)
	got := updated.Memberships[0]
	if got.Credential.Secret == "" || got.Credential.Secret == membership.Credential.Secret {
		t.Fatalf("credential was not rotated: old=%q new=%q", membership.Credential.Secret, got.Credential.Secret)
	}
	if got.ID != membership.ID || got.MonthlyQuotaBytes != membership.MonthlyQuotaBytes ||
		!got.QuotaResetsAfter.Equal(membership.QuotaResetsAfter) {
		t.Fatalf("credential reset changed unrelated membership state: %#v", got)
	}
}
