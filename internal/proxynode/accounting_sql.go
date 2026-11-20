package proxynode

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const accountingSchemaVersion = 4

type accountingDB struct {
	db               *sql.DB
	path             string
	lastLatencyPrune time.Time
}

func accountingPath(statePath string) string {
	extension := filepath.Ext(statePath)
	base := strings.TrimSuffix(statePath, extension)
	if filepath.Base(base) == "proxy-node-state" {
		base = filepath.Join(filepath.Dir(base), "proxy-node-accounting")
	} else {
		base += "-accounting"
	}
	return base + ".sqlite"
}

func openAccountingDB(statePath string, state *State) (*accountingDB, error) {
	path := accountingPath(statePath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create accounting storage directory: %w", err)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect accounting storage: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: accounting path is not a regular file", ErrUnsafeStorage)
		}
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open accounting database: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	accounting := &accountingDB{db: database, path: path}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = database.Close()
		}
	}()

	for _, statement := range []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = FULL`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
	} {
		if _, err := database.Exec(statement); err != nil {
			return nil, fmt.Errorf("configure accounting database: %w", err)
		}
	}
	if err := accounting.initialize(state); err != nil {
		return nil, err
	}
	if err := accounting.secureFiles(); err != nil {
		return nil, err
	}
	closeOnError = false
	return accounting, nil
}

func (a *accountingDB) initialize(state *State) error {
	transaction, err := a.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin accounting initialization: %w", err)
	}
	defer transaction.Rollback()

	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS accounting_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS membership_usage (
			membership_id TEXT PRIMARY KEY,
			used_bytes TEXT NOT NULL,
			period_started_at INTEGER NOT NULL,
			resets_after INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS daily_membership_usage (
			membership_id TEXT NOT NULL REFERENCES membership_usage(membership_id) ON DELETE CASCADE,
			usage_date TEXT NOT NULL,
			used_bytes TEXT NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (membership_id, usage_date)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS legacy_observations (
			agent_id TEXT NOT NULL,
			inbound_path TEXT NOT NULL,
			username TEXT NOT NULL,
			epoch TEXT NOT NULL,
			uplink_bytes TEXT NOT NULL,
			downlink_bytes TEXT NOT NULL,
			observed_at INTEGER NOT NULL,
			PRIMARY KEY (agent_id, inbound_path, username)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS accounting_failures (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id TEXT NOT NULL,
			reason TEXT NOT NULL,
			occurred_at INTEGER NOT NULL
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS link_latency_buckets (
			parent_agent TEXT NOT NULL,
			target_id TEXT NOT NULL,
			bucket_started_at INTEGER NOT NULL,
			sample_count INTEGER NOT NULL,
			response_count INTEGER NOT NULL,
			connected_count INTEGER NOT NULL,
			duration_sum_ms INTEGER NOT NULL,
			duration_min_ms INTEGER NOT NULL,
			duration_max_ms INTEGER NOT NULL,
			PRIMARY KEY (parent_agent, target_id, bucket_started_at)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS link_latency_buckets_by_time
			ON link_latency_buckets(bucket_started_at)`,
	} {
		if _, err := transaction.Exec(statement); err != nil {
			return fmt.Errorf("create accounting schema: %w", err)
		}
	}
	var version int
	row := transaction.QueryRow(`SELECT CAST(value AS INTEGER) FROM accounting_meta WHERE key = 'schema_version'`)
	switch err := row.Scan(&version); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := transaction.Exec(
			`INSERT INTO accounting_meta(key, value) VALUES ('schema_version', ?)`,
			strconv.Itoa(accountingSchemaVersion),
		); err != nil {
			return fmt.Errorf("record accounting schema: %w", err)
		}
	case err != nil:
		return fmt.Errorf("read accounting schema: %w", err)
	case version == 1:
		if err := migrateAccountingSchemaV1(transaction); err != nil {
			return err
		}
		version = 2
		fallthrough
	case version == 2:
		if _, err := transaction.Exec(
			`UPDATE accounting_meta SET value = ? WHERE key = 'schema_version'`,
			strconv.Itoa(accountingSchemaVersion),
		); err != nil {
			return fmt.Errorf("record accounting schema migration: %w", err)
		}
		version = accountingSchemaVersion
	case version == 3:
		if _, err := transaction.Exec(
			`UPDATE accounting_meta SET value = ? WHERE key = 'schema_version'`,
			strconv.Itoa(accountingSchemaVersion),
		); err != nil {
			return fmt.Errorf("record accounting schema migration: %w", err)
		}
		version = accountingSchemaVersion
	case version != accountingSchemaVersion:
		return fmt.Errorf("%w: unsupported accounting schema version %d", ErrInvalidState, version)
	}

	var imported string
	err = transaction.QueryRow(`SELECT value FROM accounting_meta WHERE key = 'legacy_json_imported'`).Scan(&imported)
	if errors.Is(err, sql.ErrNoRows) {
		if err := importLegacyAccounting(transaction, state); err != nil {
			return err
		}
		if _, err := transaction.Exec(
			`INSERT INTO accounting_meta(key, value) VALUES ('legacy_json_imported', '1')`,
		); err != nil {
			return fmt.Errorf("finish accounting import: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("read accounting import state: %w", err)
	}
	if err := ensureAccountingMemberships(transaction, state); err != nil {
		return err
	}
	if err := pruneAccountingMemberships(transaction, state); err != nil {
		return err
	}
	if err := setAccountingUserRevision(transaction, state.UserRevision); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit accounting initialization: %w", err)
	}
	if err := a.loadIntoState(state); err != nil {
		return err
	}
	return nil
}

func migrateAccountingSchemaV1(transaction *sql.Tx) error {
	rows, err := transaction.Query(`SELECT membership_id, period_started_at, resets_after FROM membership_usage`)
	if err != nil {
		return fmt.Errorf("read legacy accounting periods: %w", err)
	}
	type period struct {
		id                   string
		periodStart, resetAt int64
	}
	var periods []period
	for rows.Next() {
		var value period
		if err := rows.Scan(&value.id, &value.periodStart, &value.resetAt); err != nil {
			rows.Close()
			return fmt.Errorf("decode legacy accounting period: %w", err)
		}
		periods = append(periods, value)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy accounting periods: %w", err)
	}
	for _, value := range periods {
		periodStart := legacyUTCDateToBillingDate(time.Unix(value.periodStart, 0)).Unix()
		resetAt := legacyUTCDateToBillingDate(time.Unix(value.resetAt, 0)).Unix()
		if _, err := transaction.Exec(
			`UPDATE membership_usage SET period_started_at = ?, resets_after = ? WHERE membership_id = ?`,
			periodStart, resetAt, value.id,
		); err != nil {
			return fmt.Errorf("migrate accounting period %q: %w", value.id, err)
		}
	}
	if _, err := transaction.Exec(
		`UPDATE accounting_meta SET value = ? WHERE key = 'schema_version'`,
		strconv.Itoa(accountingSchemaVersion),
	); err != nil {
		return fmt.Errorf("record accounting schema migration: %w", err)
	}
	return nil
}

func importLegacyAccounting(transaction *sql.Tx, state *State) error {
	if err := ensureAccountingMemberships(transaction, state); err != nil {
		return err
	}
	for _, observation := range state.TrafficObservations {
		if _, err := transaction.Exec(
			`INSERT INTO legacy_observations(
				agent_id, inbound_path, username, epoch, uplink_bytes, downlink_bytes, observed_at
			) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(agent_id, inbound_path, username) DO UPDATE SET
				epoch = excluded.epoch,
				uplink_bytes = excluded.uplink_bytes,
				downlink_bytes = excluded.downlink_bytes,
				observed_at = excluded.observed_at`,
			observation.AgentID,
			observation.InboundPath,
			observation.Username,
			observation.Epoch,
			strconv.FormatUint(observation.UplinkBytes, 10),
			strconv.FormatUint(observation.DownlinkBytes, 10),
			observation.ObservedAt.UTC().Unix(),
		); err != nil {
			return fmt.Errorf("import legacy traffic observation: %w", err)
		}
	}
	for _, failure := range state.AccountingFailures {
		if _, err := transaction.Exec(
			`INSERT INTO accounting_failures(agent_id, reason, occurred_at) VALUES (?, ?, ?)`,
			failure.AgentID, failure.Reason, failure.OccurredAt.UTC().Unix(),
		); err != nil {
			return fmt.Errorf("import accounting failure: %w", err)
		}
	}
	return nil
}

func ensureAccountingMemberships(transaction *sql.Tx, state *State) error {
	now := time.Now().UTC().Unix()
	for _, node := range state.ProxyNodes {
		for _, membership := range node.Memberships {
			if _, err := transaction.Exec(
				`INSERT INTO membership_usage(
					membership_id, used_bytes, period_started_at, resets_after, updated_at
				) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(membership_id) DO NOTHING`,
				membership.ID,
				strconv.FormatUint(membership.UsedBytes, 10),
				membership.QuotaPeriodStartedOn.UTC().Unix(),
				membership.QuotaResetsAfter.UTC().Unix(),
				now,
			); err != nil {
				return fmt.Errorf("initialize membership accounting: %w", err)
			}
		}
	}
	return nil
}

func pruneAccountingMemberships(transaction *sql.Tx, state *State) error {
	live := make(map[string]struct{})
	for _, node := range state.ProxyNodes {
		for _, membership := range node.Memberships {
			live[membership.ID] = struct{}{}
		}
	}
	rows, err := transaction.Query(`SELECT membership_id FROM membership_usage`)
	if err != nil {
		return fmt.Errorf("list membership accounting rows: %w", err)
	}
	var retired []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("decode membership accounting identity: %w", err)
		}
		if _, exists := live[id]; !exists {
			retired = append(retired, id)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close membership accounting identities: %w", err)
	}
	for _, id := range retired {
		if _, err := transaction.Exec(`DELETE FROM membership_usage WHERE membership_id = ?`, id); err != nil {
			return fmt.Errorf("delete retired membership accounting: %w", err)
		}
	}
	return nil
}

// reconcileMemberships creates accounting rows for new grants and removes all
// rows whose membership identity is no longer present in the authoritative
// topology/user store. Startup performs the same reconciliation, covering a
// process interruption after the JSON mutation committed.
func (a *accountingDB) reconcileMemberships(state State) error {
	transaction, err := a.prepareMembershipReconciliation(state)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit membership accounting reconciliation: %w", err)
	}
	return a.secureFiles()
}

func (a *accountingDB) prepareMembershipReconciliation(state State) (*sql.Tx, error) {
	transaction, err := a.db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("begin membership accounting reconciliation: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = transaction.Rollback()
		}
	}()
	if err := ensureAccountingMemberships(transaction, &state); err != nil {
		return nil, err
	}
	if err := syncAccountingMembershipUsage(transaction, &state); err != nil {
		return nil, err
	}
	if err := pruneAccountingMemberships(transaction, &state); err != nil {
		return nil, err
	}
	if err := setAccountingUserRevision(transaction, state.UserRevision); err != nil {
		return nil, err
	}
	ok = true
	return transaction, nil
}

// syncAccountingMembershipUsage makes a low-frequency state reconciliation a
// complete accounting checkpoint as well as an identity reconciliation. The
// caller holds the Store write lock, so the in-memory values cannot lag a
// concurrent traffic report while the JSON authority is being replaced.
func syncAccountingMembershipUsage(transaction *sql.Tx, state *State) error {
	now := time.Now().UTC().Unix()
	for _, node := range state.ProxyNodes {
		for _, membership := range node.Memberships {
			if _, err := transaction.Exec(
				`UPDATE membership_usage SET
					used_bytes = ?,
					period_started_at = ?,
					resets_after = ?,
					updated_at = ?
				 WHERE membership_id = ?`,
				strconv.FormatUint(membership.UsedBytes, 10),
				membership.QuotaPeriodStartedOn.UTC().Unix(),
				membership.QuotaResetsAfter.UTC().Unix(),
				now,
				membership.ID,
			); err != nil {
				return fmt.Errorf("synchronize membership accounting: %w", err)
			}
		}
	}
	return nil
}

func setAccountingUserRevision(transaction *sql.Tx, revision uint64) error {
	var currentText string
	err := transaction.QueryRow(`SELECT value FROM accounting_meta WHERE key = 'user_revision'`).Scan(&currentText)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read accounting user revision: %w", err)
	}
	current := uint64(0)
	exists := err == nil
	if exists {
		current, err = strconv.ParseUint(currentText, 10, 64)
		if err != nil {
			return fmt.Errorf("%w: invalid accounting user revision", ErrInvalidState)
		}
	}
	if exists && current >= revision {
		return nil
	}
	if _, err := transaction.Exec(
		`INSERT INTO accounting_meta(key, value) VALUES ('user_revision', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		strconv.FormatUint(revision, 10),
	); err != nil {
		return fmt.Errorf("record accounting user revision: %w", err)
	}
	return nil
}

func (a *accountingDB) loadIntoState(state *State) error {
	usageRows, err := a.db.Query(
		`SELECT membership_id, used_bytes, period_started_at, resets_after FROM membership_usage`,
	)
	if err != nil {
		return fmt.Errorf("read membership accounting: %w", err)
	}
	usage := make(map[string]struct {
		used                 uint64
		periodStart, resetAt time.Time
	})
	for usageRows.Next() {
		var id, usedText string
		var periodStart, resetAt int64
		if err := usageRows.Scan(&id, &usedText, &periodStart, &resetAt); err != nil {
			usageRows.Close()
			return fmt.Errorf("decode membership accounting: %w", err)
		}
		used, err := strconv.ParseUint(usedText, 10, 64)
		if err != nil || periodStart <= 0 || resetAt <= 0 {
			usageRows.Close()
			return fmt.Errorf("%w: invalid membership accounting row", ErrInvalidState)
		}
		usage[id] = struct {
			used                 uint64
			periodStart, resetAt time.Time
		}{used: used, periodStart: time.Unix(periodStart, 0).UTC(), resetAt: time.Unix(resetAt, 0).UTC()}
	}
	if err := usageRows.Close(); err != nil {
		return fmt.Errorf("close membership accounting rows: %w", err)
	}
	for nodeIndex := range state.ProxyNodes {
		for membershipIndex := range state.ProxyNodes[nodeIndex].Memberships {
			membership := &state.ProxyNodes[nodeIndex].Memberships[membershipIndex]
			if row, exists := usage[membership.ID]; exists {
				membership.UsedBytes = row.used
				membership.QuotaPeriodStartedOn = row.periodStart
				membership.QuotaResetsAfter = row.resetAt
			}
			recomputeMembershipStatus(membership, time.Now().UTC())
		}
	}

	state.TrafficObservations = nil
	observationRows, err := a.db.Query(
		`SELECT agent_id, inbound_path, username, epoch, uplink_bytes, downlink_bytes, observed_at
		 FROM legacy_observations ORDER BY agent_id, inbound_path, username`,
	)
	if err != nil {
		return fmt.Errorf("read legacy observations: %w", err)
	}
	for observationRows.Next() {
		var observation TrafficObservation
		var uplinkText, downlinkText string
		var observedAt int64
		if err := observationRows.Scan(
			&observation.AgentID,
			&observation.InboundPath,
			&observation.Username,
			&observation.Epoch,
			&uplinkText,
			&downlinkText,
			&observedAt,
		); err != nil {
			observationRows.Close()
			return fmt.Errorf("decode legacy observation: %w", err)
		}
		observation.UplinkBytes, err = strconv.ParseUint(uplinkText, 10, 64)
		if err == nil {
			observation.DownlinkBytes, err = strconv.ParseUint(downlinkText, 10, 64)
		}
		if err != nil || observedAt <= 0 {
			observationRows.Close()
			return fmt.Errorf("%w: invalid legacy observation row", ErrInvalidState)
		}
		observation.ObservedAt = time.Unix(observedAt, 0).UTC()
		state.TrafficObservations = append(state.TrafficObservations, observation)
	}
	if err := observationRows.Close(); err != nil {
		return fmt.Errorf("close legacy observation rows: %w", err)
	}

	state.AccountingFailures = nil
	failureRows, err := a.db.Query(
		`SELECT agent_id, reason, occurred_at FROM accounting_failures ORDER BY id DESC LIMIT ?`,
		maxAccountingFailures,
	)
	if err != nil {
		return fmt.Errorf("read accounting failures: %w", err)
	}
	for failureRows.Next() {
		var failure AccountingFailure
		var occurredAt int64
		if err := failureRows.Scan(&failure.AgentID, &failure.Reason, &occurredAt); err != nil {
			failureRows.Close()
			return fmt.Errorf("decode accounting failure: %w", err)
		}
		if occurredAt <= 0 || !validAgentID(failure.AgentID) || !validAccountingFailureReason(failure.Reason) {
			failureRows.Close()
			return fmt.Errorf("%w: invalid accounting failure row", ErrInvalidState)
		}
		failure.OccurredAt = time.Unix(occurredAt, 0).UTC()
		state.AccountingFailures = append(state.AccountingFailures, failure)
	}
	if err := failureRows.Close(); err != nil {
		return fmt.Errorf("close accounting failure rows: %w", err)
	}
	for left, right := 0, len(state.AccountingFailures)-1; left < right; left, right = left+1, right-1 {
		state.AccountingFailures[left], state.AccountingFailures[right] = state.AccountingFailures[right], state.AccountingFailures[left]
	}

	var revisionText string
	if err := a.db.QueryRow(`SELECT value FROM accounting_meta WHERE key = 'user_revision'`).Scan(&revisionText); err != nil {
		return fmt.Errorf("read accounting user revision: %w", err)
	}
	revision, err := strconv.ParseUint(revisionText, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid accounting user revision", ErrInvalidState)
	}
	if revision > state.UserRevision {
		state.UserRevision = revision
	}
	return nil
}

// persistChanges stores only accounting rows whose values changed. The JSON
// topology remains the authority for membership identity and policy, while
// SQLite is the durable authority for high-frequency usage, reset boundaries,
// legacy rolling-upgrade baselines, and accounting failures.
func (a *accountingDB) persistChanges(before, after State, daily *dailyUsageDelta) error {
	transaction, err := a.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin accounting update: %w", err)
	}
	defer transaction.Rollback()

	beforeMemberships := make(map[string]Membership)
	for _, node := range before.ProxyNodes {
		for _, membership := range node.Memberships {
			beforeMemberships[membership.ID] = membership
		}
	}
	now := time.Now().UTC().Unix()
	for _, node := range after.ProxyNodes {
		for _, membership := range node.Memberships {
			previous, existed := beforeMemberships[membership.ID]
			if existed && previous.UsedBytes == membership.UsedBytes &&
				previous.QuotaPeriodStartedOn.Equal(membership.QuotaPeriodStartedOn) &&
				previous.QuotaResetsAfter.Equal(membership.QuotaResetsAfter) {
				continue
			}
			if _, err := transaction.Exec(
				`INSERT INTO membership_usage(
					membership_id, used_bytes, period_started_at, resets_after, updated_at
				) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(membership_id) DO UPDATE SET
					used_bytes = excluded.used_bytes,
					period_started_at = excluded.period_started_at,
					resets_after = excluded.resets_after,
					updated_at = excluded.updated_at`,
				membership.ID,
				strconv.FormatUint(membership.UsedBytes, 10),
				membership.QuotaPeriodStartedOn.UTC().Unix(),
				membership.QuotaResetsAfter.UTC().Unix(),
				now,
			); err != nil {
				return fmt.Errorf("update membership accounting: %w", err)
			}
		}
	}

	if !reflect.DeepEqual(before.TrafficObservations, after.TrafficObservations) {
		if _, err := transaction.Exec(`DELETE FROM legacy_observations`); err != nil {
			return fmt.Errorf("replace legacy observations: %w", err)
		}
		for _, observation := range after.TrafficObservations {
			if _, err := transaction.Exec(
				`INSERT INTO legacy_observations(
					agent_id, inbound_path, username, epoch, uplink_bytes, downlink_bytes, observed_at
				) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				observation.AgentID,
				observation.InboundPath,
				observation.Username,
				observation.Epoch,
				strconv.FormatUint(observation.UplinkBytes, 10),
				strconv.FormatUint(observation.DownlinkBytes, 10),
				observation.ObservedAt.UTC().Unix(),
			); err != nil {
				return fmt.Errorf("replace legacy observation: %w", err)
			}
		}
	}

	if !reflect.DeepEqual(before.AccountingFailures, after.AccountingFailures) {
		if _, err := transaction.Exec(`DELETE FROM accounting_failures`); err != nil {
			return fmt.Errorf("replace accounting failures: %w", err)
		}
		for _, failure := range after.AccountingFailures {
			if _, err := transaction.Exec(
				`INSERT INTO accounting_failures(agent_id, reason, occurred_at) VALUES (?, ?, ?)`,
				failure.AgentID, failure.Reason, failure.OccurredAt.UTC().Unix(),
			); err != nil {
				return fmt.Errorf("replace accounting failure: %w", err)
			}
		}
	}

	if daily != nil && len(daily.BytesByMembership) > 0 {
		if err := persistDailyUsage(transaction, daily, now); err != nil {
			return err
		}
	}

	if err := ensureAccountingMemberships(transaction, &after); err != nil {
		return err
	}
	if err := pruneAccountingMemberships(transaction, &after); err != nil {
		return err
	}
	if err := setAccountingUserRevision(transaction, after.UserRevision); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit accounting update: %w", err)
	}
	if err := a.secureFiles(); err != nil {
		return err
	}
	return nil
}

func persistDailyUsage(transaction *sql.Tx, daily *dailyUsageDelta, updatedAt int64) error {
	for membershipID, delta := range daily.BytesByMembership {
		if delta == 0 {
			continue
		}
		var currentText string
		err := transaction.QueryRow(
			`SELECT used_bytes FROM daily_membership_usage WHERE membership_id = ? AND usage_date = ?`,
			membershipID, daily.Date,
		).Scan(&currentText)
		current := uint64(0)
		if err == nil {
			current, err = strconv.ParseUint(currentText, 10, 64)
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read daily membership usage: %w", err)
		}
		if _, err := transaction.Exec(
			`INSERT INTO daily_membership_usage(membership_id, usage_date, used_bytes, updated_at)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(membership_id, usage_date) DO UPDATE SET
				used_bytes = excluded.used_bytes,
				updated_at = excluded.updated_at`,
			membershipID, daily.Date, strconv.FormatUint(saturatingAdd(current, delta), 10), updatedAt,
		); err != nil {
			return fmt.Errorf("update daily membership usage: %w", err)
		}
	}
	return nil
}

func recomputeMembershipStatus(membership *Membership, now time.Time) {
	membership.DisabledReason = MembershipEnabled
	if !membership.SubscriptionEndsAfter.IsZero() && !now.UTC().Before(membership.SubscriptionEndsAfter) {
		membership.DisabledReason = MembershipExpired
		return
	}
	if membership.MonthlyQuotaBytes > 0 && membership.UsedBytes >= membership.MonthlyQuotaBytes {
		membership.DisabledReason = MembershipQuotaReached
	}
}

func (a *accountingDB) secureFiles() error {
	for _, candidate := range []string{a.path, a.path + "-wal", a.path + "-shm"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect accounting database file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: accounting database file is unsafe", ErrUnsafeStorage)
		}
		if err := os.Chmod(candidate, 0o600); err != nil {
			return fmt.Errorf("secure accounting database file: %w", err)
		}
	}
	return nil
}
