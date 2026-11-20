package proxynode

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	linkLatencyBucketSize = 5 * time.Minute
	linkLatencyRetention  = 30 * 24 * time.Hour
)

type LinkLatencyObservation struct {
	TargetID  string
	Responded bool
	Connected bool
	Duration  time.Duration
}

type LinkLatencyBucket struct {
	StartedAt   time.Time
	Samples     uint64
	Responses   uint64
	Connections uint64
	DurationSum time.Duration
	DurationMin time.Duration
	DurationMax time.Duration
}

// RecordLinkLatencySnapshot stores one five-minute aggregate per distinct
// physical destination and transport. Logical Links sharing that path never
// duplicate history rows or network probes.
func (s *Store) RecordLinkLatencySnapshot(agentID string, observedAt time.Time, observations []LinkLatencyObservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accounting == nil || s.accounting.db == nil {
		return errors.New("Link latency storage is unavailable")
	}
	return s.accounting.recordLinkLatencySnapshot(agentID, observedAt, observations)
}

func (a *accountingDB) recordLinkLatencySnapshot(agentID string, observedAt time.Time, observations []LinkLatencyObservation) error {
	if !validAgentID(agentID) || observedAt.IsZero() || len(observations) > 256 {
		return errors.New("invalid Link latency snapshot")
	}
	transaction, err := a.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin Link latency update: %w", err)
	}
	defer transaction.Rollback()
	bucket := observedAt.UTC().Truncate(linkLatencyBucketSize).Unix()
	seen := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		if !validLatencyTargetID(observation.TargetID) || observation.Duration < 0 || observation.Duration > 30*time.Second {
			return errors.New("invalid Link latency observation")
		}
		if _, duplicate := seen[observation.TargetID]; duplicate {
			return errors.New("duplicate Link latency target")
		}
		seen[observation.TargetID] = struct{}{}
		response := boolInteger(observation.Responded)
		connected := boolInteger(observation.Connected)
		duration := int64(0)
		if observation.Responded {
			duration = observation.Duration.Milliseconds()
		}
		if _, err := transaction.Exec(`
			INSERT INTO link_latency_buckets(
				parent_agent, target_id, bucket_started_at, sample_count,
				response_count, connected_count, duration_sum_ms,
				duration_min_ms, duration_max_ms
			) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
			ON CONFLICT(parent_agent, target_id, bucket_started_at) DO UPDATE SET
				sample_count = link_latency_buckets.sample_count + 1,
				response_count = link_latency_buckets.response_count + excluded.response_count,
				connected_count = link_latency_buckets.connected_count + excluded.connected_count,
				duration_sum_ms = link_latency_buckets.duration_sum_ms + excluded.duration_sum_ms,
				duration_min_ms = CASE
					WHEN excluded.response_count = 0 THEN link_latency_buckets.duration_min_ms
					WHEN link_latency_buckets.response_count = 0 THEN excluded.duration_min_ms
					ELSE MIN(link_latency_buckets.duration_min_ms, excluded.duration_min_ms)
				END,
				duration_max_ms = CASE
					WHEN excluded.response_count = 0 THEN link_latency_buckets.duration_max_ms
					WHEN link_latency_buckets.response_count = 0 THEN excluded.duration_max_ms
					ELSE MAX(link_latency_buckets.duration_max_ms, excluded.duration_max_ms)
				END`,
			agentID, observation.TargetID, bucket, response, connected,
			duration, duration, duration,
		); err != nil {
			return fmt.Errorf("record Link latency observation: %w", err)
		}
	}
	pruned := a.lastLatencyPrune.IsZero() || observedAt.Sub(a.lastLatencyPrune) >= time.Hour
	if pruned {
		if _, err := transaction.Exec(
			`DELETE FROM link_latency_buckets WHERE bucket_started_at < ?`,
			observedAt.Add(-linkLatencyRetention).UTC().Unix(),
		); err != nil {
			return fmt.Errorf("prune Link latency history: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit Link latency update: %w", err)
	}
	if pruned {
		a.lastLatencyPrune = observedAt
	}
	return a.secureFiles()
}

// LinkLatencyHistory returns server-side resampled aggregates for one current
// physical path. Interval must be a whole multiple of the five-minute storage
// bucket so chart APIs stay bounded at every supported range.
func (s *Store) LinkLatencyHistory(agentID, targetID string, since time.Time, interval time.Duration) ([]LinkLatencyBucket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.accounting == nil || s.accounting.db == nil {
		return nil, errors.New("Link latency storage is unavailable")
	}
	if !validAgentID(agentID) || !validLatencyTargetID(targetID) || since.IsZero() ||
		interval < linkLatencyBucketSize || interval%linkLatencyBucketSize != 0 || interval > 24*time.Hour {
		return nil, errors.New("invalid Link latency history query")
	}
	step := int64(interval / time.Second)
	rows, err := s.accounting.db.Query(`
		SELECT (bucket_started_at / ?) * ?,
			SUM(sample_count), SUM(response_count), SUM(connected_count),
			SUM(duration_sum_ms),
			CASE WHEN SUM(response_count) = 0 THEN 0 ELSE MIN(CASE WHEN response_count > 0 THEN duration_min_ms END) END,
			CASE WHEN SUM(response_count) = 0 THEN 0 ELSE MAX(CASE WHEN response_count > 0 THEN duration_max_ms END) END
		FROM link_latency_buckets
		WHERE parent_agent = ? AND target_id = ? AND bucket_started_at >= ?
		GROUP BY (bucket_started_at / ?)
		ORDER BY 1`,
		step, step, agentID, targetID, since.UTC().Unix(), step,
	)
	if err != nil {
		return nil, fmt.Errorf("query Link latency history: %w", err)
	}
	defer rows.Close()
	var result []LinkLatencyBucket
	for rows.Next() {
		var started, samples, responses, connections, sum, min, max int64
		if err := rows.Scan(&started, &samples, &responses, &connections, &sum, &min, &max); err != nil {
			return nil, fmt.Errorf("decode Link latency history: %w", err)
		}
		if started <= 0 || samples < 0 || responses < 0 || responses > samples ||
			connections < 0 || connections > responses || sum < 0 || min < 0 || max < min {
			return nil, errors.New("invalid Link latency history row")
		}
		result = append(result, LinkLatencyBucket{
			StartedAt: time.Unix(started, 0).UTC(), Samples: uint64(samples),
			Responses: uint64(responses), Connections: uint64(connections),
			DurationSum: time.Duration(sum) * time.Millisecond,
			DurationMin: time.Duration(min) * time.Millisecond,
			DurationMax: time.Duration(max) * time.Millisecond,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read Link latency history: %w", err)
	}
	return result, nil
}

func validLatencyTargetID(value string) bool {
	if len(value) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func boolInteger(value bool) int {
	if value {
		return 1
	}
	return 0
}
