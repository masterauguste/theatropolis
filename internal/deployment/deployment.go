package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	MaxConfigBytes = 4 << 20

	StatusQueued           Status = "queued"
	StatusValidating       Status = "validating"
	StatusValidated        Status = "validated"
	StatusValidationFailed Status = "validation_failed"
	StatusDeploying        Status = "deploying"
	StatusApplied          Status = "applied"
	StatusRuntimeFailed    Status = "runtime_failed"
	StatusActivationFailed Status = "activation_failed"
	StatusInternalError    Status = "internal_error"
	StatusDeliveryFailed   Status = "delivery_failed"
)

var (
	ErrAlreadyExists        = errors.New("deployment already exists")
	ErrNotFound             = errors.New("deployment not found")
	ErrInvalidTransition    = errors.New("invalid deployment state transition")
	ErrInvalidConfig        = errors.New("deployment configuration must be valid JSON")
	ErrConfigTooLarge       = errors.New("deployment configuration exceeds the size limit")
	ErrInvalidRecord        = errors.New("invalid deployment record")
	ErrUnsafeStorage        = errors.New("unsafe deployment storage")
	ErrInvalidStoredData    = errors.New("invalid stored deployment data")
	ErrDeploymentInProgress = errors.New("deployment already in progress")
)

type Record struct {
	ID         string
	AgentID    string
	RevisionID string
	// ConfigJSON is the logical configuration exactly as the operator
	// submitted it; it may contain theatropolis-pool-ref outbounds.
	// ConfigSHA256 is its digest.
	ConfigJSON   []byte
	ConfigSHA256 [sha256.Size]byte
	// RenderedSHA256 is the digest of the rendered configuration: the
	// document with every pool ref resolved, which is what the agent
	// receives, digests, and reports against. It is zero for records
	// written before the outbound-pool feature existed; those predate
	// refs, so their logical and rendered configurations are identical
	// and RenderedDigest falls back to ConfigSHA256.
	RenderedSHA256 [sha256.Size]byte
	Status         Status
	Diagnostic     string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// RenderedDigest returns the digest of the configuration the agent received.
// Records without a rendered digest predate pool refs, so for them the
// rendered document is the logical one and ConfigSHA256 is the right value.
func (r Record) RenderedDigest() [sha256.Size]byte {
	if r.RenderedSHA256 == ([sha256.Size]byte{}) {
		return r.ConfigSHA256
	}
	return r.RenderedSHA256
}

func New(id, agentID, revisionID string, config []byte, now time.Time) (Record, error) {
	id = strings.TrimSpace(id)
	agentID = strings.TrimSpace(agentID)
	revisionID = strings.TrimSpace(revisionID)
	if id == "" || agentID == "" || revisionID == "" {
		return Record{}, errors.New("deployment, agent, and revision IDs are required")
	}
	if now.IsZero() {
		return Record{}, errors.New("creation time is required")
	}
	if err := validateConfig(config); err != nil {
		return Record{}, err
	}

	// RenderedSHA256 stays zero here: New only sees the logical
	// configuration. Callers that render pool refs (the control server) set
	// Record.RenderedSHA256 to the rendered digest before Store.Create.
	return Record{
		ID:           id,
		AgentID:      agentID,
		RevisionID:   revisionID,
		ConfigJSON:   append([]byte(nil), config...),
		ConfigSHA256: sha256.Sum256(config),
		Status:       StatusQueued,
		CreatedAt:    now.UTC(),
		UpdatedAt:    now.UTC(),
	}, nil
}

type Store interface {
	Create(context.Context, Record) error
	Get(context.Context, string) (Record, error)
	LatestForAgent(context.Context, string) (Record, error)
	// List returns every stored record (one per agent, the latest) sorted by
	// agent ID. The outbound-pool propagation scan uses it to find every
	// logical configuration referencing pool entries.
	List(context.Context) ([]Record, error)
	Transition(context.Context, string, Status, string, time.Time) (Record, error)
	RemoveAgent(context.Context, string) error
}

var _ Store = (*MemoryStore)(nil)

type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]Record
	latest  map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records: make(map[string]Record),
		latest:  make(map[string]string),
	}
}

func (s *MemoryStore) Create(_ context.Context, record Record) error {
	if err := validateRecord(record); err != nil {
		return err
	}
	record = cloneRecord(record)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[record.ID]; exists {
		return ErrAlreadyExists
	}
	if previousID, exists := s.latest[record.AgentID]; exists {
		if deploymentInProgress(s.records[previousID].Status) {
			return ErrDeploymentInProgress
		}
		delete(s.records, previousID)
	}
	s.records[record.ID] = record
	s.latest[record.AgentID] = record.ID
	return nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.records[id]
	if !exists {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

func (s *MemoryStore) LatestForAgent(
	_ context.Context,
	agentID string,
) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.latest[agentID]
	if !exists {
		return Record{}, ErrNotFound
	}
	return cloneRecord(s.records[id]), nil
}

func (s *MemoryStore) List(_ context.Context) ([]Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		records = append(records, cloneRecord(record))
	}
	sort.Slice(records, func(left, right int) bool {
		return records[left].AgentID < records[right].AgentID
	})
	return records, nil
}

func (s *MemoryStore) Transition(
	_ context.Context,
	id string,
	next Status,
	diagnostic string,
	now time.Time,
) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, exists := s.records[id]
	if !exists {
		return Record{}, ErrNotFound
	}
	if !canTransition(record.Status, next) {
		return Record{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, record.Status, next)
	}
	if now.IsZero() {
		return Record{}, errors.New("transition time is required")
	}

	record.Status = next
	record.Diagnostic = diagnostic
	record.UpdatedAt = now.UTC()
	s.records[id] = record
	return cloneRecord(record), nil
}

func (s *MemoryStore) RemoveAgent(_ context.Context, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, exists := s.latest[agentID]
	if !exists {
		return ErrNotFound
	}
	delete(s.latest, agentID)
	delete(s.records, id)
	return nil
}

func canTransition(current, next Status) bool {
	switch current {
	case StatusQueued:
		return next == StatusValidating ||
			next == StatusDeploying ||
			next == StatusDeliveryFailed
	case StatusValidating:
		return next == StatusValidated ||
			next == StatusValidationFailed ||
			next == StatusInternalError ||
			next == StatusDeliveryFailed
	case StatusValidated:
		return next == StatusDeploying || next == StatusDeliveryFailed
	case StatusDeploying:
		return next == StatusApplied ||
			next == StatusValidationFailed ||
			next == StatusActivationFailed ||
			next == StatusInternalError ||
			next == StatusDeliveryFailed
	case StatusApplied:
		return next == StatusRuntimeFailed
	case StatusRuntimeFailed:
		return next == StatusApplied
	default:
		return false
	}
}

func validateConfig(config []byte) error {
	if len(config) > MaxConfigBytes {
		return ErrConfigTooLarge
	}
	if len(config) == 0 || !json.Valid(config) {
		return ErrInvalidConfig
	}
	return nil
}

func validateRecord(record Record) error {
	if record.ID == "" ||
		record.ID != strings.TrimSpace(record.ID) ||
		record.AgentID == "" ||
		record.AgentID != strings.TrimSpace(record.AgentID) ||
		record.RevisionID == "" ||
		record.RevisionID != strings.TrimSpace(record.RevisionID) ||
		record.CreatedAt.IsZero() ||
		record.UpdatedAt.IsZero() ||
		record.UpdatedAt.Before(record.CreatedAt) ||
		!knownStatus(record.Status) {
		return ErrInvalidRecord
	}
	if err := validateConfig(record.ConfigJSON); err != nil {
		return err
	}
	if sha256.Sum256(record.ConfigJSON) != record.ConfigSHA256 {
		return ErrInvalidRecord
	}
	return nil
}

func knownStatus(status Status) bool {
	switch status {
	case StatusQueued,
		StatusValidating,
		StatusValidated,
		StatusValidationFailed,
		StatusDeploying,
		StatusApplied,
		StatusRuntimeFailed,
		StatusActivationFailed,
		StatusInternalError,
		StatusDeliveryFailed:
		return true
	default:
		return false
	}
}

func cloneRecord(record Record) Record {
	record.ConfigJSON = append([]byte(nil), record.ConfigJSON...)
	return record
}

func deploymentInProgress(status Status) bool {
	switch status {
	case StatusQueued, StatusValidating, StatusDeploying:
		return true
	default:
		return false
	}
}

type Event struct {
	Deployment Record
	Message    string
}

type Notifier interface {
	Notify(context.Context, Event) error
}

type NopNotifier struct{}

func (NopNotifier) Notify(context.Context, Event) error { return nil }
