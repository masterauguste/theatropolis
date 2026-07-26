package deployment

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	StatusQueued           Status = "queued"
	StatusValidating       Status = "validating"
	StatusValidated        Status = "validated"
	StatusValidationFailed Status = "validation_failed"
	StatusInternalError    Status = "internal_error"
	StatusDeliveryFailed   Status = "delivery_failed"
)

var (
	ErrAlreadyExists     = errors.New("deployment already exists")
	ErrNotFound          = errors.New("deployment not found")
	ErrInvalidTransition = errors.New("invalid deployment state transition")
)

type Record struct {
	ID           string
	AgentID      string
	RevisionID   string
	ConfigSHA256 [sha256.Size]byte
	Status       Status
	Diagnostic   string
	CreatedAt    time.Time
	UpdatedAt    time.Time
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

	return Record{
		ID:           id,
		AgentID:      agentID,
		RevisionID:   revisionID,
		ConfigSHA256: sha256.Sum256(config),
		Status:       StatusQueued,
		CreatedAt:    now.UTC(),
		UpdatedAt:    now.UTC(),
	}, nil
}

type Store interface {
	Create(context.Context, Record) error
	Get(context.Context, string) (Record, error)
	Transition(context.Context, string, Status, string, time.Time) (Record, error)
}

type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

func (s *MemoryStore) Create(_ context.Context, record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[record.ID]; exists {
		return ErrAlreadyExists
	}
	s.records[record.ID] = record
	return nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.records[id]
	if !exists {
		return Record{}, ErrNotFound
	}
	return record, nil
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

	record.Status = next
	record.Diagnostic = diagnostic
	record.UpdatedAt = now.UTC()
	s.records[id] = record
	return record, nil
}

func canTransition(current, next Status) bool {
	switch current {
	case StatusQueued:
		return next == StatusValidating || next == StatusDeliveryFailed
	case StatusValidating:
		return next == StatusValidated ||
			next == StatusValidationFailed ||
			next == StatusInternalError ||
			next == StatusDeliveryFailed
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
