package deployment

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStoreEnforcesDeploymentStateMachine(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	record, err := New("deployment-1", "agent-1", "revision-1", []byte(`{}`), now)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	if err := store.Create(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(
		ctx,
		record.ID,
		StatusValidated,
		"",
		now.Add(time.Second),
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid transition, got %v", err)
	}
	if _, err := store.Transition(
		ctx,
		record.ID,
		StatusValidating,
		"",
		now.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	updated, err := store.Transition(
		ctx,
		record.ID,
		StatusValidationFailed,
		"configuration rejected",
		now.Add(2*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != StatusValidationFailed {
		t.Fatalf("got status %q", updated.Status)
	}
	if updated.Diagnostic != "configuration rejected" {
		t.Fatalf("got diagnostic %q", updated.Diagnostic)
	}
	if _, err := store.Transition(
		ctx,
		record.ID,
		StatusValidated,
		"",
		now.Add(3*time.Second),
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal deployment accepted a transition: %v", err)
	}
}
