package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestControlTargetStorePersistsMigrationAndEnrollmentResetsIt(t *testing.T) {
	directory := t.TempDir()
	store := NewControlTargetStore(directory)
	if got, err := store.Load("old.example:443"); err != nil || got != "old.example:443" {
		t.Fatalf("initial = %q, %v", got, err)
	}
	if err := store.StageMasterMigration("migration_1", "new.example:8443"); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Load("old.example:443"); err != nil || got != "new.example:8443" {
		t.Fatalf("migrated = %q, %v", got, err)
	}
	if info, err := os.Stat(filepath.Join(directory, "control-target.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", info, err)
	}
	if err := store.ResetForEnrollment(); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Load("third.example:443"); err != nil || got != "third.example:443" {
		t.Fatalf("reset = %q, %v", got, err)
	}
}

func TestControlTargetStoreRejectsInvalidAddress(t *testing.T) {
	store := NewControlTargetStore(t.TempDir())
	if err := store.StageMasterMigration("migration_1", "missing-port"); err == nil {
		t.Fatal("invalid address accepted")
	}
}
