package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveLegacyAgentID(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "agent-id")
	if err := os.WriteFile(path, []byte("obsolete-server-name\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeLegacyAgentID(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("obsolete agent ID still exists: %v", err)
	}
}

func TestRemoveLegacyAgentIDRejectsSymlink(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("do not remove\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent-id")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := removeLegacyAgentID(path); err == nil {
		t.Fatal("symlinked obsolete agent ID was accepted")
	}
	if contents, err := os.ReadFile(target); err != nil || string(contents) != "do not remove\n" {
		t.Fatalf("symlink target changed: %q, %v", contents, err)
	}
}
