package deployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestNewValidatesAndDefensivelyCopiesConfig(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	config := []byte(`{"inbounds":[]}`)
	record, err := New(" deployment-1 ", " agent-1 ", " revision-1 ", config, now)
	if err != nil {
		t.Fatal(err)
	}
	config[2] = 'X'
	if string(record.ConfigJSON) != `{"inbounds":[]}` {
		t.Fatalf("record config changed with caller buffer: %q", record.ConfigJSON)
	}
	if record.ID != "deployment-1" ||
		record.AgentID != "agent-1" ||
		record.RevisionID != "revision-1" {
		t.Fatalf("record IDs were not normalized: %#v", record)
	}
	if record.ConfigSHA256 != sha256.Sum256(record.ConfigJSON) {
		t.Fatal("record config digest does not match its retained config")
	}

	tests := []struct {
		name   string
		id     string
		agent  string
		rev    string
		config []byte
		now    time.Time
		want   error
	}{
		{
			name:   "missing deployment ID",
			id:     " ",
			agent:  "agent-1",
			rev:    "revision-1",
			config: []byte(`{}`),
			now:    now,
		},
		{
			name:   "missing agent ID",
			id:     "deployment-1",
			agent:  "",
			rev:    "revision-1",
			config: []byte(`{}`),
			now:    now,
		},
		{
			name:   "missing revision ID",
			id:     "deployment-1",
			agent:  "agent-1",
			rev:    "",
			config: []byte(`{}`),
			now:    now,
		},
		{
			name:   "missing timestamp",
			id:     "deployment-1",
			agent:  "agent-1",
			rev:    "revision-1",
			config: []byte(`{}`),
		},
		{
			name:   "empty config",
			id:     "deployment-1",
			agent:  "agent-1",
			rev:    "revision-1",
			config: nil,
			now:    now,
			want:   ErrInvalidConfig,
		},
		{
			name:   "invalid config",
			id:     "deployment-1",
			agent:  "agent-1",
			rev:    "revision-1",
			config: []byte(`{"password":"not closed}`),
			now:    now,
			want:   ErrInvalidConfig,
		},
		{
			name:   "oversize config",
			id:     "deployment-1",
			agent:  "agent-1",
			rev:    "revision-1",
			config: bytes.Repeat([]byte(" "), MaxConfigBytes+1),
			now:    now,
			want:   ErrConfigTooLarge,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.id, test.agent, test.rev, test.config, test.now)
			if err == nil {
				t.Fatal("New unexpectedly succeeded")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("New error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestMemoryStoreKeepsOnlyDefensiveLatestRecordPerAgent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	first, err := New(
		"deployment-1",
		"agent-1",
		"revision-1",
		[]byte(`{"route":{"final":"direct"}}`),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	if err := store.Create(ctx, first); err != nil {
		t.Fatal(err)
	}

	first.ConfigJSON[0] = '['
	stored, err := store.Get(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored.ConfigJSON) != `{"route":{"final":"direct"}}` {
		t.Fatalf("store retained caller-owned config: %q", stored.ConfigJSON)
	}
	stored.ConfigJSON[0] = '['
	latest, err := store.LatestForAgent(ctx, first.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if string(latest.ConfigJSON) != `{"route":{"final":"direct"}}` {
		t.Fatalf("latest config was mutable through Get: %q", latest.ConfigJSON)
	}

	second, err := New(
		"deployment-2",
		"agent-1",
		"revision-2",
		[]byte(`{"route":{"final":"block"}}`),
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, second); !errors.Is(err, ErrDeploymentInProgress) {
		t.Fatalf("concurrent Create error = %v, want %v", err, ErrDeploymentInProgress)
	}
	if _, err := store.Transition(
		ctx,
		first.ID,
		StatusDeliveryFailed,
		"agent offline",
		now.Add(30*time.Second),
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("superseded deployment Get error = %v, want %v", err, ErrNotFound)
	}
	latest, err = store.LatestForAgent(ctx, second.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != second.ID {
		t.Fatalf("latest deployment = %q, want %q", latest.ID, second.ID)
	}
	if err := store.Create(ctx, second); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate Create error = %v, want %v", err, ErrAlreadyExists)
	}

	if err := store.RemoveAgent(ctx, second.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LatestForAgent(ctx, second.AgentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed agent latest error = %v, want %v", err, ErrNotFound)
	}
	if _, err := store.Get(ctx, second.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed deployment Get error = %v, want %v", err, ErrNotFound)
	}
	if err := store.RemoveAgent(ctx, second.AgentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second RemoveAgent error = %v, want %v", err, ErrNotFound)
	}
}

func TestDeploymentStateTransitions(t *testing.T) {
	t.Parallel()

	statuses := []Status{
		StatusQueued,
		StatusValidating,
		StatusValidated,
		StatusValidationFailed,
		StatusDeploying,
		StatusApplied,
		StatusActivationFailed,
		StatusInternalError,
		StatusDeliveryFailed,
	}
	allowed := map[Status]map[Status]bool{
		StatusQueued: {
			StatusValidating:     true,
			StatusDeploying:      true,
			StatusDeliveryFailed: true,
		},
		StatusValidating: {
			StatusValidated:        true,
			StatusValidationFailed: true,
			StatusInternalError:    true,
			StatusDeliveryFailed:   true,
		},
		StatusValidated: {
			StatusDeploying:      true,
			StatusDeliveryFailed: true,
		},
		StatusDeploying: {
			StatusApplied:          true,
			StatusValidationFailed: true,
			StatusActivationFailed: true,
			StatusInternalError:    true,
			StatusDeliveryFailed:   true,
		},
	}
	for _, current := range statuses {
		for _, next := range statuses {
			if got, want := canTransition(current, next), allowed[current][next]; got != want {
				t.Errorf("canTransition(%q, %q) = %v, want %v", current, next, got, want)
			}
		}
	}
}

func TestDiskStorePersistsLatestRecordAcrossRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	directory := t.TempDir()
	now := time.Now().UTC().Truncate(time.Microsecond)
	config := []byte("{\n  \"inbounds\": [{\"type\":\"hysteria2\",\"tag\":\"edge\"}]\n}\n")
	first, err := New("deployment-1", "edge/one", "revision-1", config, now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewDiskStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, first); err != nil {
		t.Fatal(err)
	}
	concurrent, err := New(
		"deployment-concurrent",
		first.AgentID,
		"revision-concurrent",
		[]byte(`{"inbounds":[]}`),
		now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, concurrent); !errors.Is(err, ErrDeploymentInProgress) {
		t.Fatalf("concurrent disk Create error = %v, want %v", err, ErrDeploymentInProgress)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("deployment file count = %d, want 1", len(entries))
	}
	filename := deploymentFilename(first.AgentID)
	if entries[0].Name() != filename {
		t.Fatalf("deployment filename = %q, want %q", entries[0].Name(), filename)
	}
	if strings.Contains(filename, first.AgentID) {
		t.Fatalf("deployment filename exposes agent ID: %q", filename)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("deployment file mode = %o, want 0600", info.Mode().Perm())
	}

	reopened, err := NewDiskStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.LatestForAgent(ctx, first.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != first.ID ||
		loaded.RevisionID != first.RevisionID ||
		!bytes.Equal(loaded.ConfigJSON, config) ||
		loaded.ConfigSHA256 != first.ConfigSHA256 {
		t.Fatalf("reloaded deployment differs: %#v", loaded)
	}
	loaded.ConfigJSON[0] = '['
	loadedAgain, err := reopened.Get(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedAgain.ConfigJSON, config) {
		t.Fatal("disk store returned caller-owned config")
	}

	for index, transition := range []struct {
		status     Status
		diagnostic string
	}{
		{status: StatusValidating},
		{status: StatusValidated},
		{status: StatusDeploying},
		{status: StatusApplied, diagnostic: "activated"},
	} {
		if _, err := reopened.Transition(
			ctx,
			first.ID,
			transition.status,
			transition.diagnostic,
			now.Add(time.Duration(index+1)*time.Second),
		); err != nil {
			t.Fatalf("transition to %q: %v", transition.status, err)
		}
	}
	reopened, err = NewDiskStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := reopened.Get(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != StatusApplied || applied.Diagnostic != "activated" {
		t.Fatalf("reloaded applied deployment = %#v", applied)
	}

	second, err := New(
		"deployment-2",
		first.AgentID,
		"revision-2",
		[]byte(`{"inbounds":[],"outbounds":[{"type":"direct"}]}`),
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Get(ctx, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("superseded disk deployment Get error = %v, want %v", err, ErrNotFound)
	}
	entries, err = os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filename {
		t.Fatalf("latest deployment files = %#v, want one stable hashed filename", entries)
	}
	reopened, err = NewDiskStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := reopened.LatestForAgent(ctx, first.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != second.ID {
		t.Fatalf("reloaded latest deployment = %q, want %q", latest.ID, second.ID)
	}

	if err := reopened.RemoveAgent(ctx, first.AgentID); err != nil {
		t.Fatal(err)
	}
	entries, err = os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("deployment files remain after removal: %#v", entries)
	}
	reopened, err = NewDiskStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.LatestForAgent(ctx, first.AgentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed deployment survived restart: %v", err)
	}
}

func TestDiskStoreRejectsMalformedAndUnsafeEntriesWithoutLeakingConfig(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	record, err := New(
		"deployment-1",
		"agent-1",
		"revision-1",
		[]byte(`{"password":"stored-secret-marker"}`),
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := encodeDiskRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	var validStored diskRecord
	if err := json.Unmarshal(valid, &validStored); err != nil {
		t.Fatal(err)
	}
	wrongDigestStored := validStored
	wrongDigestStored.ConfigSHA256 = strings.Repeat("0", sha256.Size*2)
	wrongDigestEncoded, err := jsonMarshalForTest(wrongDigestStored)
	if err != nil {
		t.Fatal(err)
	}
	wrongVersionStored := validStored
	wrongVersionStored.Version++
	wrongVersionEncoded, err := jsonMarshalForTest(wrongVersionStored)
	if err != nil {
		t.Fatal(err)
	}
	unknownFieldEncoded := append(
		[]byte(`{"unexpected":true,`),
		valid[1:]...,
	)
	invalidConfig := diskRecord{
		Version:      diskRecordVersion,
		ID:           record.ID,
		AgentID:      record.AgentID,
		RevisionID:   record.RevisionID,
		ConfigJSON:   []byte(`{"password":"stored-secret-marker"`),
		ConfigSHA256: hexDigest([]byte(`{"password":"stored-secret-marker"`)),
		Status:       record.Status,
		CreatedAt:    record.CreatedAt,
		UpdatedAt:    record.UpdatedAt,
	}
	invalidConfigEncoded, err := jsonMarshalForTest(invalidConfig)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		filename string
		contents []byte
		mode     os.FileMode
		want     error
	}{
		{
			name:     "invalid JSON",
			filename: deploymentFilename(record.AgentID),
			contents: []byte(`{"stored-secret-marker"`),
			mode:     0o600,
			want:     ErrInvalidStoredData,
		},
		{
			name:     "trailing JSON",
			filename: deploymentFilename(record.AgentID),
			contents: append(append([]byte(nil), valid...), []byte(`{}`)...),
			mode:     0o600,
			want:     ErrInvalidStoredData,
		},
		{
			name:     "unknown field",
			filename: deploymentFilename(record.AgentID),
			contents: unknownFieldEncoded,
			mode:     0o600,
			want:     ErrInvalidStoredData,
		},
		{
			name:     "unsupported version",
			filename: deploymentFilename(record.AgentID),
			contents: wrongVersionEncoded,
			mode:     0o600,
			want:     ErrInvalidStoredData,
		},
		{
			name:     "config digest mismatch",
			filename: deploymentFilename(record.AgentID),
			contents: wrongDigestEncoded,
			mode:     0o600,
			want:     ErrInvalidStoredData,
		},
		{
			name:     "invalid embedded config",
			filename: deploymentFilename(record.AgentID),
			contents: invalidConfigEncoded,
			mode:     0o600,
			want:     ErrInvalidStoredData,
		},
		{
			name:     "wrong hashed filename",
			filename: deploymentFilename("different-agent"),
			contents: valid,
			mode:     0o600,
			want:     ErrInvalidStoredData,
		},
		{
			name:     "unexpected filename",
			filename: "agent-1.json",
			contents: valid,
			mode:     0o600,
			want:     ErrInvalidStoredData,
		},
		{
			name:     "oversize file",
			filename: deploymentFilename(record.AgentID),
			contents: bytes.Repeat([]byte("x"), maxPersistedDeploymentBytes+1),
			mode:     0o600,
			want:     ErrInvalidStoredData,
		},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name     string
			filename string
			contents []byte
			mode     os.FileMode
			want     error
		}{
			name:     "unsafe permissions",
			filename: deploymentFilename(record.AgentID),
			contents: valid,
			mode:     0o644,
			want:     ErrUnsafeStorage,
		})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, test.filename)
			if err := os.WriteFile(path, test.contents, test.mode); err != nil {
				t.Fatal(err)
			}
			_, err := NewDiskStore(directory)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewDiskStore error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), "stored-secret-marker") {
				t.Fatalf("storage error exposed configuration: %v", err)
			}
		})
	}
}

func TestDiskStoreRejectsNonregularEntriesAndSymlinks(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, deploymentFilename("agent-1")), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiskStore(directory); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("directory entry error = %v, want %v", err, ErrUnsafeStorage)
	}

	if runtime.GOOS == "windows" {
		return
	}
	targetDirectory := t.TempDir()
	linkDirectory := filepath.Join(t.TempDir(), "deployments")
	if err := os.Symlink(targetDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiskStore(linkDirectory); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("symlink directory error = %v, want %v", err, ErrUnsafeStorage)
	}

	fileDirectory := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(fileDirectory, deploymentFilename("agent-1"))); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiskStore(fileDirectory); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("symlink deployment error = %v, want %v", err, ErrUnsafeStorage)
	}

	writeDirectory := t.TempDir()
	writeStore, err := NewDiskStore(writeDirectory)
	if err != nil {
		t.Fatal(err)
	}
	writeTarget := filepath.Join(t.TempDir(), "write-target.json")
	targetContents := []byte("do not overwrite")
	if err := os.WriteFile(writeTarget, targetContents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(
		writeTarget,
		filepath.Join(writeDirectory, deploymentFilename("agent-write")),
	); err != nil {
		t.Fatal(err)
	}
	record, err := New(
		"deployment-write",
		"agent-write",
		"revision-write",
		[]byte(`{}`),
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStore.Create(context.Background(), record); !errors.Is(err, ErrUnsafeStorage) {
		t.Fatalf("Create through symlink error = %v, want %v", err, ErrUnsafeStorage)
	}
	contents, err := os.ReadFile(writeTarget)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, targetContents) {
		t.Fatal("deployment Create wrote through a symlink")
	}
}

func TestDiskStoreCleansPrivateAtomicTempFile(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(directory, ".deployment-interrupted.tmp"),
		[]byte(`stored-secret-marker`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	store, err := NewDiskStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LatestForAgent(context.Background(), "agent-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store latest error = %v, want %v", err, ErrNotFound)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("interrupted deployment file was not removed: %#v", entries)
	}
}

func TestDiskStoreRejectsInvalidRecordWithoutLeakingConfig(t *testing.T) {
	t.Parallel()

	record := Record{
		ID:           "deployment-1",
		AgentID:      "agent-1",
		RevisionID:   "revision-1",
		ConfigJSON:   []byte(`{"password":"caller-secret-marker"}`),
		ConfigSHA256: sha256.Sum256([]byte(`{}`)),
		Status:       StatusQueued,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	store, err := NewDiskStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = store.Create(context.Background(), record)
	if !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Create error = %v, want %v", err, ErrInvalidRecord)
	}
	if strings.Contains(err.Error(), "caller-secret-marker") {
		t.Fatalf("Create error exposed configuration: %v", err)
	}
}

func hexDigest(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func TestRenderedDigestFallsBackForLegacyRecords(t *testing.T) {
	t.Parallel()

	config := []byte(`{"inbounds":[]}`)
	record, err := New("deployment-1", "agent-1", "revision-1", config, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	// New leaves RenderedSHA256 zero; the legacy fallback treats the logical
	// digest as the rendered one.
	if record.RenderedSHA256 != ([sha256.Size]byte{}) {
		t.Fatal("New() set a rendered digest")
	}
	if record.RenderedDigest() != record.ConfigSHA256 {
		t.Fatal("RenderedDigest() did not fall back to ConfigSHA256")
	}
	rendered := []byte(`{"outbounds":[{"type":"direct","tag":"via-a"}]}`)
	record.RenderedSHA256 = sha256.Sum256(rendered)
	if record.RenderedDigest() != record.RenderedSHA256 {
		t.Fatal("RenderedDigest() ignored the rendered digest")
	}
}

func TestDiskStoreRoundTripsRenderedDigestAndLegacyAbsence(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	directory := t.TempDir()
	now := time.Now().UTC().Truncate(time.Microsecond)
	store, err := NewDiskStore(directory)
	if err != nil {
		t.Fatal(err)
	}

	legacy, err := New("deployment-legacy", "agent-legacy", "revision-1", []byte(`{}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	rendered, err := New("deployment-rendered", "agent-rendered", "revision-1", []byte(`{"outbounds":[]}`), now)
	if err != nil {
		t.Fatal(err)
	}
	rendered.RenderedSHA256 = sha256.Sum256([]byte(`{"outbounds":[{"type":"direct","tag":"x"}]}`))
	if err := store.Create(ctx, rendered); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewDiskStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	loadedLegacy, err := reopened.LatestForAgent(ctx, legacy.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if loadedLegacy.RenderedSHA256 != ([sha256.Size]byte{}) ||
		loadedLegacy.RenderedDigest() != loadedLegacy.ConfigSHA256 {
		t.Fatalf("legacy record did not reload with a fallback digest: %#v", loadedLegacy)
	}
	loadedRendered, err := reopened.LatestForAgent(ctx, rendered.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if loadedRendered.RenderedSHA256 != rendered.RenderedSHA256 {
		t.Fatalf("rendered digest did not round-trip: %#v", loadedRendered)
	}
}

func TestStoreListReturnsLatestRecordsSortedByAgent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	for _, newStore := range []struct {
		name string
		open func(t *testing.T) Store
	}{
		{name: "memory", open: func(*testing.T) Store { return NewMemoryStore() }},
		{name: "disk", open: func(t *testing.T) Store {
			t.Helper()
			store, err := NewDiskStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			return store
		}},
	} {
		t.Run(newStore.name, func(t *testing.T) {
			t.Parallel()
			store := newStore.open(t)
			records, err := store.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 0 {
				t.Fatalf("empty store listed %d records", len(records))
			}
			for _, agentID := range []string{"agent-c", "agent-a", "agent-b"} {
				record, err := New("deployment-"+agentID, agentID, "revision-1", []byte(`{}`), now)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Create(ctx, record); err != nil {
					t.Fatal(err)
				}
			}
			records, err = store.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 3 ||
				records[0].AgentID != "agent-a" ||
				records[1].AgentID != "agent-b" ||
				records[2].AgentID != "agent-c" {
				t.Fatalf("List() order = %#v", records)
			}
			records[0].ConfigJSON[0] = '['
			again, err := store.Get(ctx, "deployment-agent-a")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again.ConfigJSON, []byte(`{}`)) {
				t.Fatal("List() returned caller-owned config")
			}
		})
	}
}

func jsonMarshalForTest(value any) ([]byte, error) {
	return json.Marshal(value)
}
