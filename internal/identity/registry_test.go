package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestEnrollmentIsSingleUseAndProofRequiresPrivateKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	registry := NewRegistry()
	token, err := registry.CreateEnrollment(ctx, "edge-paris-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Enroll(ctx, "edge-paris-1", token, publicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := registry.Enroll(ctx, "edge-paris-1", token, publicKey, time.Now()); !errors.Is(err, ErrAgentAlreadyEnrolled) {
		t.Fatalf("expected enrollment to be single use, got %v", err)
	}

	nonce, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, ChallengePayload("edge-paris-1", nonce))
	if !VerifyProof(publicKey, "edge-paris-1", nonce, signature) {
		t.Fatal("valid proof was rejected")
	}
	if VerifyProof(publicKey, "another-agent", nonce, signature) {
		t.Fatal("proof was accepted for another agent")
	}
}

func TestLoadOrCreatePrivateKeyPersistsIdentity(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "identity", "agent-key.pem")
	first, err := LoadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("agent identity changed when it was reloaded")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("agent identity is accessible by group or others: %v", info.Mode().Perm())
	}
}

func TestPersistentRegistryStoresOnlyTokenDigestAndPublicKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "master", "identities.json")
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := registry.CreateEnrollment(ctx, "edge-persistent-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, token) {
		t.Fatal("identity registry stored a plaintext enrollment token")
	}

	reopened, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Enroll(ctx, "edge-persistent-1", token, publicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	reopened, err = OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	actualPublicKey, err := reopened.PublicKey(ctx, "edge-persistent-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualPublicKey, publicKey) {
		t.Fatal("persistent registry returned a different public key")
	}
}

func TestPersistentRegistryRejectsOversizedFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "identities.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxRegistryFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRegistry(path); err == nil {
		t.Fatal("oversized identity registry was accepted")
	}
}

func TestRegistrySnapshotIsSortedAndClassifiesIdentities(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	registry := NewRegistry()

	pendingExpiry := now.Add(2 * time.Hour)
	if _, err := registry.CreateEnrollment(ctx, "zulu-pending", pendingExpiry); err != nil {
		t.Fatal(err)
	}
	expiredExpiry := now.Add(time.Hour)
	if _, err := registry.CreateEnrollment(ctx, "middle-expired", expiredExpiry); err != nil {
		t.Fatal(err)
	}
	enrollmentToken, err := registry.CreateEnrollment(
		ctx,
		"alpha-enrolled",
		now.Add(3*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Enroll(
		ctx,
		"alpha-enrolled",
		enrollmentToken,
		publicKey,
		now,
	); err != nil {
		t.Fatal(err)
	}

	snapshot := registry.Snapshot(now.Add(90 * time.Minute))
	expected := []AgentSnapshot{
		{
			ID:    "alpha-enrolled",
			State: AgentStateEnrolled,
		},
		{
			ID:                  "middle-expired",
			State:               AgentStateExpired,
			EnrollmentExpiresAt: expiredExpiry,
		},
		{
			ID:                  "zulu-pending",
			State:               AgentStatePending,
			EnrollmentExpiresAt: pendingExpiry,
		},
	}
	if !reflect.DeepEqual(snapshot, expected) {
		t.Fatalf("snapshot mismatch:\ngot:  %#v\nwant: %#v", snapshot, expected)
	}
}

func TestCreateEnrollmentRejectsActivePendingCredential(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	ctx := context.Background()
	firstToken, err := registry.CreateEnrollment(
		ctx,
		"edge-pending-once",
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CreateEnrollment(
		ctx,
		"edge-pending-once",
		time.Now().Add(2*time.Hour),
	); !errors.Is(err, ErrEnrollmentPending) {
		t.Fatalf("second CreateEnrollment() error = %v, want ErrEnrollmentPending", err)
	}

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Enroll(
		ctx,
		"edge-pending-once",
		firstToken,
		publicKey,
		time.Now(),
	); err != nil {
		t.Fatalf("first token was invalidated by rejected duplicate: %v", err)
	}
}

func TestCreateEnrollmentReplacesExpiredPendingCredential(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	ctx := context.Background()
	oldToken, err := registry.CreateEnrollment(
		ctx,
		"edge-expired-replacement",
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	expired := registry.pending["edge-expired-replacement"]
	expired.expiresAt = time.Now().Add(-time.Minute)
	registry.pending["edge-expired-replacement"] = expired
	registry.mu.Unlock()

	newToken, err := registry.CreateEnrollment(
		ctx,
		"edge-expired-replacement",
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("replace expired enrollment: %v", err)
	}
	if bytes.Equal(oldToken, newToken) {
		t.Fatal("replacement enrollment reused the old token")
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Enroll(
		ctx,
		"edge-expired-replacement",
		oldToken,
		publicKey,
		time.Now(),
	); !errors.Is(err, ErrEnrollmentUnavailable) {
		t.Fatalf("old token error = %v, want ErrEnrollmentUnavailable", err)
	}
	if err := registry.Enroll(
		ctx,
		"edge-expired-replacement",
		newToken,
		publicKey,
		time.Now(),
	); err != nil {
		t.Fatalf("new token was not accepted: %v", err)
	}
}

func TestAgentSnapshotContainsNoCredentialFields(t *testing.T) {
	t.Parallel()

	recordType := reflect.TypeOf(AgentSnapshot{})
	expectedFields := map[string]reflect.Type{
		"ID":                  reflect.TypeOf(""),
		"State":               reflect.TypeOf(AgentState("")),
		"EnrollmentExpiresAt": reflect.TypeOf(time.Time{}),
	}
	if recordType.NumField() != len(expectedFields) {
		t.Fatalf("AgentSnapshot exposes %d fields, want %d", recordType.NumField(), len(expectedFields))
	}
	for index := range recordType.NumField() {
		field := recordType.Field(index)
		expectedType, ok := expectedFields[field.Name]
		if !ok {
			t.Fatalf("AgentSnapshot exposes unexpected field %q", field.Name)
		}
		if field.Type != expectedType {
			t.Fatalf("AgentSnapshot field %q has type %v, want %v", field.Name, field.Type, expectedType)
		}
	}
}
