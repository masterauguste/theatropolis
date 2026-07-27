package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

func TestEnrollmentTokenResolvesAgentIdentity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "master", "identities.json")
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := registry.CreateEnrollment(
		ctx,
		"edge-token-only",
		time.Now().Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentID, err := registry.EnrollByToken(ctx, token, publicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if agentID != "edge-token-only" {
		t.Fatalf("resolved agent ID = %q", agentID)
	}
	reopened, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	storedKey, err := reopened.PublicKey(ctx, agentID)
	if err != nil || !bytes.Equal(storedKey, publicKey) {
		t.Fatalf("persisted public key = %x, %v", storedKey, err)
	}
	if _, err := registry.EnrollByToken(ctx, token, publicKey, time.Now()); !errors.Is(err, ErrEnrollmentUnavailable) {
		t.Fatalf("reused token error = %v", err)
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

func TestRevokeInvalidatesPendingAndEnrolledCredentials(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("pending", func(t *testing.T) {
		registry := NewRegistry()
		token, err := registry.CreateEnrollment(ctx, "edge-pending-revoke", now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := registry.Revoke(ctx, "edge-pending-revoke"); err != nil {
			t.Fatal(err)
		}
		if snapshot := registry.Snapshot(now); len(snapshot) != 0 {
			t.Fatalf("revoked pending identity remained in snapshot: %+v", snapshot)
		}
		if err := registry.Enroll(
			ctx,
			"edge-pending-revoke",
			token,
			publicKey,
			now,
		); !errors.Is(err, ErrEnrollmentUnavailable) {
			t.Fatalf("revoked enrollment token error = %v, want ErrEnrollmentUnavailable", err)
		}
		if err := registry.Revoke(ctx, "edge-pending-revoke"); !errors.Is(err, ErrAgentNotFound) {
			t.Fatalf("second Revoke() error = %v, want ErrAgentNotFound", err)
		}
	})

	t.Run("enrolled", func(t *testing.T) {
		registry := NewRegistry()
		token, err := registry.CreateEnrollment(ctx, "edge-enrolled-revoke", now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := registry.Enroll(
			ctx,
			"edge-enrolled-revoke",
			token,
			publicKey,
			now,
		); err != nil {
			t.Fatal(err)
		}
		if err := registry.Revoke(ctx, "edge-enrolled-revoke"); err != nil {
			t.Fatal(err)
		}
		if _, err := registry.PublicKey(
			ctx,
			"edge-enrolled-revoke",
		); !errors.Is(err, ErrAgentNotFound) {
			t.Fatalf("PublicKey() error = %v, want ErrAgentNotFound", err)
		}
		if _, err := registry.CreateEnrollment(
			ctx,
			"edge-enrolled-revoke",
			now.Add(time.Hour),
		); err != nil {
			t.Fatalf("recreate enrollment after revocation: %v", err)
		}
	})

	if err := NewRegistry().Revoke(ctx, "../invalid"); !errors.Is(err, ErrInvalidAgentID) {
		t.Fatalf("invalid agent ID error = %v, want ErrInvalidAgentID", err)
	}
}

func TestPersistentRevocationSurvivesReload(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "master", "identities.json")
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := registry.CreateEnrollment(ctx, "edge-revoked-persistent", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Enroll(
		ctx,
		"edge-revoked-persistent",
		token,
		publicKey,
		now,
	); err != nil {
		t.Fatal(err)
	}
	if err := registry.Revoke(ctx, "edge-revoked-persistent"); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.PublicKey(
		ctx,
		"edge-revoked-persistent",
	); !errors.Is(err, ErrAgentNotFound) {
		t.Fatalf("reloaded PublicKey() error = %v, want ErrAgentNotFound", err)
	}
	if snapshot := reopened.Snapshot(now); len(snapshot) != 0 {
		t.Fatalf("reloaded registry retained revoked identity: %+v", snapshot)
	}
}

func TestRevokeRollsBackWhenPersistenceFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now().UTC()
	registry := NewRegistry()
	token, err := registry.CreateEnrollment(ctx, "edge-revoke-rollback", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Enroll(
		ctx,
		"edge-revoke-rollback",
		token,
		publicKey,
		now,
	); err != nil {
		t.Fatal(err)
	}

	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	registry.persistPath = filepath.Join(parentFile, "identities.json")
	if err := registry.Revoke(ctx, "edge-revoke-rollback"); err == nil {
		t.Fatal("Revoke() unexpectedly succeeded when persistence failed")
	}
	actualPublicKey, err := registry.PublicKey(ctx, "edge-revoke-rollback")
	if err != nil {
		t.Fatalf("credential was not restored: %v", err)
	}
	if !bytes.Equal(actualPublicKey, publicKey) {
		t.Fatal("Revoke() restored a different public key")
	}
}

func TestRegistryRejectsConflictingAgentStates(t *testing.T) {
	t.Parallel()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var tokenDigest [32]byte
	stored := diskRegistry{
		Version: 1,
		Pending: map[string]diskPending{
			"edge-conflict": {
				TokenSHA256: base64.RawURLEncoding.EncodeToString(tokenDigest[:]),
				ExpiresAt:   time.Now().Add(time.Hour),
			},
		},
		Enrolled: map[string]string{
			"edge-conflict": base64.RawURLEncoding.EncodeToString(publicKey),
		},
	}
	encoded, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identities.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRegistry(path); err == nil {
		t.Fatal("OpenRegistry() accepted conflicting pending and enrolled states")
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
