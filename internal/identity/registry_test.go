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
	"strings"
	"testing"
	"time"
)

func enrollByTokenForTest(
	registry *Registry,
	ctx context.Context,
	token []byte,
	publicKey []byte,
	now time.Time,
) error {
	_, err := registry.EnrollByToken(ctx, token, publicKey, now)
	return err
}

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
	if err := enrollByTokenForTest(registry, ctx, token, publicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := enrollByTokenForTest(registry, ctx, token, publicKey, time.Now()); !errors.Is(err, ErrEnrollmentUnavailable) {
		t.Fatalf("expected enrollment to be single use, got %v", err)
	}

	nonce, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, ChallengePayload(publicKey, nonce))
	if !VerifyProof(publicKey, nonce, signature) {
		t.Fatal("valid proof was rejected")
	}
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyProof(otherPublicKey, nonce, signature) {
		t.Fatal("proof was accepted for another public key")
	}
}

func TestHasRecordDistinguishesRevokedIdentityFromEnrollmentState(t *testing.T) {
	ctx := context.Background()
	registry := NewRegistry()
	const agentID = "edge-record-lifecycle"
	if registry.HasRecord(agentID) {
		t.Fatal("unknown Agent unexpectedly has a registry record")
	}
	token, err := registry.CreateEnrollment(ctx, agentID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !registry.HasRecord(agentID) {
		t.Fatal("pending enrollment is not recognized as an existing record")
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.EnrollByToken(ctx, token, publicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !registry.HasRecord(agentID) {
		t.Fatal("enrolled Agent is not recognized as an existing record")
	}
	if err := registry.Revoke(ctx, agentID); err != nil {
		t.Fatal(err)
	}
	if registry.HasRecord(agentID) {
		t.Fatal("revoked Agent still has a registry record")
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
	resolvedAgentID, err := registry.AgentIDForPublicKey(ctx, publicKey)
	if err != nil || resolvedAgentID != "edge-token-only" {
		t.Fatalf("public-key-resolved Agent ID = %q, %v", resolvedAgentID, err)
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

func TestEnrollmentRejectsDuplicatePublicKeyWithoutConsumingToken(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	registry := NewRegistry()
	now := time.Now().UTC()
	firstToken, err := registry.CreateEnrollment(ctx, "edge-one", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	sharedPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.EnrollByToken(ctx, firstToken, sharedPublicKey, now); err != nil {
		t.Fatal(err)
	}
	secondToken, err := registry.CreateEnrollment(ctx, "edge-two", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.EnrollByToken(
		ctx,
		secondToken,
		sharedPublicKey,
		now,
	); !errors.Is(err, ErrPublicKeyEnrolled) {
		t.Fatalf("duplicate public key error = %v", err)
	}
	uniquePublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if agentID, err := registry.EnrollByToken(
		ctx,
		secondToken,
		uniquePublicKey,
		now,
	); err != nil || agentID != "edge-two" {
		t.Fatalf("retry with unique key = %q, %v", agentID, err)
	}
}

func TestReplacementEnrollmentSwapsKeyOnlyWhenRedeemed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "master", "identities.json")
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	firstToken, err := registry.CreateEnrollment(ctx, "edge-replaced", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	firstPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.EnrollByToken(ctx, firstToken, firstPublicKey, now); err != nil {
		t.Fatal(err)
	}

	replacementToken, err := registry.CreateReplacementEnrollment(
		ctx,
		"edge-replaced",
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeRedemption, err := reopened.PublicKey(ctx, "edge-replaced")
	if err != nil || !bytes.Equal(beforeRedemption, firstPublicKey) {
		t.Fatalf("key before replacement redemption = %x, %v", beforeRedemption, err)
	}
	replacementPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agentID, err := reopened.EnrollByToken(
		ctx,
		replacementToken,
		replacementPublicKey,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if agentID != "edge-replaced" {
		t.Fatalf("replacement Agent ID = %q", agentID)
	}
	afterRedemption, err := reopened.PublicKey(ctx, "edge-replaced")
	if err != nil || !bytes.Equal(afterRedemption, replacementPublicKey) {
		t.Fatalf("key after replacement redemption = %x, %v", afterRedemption, err)
	}
	if _, err := reopened.EnrollByToken(
		ctx,
		replacementToken,
		replacementPublicKey,
		now,
	); !errors.Is(err, ErrEnrollmentUnavailable) {
		t.Fatalf("replacement token reuse error = %v", err)
	}
	if _, err := reopened.CreateReplacementEnrollment(
		ctx,
		"missing-agent",
		now.Add(time.Hour),
	); !errors.Is(err, ErrAgentNotFound) {
		t.Fatalf("missing replacement Agent error = %v", err)
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
	if err := enrollByTokenForTest(reopened, ctx, token, publicKey, time.Now()); err != nil {
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
	if err := enrollByTokenForTest(
		registry,
		ctx,
		enrollmentToken,
		publicKey,
		now,
	); err != nil {
		t.Fatal(err)
	}

	snapshot := registry.Snapshot(now.Add(90 * time.Minute))
	expected := []AgentSnapshot{
		{
			ID:          "alpha-enrolled",
			DisplayName: "alpha-enrolled",
			State:       AgentStateEnrolled,
		},
		{
			ID:                  "middle-expired",
			DisplayName:         "middle-expired",
			State:               AgentStateExpired,
			EnrollmentExpiresAt: expiredExpiry,
		},
		{
			ID:                  "zulu-pending",
			DisplayName:         "zulu-pending",
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
	if err := enrollByTokenForTest(
		registry,
		ctx,
		firstToken,
		publicKey,
		time.Now(),
	); err != nil {
		t.Fatalf("first token was invalidated by rejected duplicate: %v", err)
	}
}

func TestOpaqueEnrollmentDisplayNameRenamePersistsWithoutChangingIdentity(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "identities.json")
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour)
	agentID, token, err := registry.CreateEnrollmentForDisplayName(
		context.Background(),
		"  上海 中继  ",
		expiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(agentID, "agt_") || agentID == "上海 中继" || !ValidAgentID(agentID) {
		t.Fatalf("opaque agent ID = %q", agentID)
	}
	if got := registry.DisplayName(agentID); got != "上海 中继" {
		t.Fatalf("display name = %q, want 上海 中继", got)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := enrollByTokenForTest(registry, context.Background(), token, publicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := registry.RenameDisplayName(agentID, "东京 出口"); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.DisplayName(agentID); got != "东京 出口" {
		t.Fatalf("reopened display name = %q, want 东京 出口", got)
	}
	resolved, err := reopened.AgentIDForPublicKey(context.Background(), publicKey)
	if err != nil || resolved != agentID {
		t.Fatalf("resolved ID after rename = %q, %v; want %q", resolved, err, agentID)
	}
}

func TestLegacyLongAgentIDUsesUnpersistedDisplayFallback(t *testing.T) {
	t.Parallel()

	legacyID := strings.Repeat("a", 128)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stored := diskRegistry{
		Version: 1,
		Pending: map[string]diskPending{},
		Enrolled: map[string]string{
			legacyID: base64.RawURLEncoding.EncodeToString(publicKey),
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
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := registry.DisplayName(legacyID); got != legacyID {
		t.Fatalf("legacy display fallback = %q", got)
	}
	if _, _, err := registry.CreateEnrollmentForDisplayName(
		context.Background(),
		"新服务器",
		time.Now().Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRegistry(path)
	if err != nil {
		t.Fatalf("reopen migrated registry: %v", err)
	}
	if got := reopened.DisplayName(legacyID); got != legacyID {
		t.Fatalf("migrated legacy display fallback = %q", got)
	}
}

func TestDisplayNamesAreUniqueByUnicodeCaseFold(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	firstID, _, err := registry.CreateEnrollmentForDisplayName(
		context.Background(),
		"Édge 上海",
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.CreateEnrollmentForDisplayName(
		context.Background(),
		"e\u0301DGE 上海",
		time.Now().Add(time.Hour),
	); !errors.Is(err, ErrDisplayNameExists) {
		t.Fatalf("case-fold duplicate create error = %v, want ErrDisplayNameExists", err)
	}
	if err := registry.RenameDisplayName(firstID, "另一个 名称"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.CreateEnrollmentForDisplayName(
		context.Background(),
		"ÉDGE 上海",
		time.Now().Add(time.Hour),
	); err != nil {
		t.Fatalf("old display name remained reserved after rename: %v", err)
	}
}

func TestLegacyCaseFoldDuplicateFallbacksDoNotBlockOpen(t *testing.T) {
	t.Parallel()

	publicKeyA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stored := diskRegistry{
		Version: 1,
		Pending: map[string]diskPending{},
		Enrolled: map[string]string{
			"EDGE": base64.RawURLEncoding.EncodeToString(publicKeyA),
			"edge": base64.RawURLEncoding.EncodeToString(publicKeyB),
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
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatalf("legacy duplicate fallback names must load: %v", err)
	}
	if _, _, err := registry.CreateEnrollmentForDisplayName(
		context.Background(),
		"Edge",
		time.Now().Add(time.Hour),
	); !errors.Is(err, ErrDisplayNameExists) {
		t.Fatalf("new name colliding with legacy fallback error = %v", err)
	}
	if _, _, err := registry.CreateEnrollmentForDisplayName(
		context.Background(),
		"东京 中继",
		time.Now().Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRegistry(path); err != nil {
		t.Fatalf("v2 registry must preserve legacy fallback-only duplicates: %v", err)
	}
}

func TestOpenRegistryRejectsExplicitDisplayNameConflictsAndNonCanonicalValues(t *testing.T) {
	t.Parallel()

	publicKeyA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedA := base64.RawURLEncoding.EncodeToString(publicKeyA)
	encodedB := base64.RawURLEncoding.EncodeToString(publicKeyB)
	tests := []struct {
		name         string
		enrolled     map[string]string
		displayNames map[string]string
	}{
		{
			name: "two explicit names",
			enrolled: map[string]string{
				"server-a": encodedA,
				"server-b": encodedB,
			},
			displayNames: map[string]string{
				"server-a": "上海 Edge",
				"server-b": "上海 EDGE",
			},
		},
		{
			name: "explicit name and legacy fallback",
			enrolled: map[string]string{
				"EDGE":     encodedA,
				"server-b": encodedB,
			},
			displayNames: map[string]string{
				"server-b": "edge",
			},
		},
		{
			name: "non canonical value",
			enrolled: map[string]string{
				"server-a": encodedA,
			},
			displayNames: map[string]string{
				"server-a": " Cafe\u0301 ",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identities.json")
			encoded, err := json.Marshal(diskRegistry{
				Version:      2,
				Pending:      map[string]diskPending{},
				Enrolled:     test.enrolled,
				DisplayNames: test.displayNames,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenRegistry(path); err == nil {
				t.Fatal("OpenRegistry() accepted conflicting or non-canonical display names")
			}
		})
	}
}

func TestCompatibilityEnrollmentChecksExplicitDisplayNamesButAllowsLegacyFallbacks(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	if _, _, err := registry.CreateEnrollmentForDisplayName(
		context.Background(),
		"Edge",
		time.Now().Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CreateEnrollment(
		context.Background(),
		"EDGE",
		time.Now().Add(time.Hour),
	); !errors.Is(err, ErrDisplayNameExists) {
		t.Fatalf("fallback colliding with explicit display name error = %v, want ErrDisplayNameExists", err)
	}

	registry = NewRegistry()
	if _, err := registry.CreateEnrollment(context.Background(), "EDGE", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CreateEnrollment(context.Background(), "edge", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("legacy fallback-only duplicate was rejected: %v", err)
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
	if err := enrollByTokenForTest(
		registry,
		ctx,
		oldToken,
		publicKey,
		time.Now(),
	); !errors.Is(err, ErrEnrollmentUnavailable) {
		t.Fatalf("old token error = %v, want ErrEnrollmentUnavailable", err)
	}
	if err := enrollByTokenForTest(
		registry,
		ctx,
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
		if err := enrollByTokenForTest(
			registry,
			ctx,
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
		if err := enrollByTokenForTest(
			registry,
			ctx,
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
	if err := enrollByTokenForTest(
		registry,
		ctx,
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
	if err := enrollByTokenForTest(
		registry,
		ctx,
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

func TestRegistryLoadsEnrolledIdentityWithPendingReplacement(t *testing.T) {
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
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := registry.PublicKey(context.Background(), "edge-conflict")
	if err != nil || !bytes.Equal(actual, publicKey) {
		t.Fatalf("active replacement key = %x, %v", actual, err)
	}
}

func TestAgentSnapshotContainsNoCredentialFields(t *testing.T) {
	t.Parallel()

	recordType := reflect.TypeOf(AgentSnapshot{})
	expectedFields := map[string]reflect.Type{
		"ID":                  reflect.TypeOf(""),
		"DisplayName":         reflect.TypeOf(""),
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
