package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
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
