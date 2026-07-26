package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

const (
	EnrollmentTokenBytes = 32
	ChallengeNonceBytes  = 32
)

var (
	ErrAgentNotFound         = errors.New("agent identity not found")
	ErrAgentAlreadyEnrolled  = errors.New("agent already enrolled")
	ErrEnrollmentUnavailable = errors.New("enrollment token is invalid or expired")
	ErrInvalidPublicKey      = errors.New("invalid Ed25519 public key")
	ErrInvalidAgentID        = errors.New("invalid agent ID")
)

var agentIDPattern = regexp.MustCompile(`\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\z`)

type pendingEnrollment struct {
	tokenSHA256 [sha256.Size]byte
	expiresAt   time.Time
}

type Registry struct {
	mu       sync.RWMutex
	pending  map[string]pendingEnrollment
	enrolled map[string]ed25519.PublicKey
}

func NewRegistry() *Registry {
	return &Registry{
		pending:  make(map[string]pendingEnrollment),
		enrolled: make(map[string]ed25519.PublicKey),
	}
}

func (r *Registry) CreateEnrollment(
	_ context.Context,
	agentID string,
	expiresAt time.Time,
) ([]byte, error) {
	if !agentIDPattern.MatchString(agentID) {
		return nil, ErrInvalidAgentID
	}
	if expiresAt.IsZero() || !expiresAt.After(time.Now()) {
		return nil, errors.New("enrollment expiry must be in the future")
	}

	token := make([]byte, EnrollmentTokenBytes)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("generate enrollment token: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.enrolled[agentID]; exists {
		return nil, ErrAgentAlreadyEnrolled
	}
	r.pending[agentID] = pendingEnrollment{
		tokenSHA256: sha256.Sum256(token),
		expiresAt:   expiresAt.UTC(),
	}
	return token, nil
}

func (r *Registry) Enroll(
	_ context.Context,
	agentID string,
	token []byte,
	publicKey []byte,
	now time.Time,
) error {
	if !agentIDPattern.MatchString(agentID) {
		return ErrInvalidAgentID
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidPublicKey
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.enrolled[agentID]; exists {
		return ErrAgentAlreadyEnrolled
	}
	pending, exists := r.pending[agentID]
	tokenHash := sha256.Sum256(token)
	if !exists ||
		now.After(pending.expiresAt) ||
		subtle.ConstantTimeCompare(tokenHash[:], pending.tokenSHA256[:]) != 1 {
		return ErrEnrollmentUnavailable
	}

	r.enrolled[agentID] = append(ed25519.PublicKey(nil), publicKey...)
	delete(r.pending, agentID)
	return nil
}

func (r *Registry) PublicKey(_ context.Context, agentID string) (ed25519.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	publicKey, exists := r.enrolled[agentID]
	if !exists {
		return nil, ErrAgentNotFound
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

func NewChallenge() ([]byte, error) {
	nonce := make([]byte, ChallengeNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}
	return nonce, nil
}

func ChallengePayload(agentID string, nonce []byte) []byte {
	const domain = "theatropolis-agent-auth-v1"

	payload := make([]byte, 0, len(domain)+4+len(agentID)+4+len(nonce))
	payload = append(payload, domain...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(agentID)))
	payload = append(payload, agentID...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(nonce)))
	payload = append(payload, nonce...)
	return payload
}

func VerifyProof(publicKey ed25519.PublicKey, agentID string, nonce, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize ||
		len(nonce) != ChallengeNonceBytes ||
		len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, ChallengePayload(agentID, nonce), signature)
}
