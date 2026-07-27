package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	EnrollmentTokenBytes = 32
	ChallengeNonceBytes  = 32
	maxRegistryFileBytes = 4 << 20
)

var (
	ErrAgentNotFound         = errors.New("agent identity not found")
	ErrAgentAlreadyEnrolled  = errors.New("agent already enrolled")
	ErrEnrollmentPending     = errors.New("agent enrollment is already pending")
	ErrEnrollmentUnavailable = errors.New("enrollment token is invalid or expired")
	ErrInvalidPublicKey      = errors.New("invalid Ed25519 public key")
	ErrInvalidAgentID        = errors.New("invalid agent ID")
)

var agentIDPattern = regexp.MustCompile(`\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\z`)

type pendingEnrollment struct {
	tokenSHA256 [sha256.Size]byte
	expiresAt   time.Time
}

type AgentState string

const (
	AgentStatePending  AgentState = "pending"
	AgentStateEnrolled AgentState = "enrolled"
	AgentStateExpired  AgentState = "expired"
)

// AgentSnapshot is a credential-free view of an identity known to the registry.
// EnrollmentExpiresAt is set only for pending and expired identities.
type AgentSnapshot struct {
	ID                  string
	State               AgentState
	EnrollmentExpiresAt time.Time
}

type Registry struct {
	mu          sync.RWMutex
	pending     map[string]pendingEnrollment
	enrolled    map[string]ed25519.PublicKey
	persistPath string
}

func NewRegistry() *Registry {
	return &Registry{
		pending:  make(map[string]pendingEnrollment),
		enrolled: make(map[string]ed25519.PublicKey),
	}
}

// OpenRegistry opens a registry which persists enrollment-token hashes and
// agent public keys. Agent private keys and plaintext tokens are never stored.
func OpenRegistry(path string) (*Registry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("identity registry path is required")
	}
	registry := NewRegistry()
	registry.persistPath = filepath.Clean(path)

	info, err := os.Lstat(registry.persistPath)
	if errors.Is(err, os.ErrNotExist) {
		return registry, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect identity registry: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("identity registry is not a regular file")
	}
	if info.Size() > maxRegistryFileBytes {
		return nil, errors.New("identity registry exceeds the size limit")
	}
	if err := os.Chmod(registry.persistPath, 0o600); err != nil {
		return nil, fmt.Errorf("secure identity registry: %w", err)
	}

	file, err := os.Open(registry.persistPath)
	if err != nil {
		return nil, fmt.Errorf("open identity registry: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxRegistryFileBytes+1))
	decoder.DisallowUnknownFields()
	var stored diskRegistry
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("decode identity registry: %w", err)
	}
	if stored.Version != 1 {
		return nil, fmt.Errorf("unsupported identity registry version %d", stored.Version)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}

	for agentID, pending := range stored.Pending {
		if !agentIDPattern.MatchString(agentID) {
			return nil, errors.New("identity registry contains an invalid agent ID")
		}
		tokenHash, err := base64.RawURLEncoding.DecodeString(pending.TokenSHA256)
		if err != nil || len(tokenHash) != sha256.Size {
			return nil, errors.New("identity registry contains an invalid enrollment digest")
		}
		var digest [sha256.Size]byte
		copy(digest[:], tokenHash)
		registry.pending[agentID] = pendingEnrollment{
			tokenSHA256: digest,
			expiresAt:   pending.ExpiresAt.UTC(),
		}
	}
	for agentID, encodedPublicKey := range stored.Enrolled {
		if !agentIDPattern.MatchString(agentID) {
			return nil, errors.New("identity registry contains an invalid agent ID")
		}
		if _, pending := registry.pending[agentID]; pending {
			return nil, errors.New("identity registry contains conflicting agent states")
		}
		publicKey, err := base64.RawURLEncoding.DecodeString(encodedPublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.New("identity registry contains an invalid public key")
		}
		registry.enrolled[agentID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return registry, nil
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
		clear(token)
		return nil, ErrAgentAlreadyEnrolled
	}
	previous, hadPrevious := r.pending[agentID]
	if hadPrevious && !time.Now().After(previous.expiresAt) {
		clear(token)
		return nil, ErrEnrollmentPending
	}
	r.pending[agentID] = pendingEnrollment{
		tokenSHA256: sha256.Sum256(token),
		expiresAt:   expiresAt.UTC(),
	}
	if err := r.persistLocked(); err != nil {
		if hadPrevious {
			r.pending[agentID] = previous
		} else {
			delete(r.pending, agentID)
		}
		return nil, err
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
	if err := r.persistLocked(); err != nil {
		delete(r.enrolled, agentID)
		r.pending[agentID] = pending
		return fmt.Errorf("persist enrollment: %w", err)
	}
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

// Revoke durably removes every enrollment credential associated with agentID.
// It removes both maps defensively so a malformed historical registry cannot
// leave a hidden pending token usable after an enrolled identity is revoked.
func (r *Registry) Revoke(_ context.Context, agentID string) error {
	if !agentIDPattern.MatchString(agentID) {
		return ErrInvalidAgentID
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	pending, hadPending := r.pending[agentID]
	publicKey, hadPublicKey := r.enrolled[agentID]
	if !hadPending && !hadPublicKey {
		return ErrAgentNotFound
	}
	delete(r.pending, agentID)
	delete(r.enrolled, agentID)
	if err := r.persistLocked(); err != nil {
		if hadPending {
			r.pending[agentID] = pending
		}
		if hadPublicKey {
			r.enrolled[agentID] = publicKey
		}
		return fmt.Errorf("persist agent revocation: %w", err)
	}
	return nil
}

// Snapshot returns a sorted, credential-free view of registered identities.
func (r *Registry) Snapshot(now time.Time) []AgentSnapshot {
	r.mu.RLock()
	records := make([]AgentSnapshot, 0, len(r.pending)+len(r.enrolled))
	for agentID := range r.enrolled {
		records = append(records, AgentSnapshot{
			ID:    agentID,
			State: AgentStateEnrolled,
		})
	}
	for agentID, pending := range r.pending {
		if _, enrolled := r.enrolled[agentID]; enrolled {
			continue
		}
		state := AgentStatePending
		if now.After(pending.expiresAt) {
			state = AgentStateExpired
		}
		records = append(records, AgentSnapshot{
			ID:                  agentID,
			State:               state,
			EnrollmentExpiresAt: pending.expiresAt.UTC(),
		})
	}
	r.mu.RUnlock()

	sort.Slice(records, func(left, right int) bool {
		return records[left].ID < records[right].ID
	})
	return records
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

type diskRegistry struct {
	Version  int                    `json:"version"`
	Pending  map[string]diskPending `json:"pending"`
	Enrolled map[string]string      `json:"enrolled"`
}

type diskPending struct {
	TokenSHA256 string    `json:"token_sha256"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (r *Registry) persistLocked() error {
	if r.persistPath == "" {
		return nil
	}
	stored := diskRegistry{
		Version:  1,
		Pending:  make(map[string]diskPending, len(r.pending)),
		Enrolled: make(map[string]string, len(r.enrolled)),
	}
	for agentID, pending := range r.pending {
		stored.Pending[agentID] = diskPending{
			TokenSHA256: base64.RawURLEncoding.EncodeToString(pending.tokenSHA256[:]),
			ExpiresAt:   pending.expiresAt.UTC(),
		}
	}
	for agentID, publicKey := range r.enrolled {
		stored.Enrolled[agentID] = base64.RawURLEncoding.EncodeToString(publicKey)
	}
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity registry: %w", err)
	}
	encoded = append(encoded, '\n')

	directory := filepath.Dir(r.persistPath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create identity registry directory: %w", err)
	}
	tempFile, err := os.CreateTemp(directory, ".identities-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary identity registry: %w", err)
	}
	tempPath := tempFile.Name()
	installed := false
	defer func() {
		_ = tempFile.Close()
		if !installed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := tempFile.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary identity registry: %w", err)
	}
	if _, err := tempFile.Write(encoded); err != nil {
		return fmt.Errorf("write temporary identity registry: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("flush temporary identity registry: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temporary identity registry: %w", err)
	}
	if err := replaceFile(tempPath, r.persistPath); err != nil {
		return fmt.Errorf("replace identity registry: %w", err)
	}
	installed = true
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("identity registry contains trailing JSON data")
		}
		return fmt.Errorf("decode trailing identity registry data: %w", err)
	}
	return nil
}
