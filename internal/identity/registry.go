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
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	EnrollmentTokenBytes = 32
	ChallengeNonceBytes  = 32
	maxRegistryFileBytes = 4 << 20
	maxDisplayNameRunes  = 60
	maxDisplayNameBytes  = maxDisplayNameRunes * utf8.UTFMax
	agentRecordIDBytes   = 18
)

var (
	ErrAgentNotFound         = errors.New("agent identity not found")
	ErrAgentAlreadyEnrolled  = errors.New("agent already enrolled")
	ErrEnrollmentPending     = errors.New("agent enrollment is already pending")
	ErrEnrollmentUnavailable = errors.New("enrollment token is invalid or expired")
	ErrInvalidPublicKey      = errors.New("invalid Ed25519 public key")
	ErrPublicKeyEnrolled     = errors.New("Ed25519 public key is already enrolled")
	ErrInvalidAgentID        = errors.New("invalid agent ID")
	ErrInvalidDisplayName    = errors.New("invalid server display name")
	ErrDisplayNameExists     = errors.New("server display name already exists")
)

var agentIDPattern = regexp.MustCompile(`\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\z`)

func ValidAgentID(agentID string) bool {
	return agentIDPattern.MatchString(agentID)
}

func NormalizeDisplayName(value string) string {
	return norm.NFC.String(strings.TrimSpace(value))
}

func foldedDisplayName(value string) string {
	return norm.NFC.String(cases.Fold().String(NormalizeDisplayName(value)))
}

func ValidDisplayName(value string) bool {
	if !utf8.ValidString(value) || value == "" || len(value) > maxDisplayNameBytes || utf8.RuneCountInString(value) > maxDisplayNameRunes {
		return false
	}
	for index, character := range value {
		if index == 0 {
			if !unicode.IsLetter(character) && !unicode.IsDigit(character) {
				return false
			}
			continue
		}
		if unicode.IsLetter(character) || unicode.IsDigit(character) || unicode.IsMark(character) {
			continue
		}
		switch character {
		case ' ', '.', '_', '-':
			continue
		default:
			return false
		}
	}
	return true
}

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
	DisplayName         string
	State               AgentState
	EnrollmentExpiresAt time.Time
}

type Registry struct {
	mu           sync.RWMutex
	pending      map[string]pendingEnrollment
	enrolled     map[string]ed25519.PublicKey
	displayNames map[string]string
	persistPath  string
}

func NewRegistry() *Registry {
	return &Registry{
		pending:      make(map[string]pendingEnrollment),
		enrolled:     make(map[string]ed25519.PublicKey),
		displayNames: make(map[string]string),
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
	if stored.Version != 1 && stored.Version != 2 {
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
		publicKey, err := base64.RawURLEncoding.DecodeString(encodedPublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.New("identity registry contains an invalid public key")
		}
		registry.enrolled[agentID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	for agentID, displayName := range stored.DisplayNames {
		if !agentIDPattern.MatchString(agentID) {
			return nil, errors.New("identity registry contains a display name for an invalid agent ID")
		}
		if _, pending := registry.pending[agentID]; !pending {
			if _, enrolled := registry.enrolled[agentID]; !enrolled {
				return nil, errors.New("identity registry contains an orphaned display name")
			}
		}
		if displayName != NormalizeDisplayName(displayName) || !ValidDisplayName(displayName) {
			return nil, errors.New("identity registry contains an invalid server display name")
		}
		registry.displayNames[agentID] = displayName
	}
	if registry.hasDisplayNameConflictLocked() {
		return nil, errors.New("identity registry contains conflicting server display names")
	}
	return registry, nil
}

func (r *Registry) CreateEnrollment(
	_ context.Context,
	agentID string,
	expiresAt time.Time,
) ([]byte, error) {
	return r.createEnrollment(agentID, "", expiresAt, false, false)
}

func (r *Registry) CreateEnrollmentWithDisplayName(
	_ context.Context,
	agentID string,
	displayName string,
	expiresAt time.Time,
) ([]byte, error) {
	displayName = NormalizeDisplayName(displayName)
	if !ValidDisplayName(displayName) {
		return nil, ErrInvalidDisplayName
	}
	return r.createEnrollment(agentID, displayName, expiresAt, false, false)
}

// CreateEnrollmentForDisplayName atomically creates a private opaque record ID
// and a public, mutable server display name. Callers must not expose or derive
// authorization from the generated ID.
func (r *Registry) CreateEnrollmentForDisplayName(
	_ context.Context,
	displayName string,
	expiresAt time.Time,
) (string, []byte, error) {
	displayName = NormalizeDisplayName(displayName)
	if !ValidDisplayName(displayName) {
		return "", nil, ErrInvalidDisplayName
	}
	for attempt := 0; attempt < 4; attempt++ {
		randomID := make([]byte, agentRecordIDBytes)
		if _, err := rand.Read(randomID); err != nil {
			return "", nil, fmt.Errorf("generate server record ID: %w", err)
		}
		agentID := "agt_" + base64.RawURLEncoding.EncodeToString(randomID)
		token, err := r.createEnrollment(agentID, displayName, expiresAt, false, true)
		if errors.Is(err, ErrEnrollmentPending) || errors.Is(err, ErrAgentAlreadyEnrolled) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return agentID, token, nil
	}
	return "", nil, errors.New("generate unique server record ID")
}

// CreateReplacementEnrollment creates a single-use credential that replaces
// the public key of an already enrolled Agent only when redeemed. The current
// key remains authorized until then, so preparing a replacement does not
// interrupt the live Agent.
func (r *Registry) CreateReplacementEnrollment(
	_ context.Context,
	agentID string,
	expiresAt time.Time,
) ([]byte, error) {
	return r.createEnrollment(agentID, "", expiresAt, true, false)
}

func (r *Registry) createEnrollment(
	agentID string,
	displayName string,
	expiresAt time.Time,
	replacement bool,
	requireUnused bool,
) ([]byte, error) {
	if !agentIDPattern.MatchString(agentID) {
		return nil, ErrInvalidAgentID
	}
	if expiresAt.IsZero() || !expiresAt.After(time.Now()) {
		return nil, errors.New("enrollment expiry must be in the future")
	}
	if !replacement && displayName != "" {
		displayName = NormalizeDisplayName(displayName)
		if !ValidDisplayName(displayName) {
			return nil, ErrInvalidDisplayName
		}
	}

	token := make([]byte, EnrollmentTokenBytes)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("generate enrollment token: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	_, enrolled := r.enrolled[agentID]
	_, pendingExists := r.pending[agentID]
	if requireUnused && (enrolled || pendingExists) {
		clear(token)
		if enrolled {
			return nil, ErrAgentAlreadyEnrolled
		}
		return nil, ErrEnrollmentPending
	}
	if replacement && !enrolled {
		clear(token)
		return nil, ErrAgentNotFound
	}
	if !replacement && enrolled {
		clear(token)
		return nil, ErrAgentAlreadyEnrolled
	}
	if !replacement {
		effectiveDisplayName := displayName
		explicitDisplayName := displayName != ""
		if effectiveDisplayName == "" {
			effectiveDisplayName = r.displayNameLocked(agentID)
			_, explicitDisplayName = r.displayNames[agentID]
		}
		if r.displayNameConflictsLocked(agentID, effectiveDisplayName, explicitDisplayName) {
			clear(token)
			return nil, ErrDisplayNameExists
		}
	}
	previous, hadPrevious := r.pending[agentID]
	previousDisplayName, hadPreviousDisplayName := r.displayNames[agentID]
	if hadPrevious && !time.Now().After(previous.expiresAt) {
		clear(token)
		return nil, ErrEnrollmentPending
	}
	r.pending[agentID] = pendingEnrollment{
		tokenSHA256: sha256.Sum256(token),
		expiresAt:   expiresAt.UTC(),
	}
	if !replacement && displayName != "" {
		r.displayNames[agentID] = displayName
	}
	if err := r.persistLocked(); err != nil {
		if hadPrevious {
			r.pending[agentID] = previous
		} else {
			delete(r.pending, agentID)
		}
		if hadPreviousDisplayName {
			r.displayNames[agentID] = previousDisplayName
		} else {
			delete(r.displayNames, agentID)
		}
		return nil, err
	}
	return token, nil
}

// EnrollByToken resolves the pending agent record from its single-use token.
// New agents therefore do not need to be told the master's internal agent ID.
// Every pending digest is compared so a token lookup does not reveal which
// record, if any, matched through an early return.
func (r *Registry) EnrollByToken(
	_ context.Context,
	token []byte,
	publicKey []byte,
	now time.Time,
) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalidPublicKey
	}

	tokenHash := sha256.Sum256(token)
	r.mu.Lock()
	defer r.mu.Unlock()

	matchedAgentID := ""
	for agentID, pending := range r.pending {
		matches := subtle.ConstantTimeCompare(
			tokenHash[:],
			pending.tokenSHA256[:],
		)
		if matches == 1 && !now.After(pending.expiresAt) {
			if matchedAgentID != "" {
				return "", ErrEnrollmentUnavailable
			}
			matchedAgentID = agentID
		}
	}
	if matchedAgentID == "" {
		return "", ErrEnrollmentUnavailable
	}
	for agentID, enrolledPublicKey := range r.enrolled {
		if agentID != matchedAgentID && subtle.ConstantTimeCompare(
			publicKey,
			enrolledPublicKey,
		) == 1 {
			return "", ErrPublicKeyEnrolled
		}
	}
	pending := r.pending[matchedAgentID]
	previousPublicKey, replacing := r.enrolled[matchedAgentID]
	r.enrolled[matchedAgentID] = append(
		ed25519.PublicKey(nil),
		publicKey...,
	)
	delete(r.pending, matchedAgentID)
	if err := r.persistLocked(); err != nil {
		if replacing {
			r.enrolled[matchedAgentID] = previousPublicKey
		} else {
			delete(r.enrolled, matchedAgentID)
		}
		r.pending[matchedAgentID] = pending
		return "", fmt.Errorf("persist enrollment: %w", err)
	}
	return matchedAgentID, nil
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

// DisplayName resolves the mutable human-readable name for a private server
// record. Unknown records deliberately fall back to the supplied ID so display
// lookups never change authorization or routing decisions.
func (r *Registry) DisplayName(agentID string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.displayNameLocked(agentID)
}

func (r *Registry) displayNameLocked(agentID string) string {
	if displayName := r.displayNames[agentID]; displayName != "" {
		return displayName
	}
	return agentID
}

func (r *Registry) displayNameExistsLocked(exceptAgentID, displayName string) bool {
	return r.displayNameConflictsLocked(exceptAgentID, displayName, true)
}

func (r *Registry) displayNameConflictsLocked(exceptAgentID, displayName string, explicitDisplayName bool) bool {
	folded := foldedDisplayName(displayName)
	visited := make(map[string]struct{}, len(r.pending)+len(r.enrolled))
	conflicts := func(agentID string) bool {
		if agentID == exceptAgentID {
			return false
		}
		if _, exists := visited[agentID]; exists {
			return false
		}
		visited[agentID] = struct{}{}
		_, otherExplicit := r.displayNames[agentID]
		return foldedDisplayName(r.displayNameLocked(agentID)) == folded && (explicitDisplayName || otherExplicit)
	}
	for agentID := range r.pending {
		if conflicts(agentID) {
			return true
		}
	}
	for agentID := range r.enrolled {
		if conflicts(agentID) {
			return true
		}
	}
	return false
}

func (r *Registry) hasDisplayNameConflictLocked() bool {
	type displayNameClaim struct {
		agentID  string
		explicit bool
	}
	claims := make(map[string]displayNameClaim, len(r.pending)+len(r.enrolled))
	visited := make(map[string]struct{}, len(r.pending)+len(r.enrolled))
	visit := func(agentID string) bool {
		if _, exists := visited[agentID]; exists {
			return false
		}
		visited[agentID] = struct{}{}
		_, explicit := r.displayNames[agentID]
		key := foldedDisplayName(r.displayNameLocked(agentID))
		if previous, exists := claims[key]; exists {
			return previous.agentID != agentID && (previous.explicit || explicit)
		}
		claims[key] = displayNameClaim{agentID: agentID, explicit: explicit}
		return false
	}
	for agentID := range r.pending {
		if visit(agentID) {
			return true
		}
	}
	for agentID := range r.enrolled {
		if visit(agentID) {
			return true
		}
	}
	return false
}

// RenameDisplayName changes only the human-readable label. The immutable
// server-record ID, enrolled key, topology references, and URLs are untouched.
func (r *Registry) RenameDisplayName(agentID, displayName string) error {
	if !agentIDPattern.MatchString(agentID) {
		return ErrInvalidAgentID
	}
	displayName = NormalizeDisplayName(displayName)
	if !ValidDisplayName(displayName) {
		return ErrInvalidDisplayName
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, pending := r.pending[agentID]; !pending {
		if _, enrolled := r.enrolled[agentID]; !enrolled {
			return ErrAgentNotFound
		}
	}
	if r.displayNameExistsLocked(agentID, displayName) {
		return ErrDisplayNameExists
	}
	previous, hadPrevious := r.displayNames[agentID]
	r.displayNames[agentID] = displayName
	if err := r.persistLocked(); err != nil {
		if hadPrevious {
			r.displayNames[agentID] = previous
		} else {
			delete(r.displayNames, agentID)
		}
		return fmt.Errorf("persist server display name: %w", err)
	}
	return nil
}

// AgentIDForPublicKey resolves an authenticated transport key to the master's
// private server record. Agents never receive or submit that record ID.
func (r *Registry) AgentIDForPublicKey(
	_ context.Context,
	publicKey []byte,
) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalidPublicKey
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	matchedAgentID := ""
	for agentID, enrolledPublicKey := range r.enrolled {
		if subtle.ConstantTimeCompare(publicKey, enrolledPublicKey) != 1 {
			continue
		}
		if matchedAgentID != "" {
			// Historical duplicate keys are ambiguous and therefore cannot
			// authenticate either record.
			return "", ErrAgentNotFound
		}
		matchedAgentID = agentID
	}
	if matchedAgentID == "" {
		return "", ErrAgentNotFound
	}
	return matchedAgentID, nil
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
	displayName, hadDisplayName := r.displayNames[agentID]
	if !hadPending && !hadPublicKey {
		return ErrAgentNotFound
	}
	delete(r.pending, agentID)
	delete(r.enrolled, agentID)
	delete(r.displayNames, agentID)
	if err := r.persistLocked(); err != nil {
		if hadPending {
			r.pending[agentID] = pending
		}
		if hadPublicKey {
			r.enrolled[agentID] = publicKey
		}
		if hadDisplayName {
			r.displayNames[agentID] = displayName
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
			ID:          agentID,
			DisplayName: r.displayNameLocked(agentID),
			State:       AgentStateEnrolled,
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
			DisplayName:         r.displayNameLocked(agentID),
			State:               state,
			EnrollmentExpiresAt: pending.expiresAt.UTC(),
		})
	}
	r.mu.RUnlock()

	sort.Slice(records, func(left, right int) bool {
		if records[left].DisplayName != records[right].DisplayName {
			return records[left].DisplayName < records[right].DisplayName
		}
		return records[left].ID < records[right].ID
	})
	return records
}

// MigrationSnapshot exports enrolled Agent public keys without pending
// enrollment-token digests. Existing Agent private keys therefore remain able
// to authenticate to a restored Master, while unused invitations do not cross
// the migration boundary.
func (r *Registry) MigrationSnapshot() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	stored := diskRegistry{
		Version:      2,
		Pending:      map[string]diskPending{},
		Enrolled:     make(map[string]string, len(r.enrolled)),
		DisplayNames: make(map[string]string, len(r.enrolled)),
	}
	for agentID, publicKey := range r.enrolled {
		stored.Enrolled[agentID] = base64.RawURLEncoding.EncodeToString(publicKey)
		if displayName := r.displayNames[agentID]; displayName != "" {
			stored.DisplayNames[agentID] = displayName
		}
	}
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode migration identity registry: %w", err)
	}
	return append(encoded, '\n'), nil
}

func NewChallenge() ([]byte, error) {
	nonce := make([]byte, ChallengeNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}
	return nonce, nil
}

func ChallengePayload(publicKey, nonce []byte) []byte {
	const domain = "theatropolis-agent-auth-v2"

	payload := make([]byte, 0, len(domain)+4+len(publicKey)+4+len(nonce))
	payload = append(payload, domain...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(publicKey)))
	payload = append(payload, publicKey...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(nonce)))
	payload = append(payload, nonce...)
	return payload
}

func VerifyProof(publicKey ed25519.PublicKey, nonce, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize ||
		len(nonce) != ChallengeNonceBytes ||
		len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, ChallengePayload(publicKey, nonce), signature)
}

type diskRegistry struct {
	Version      int                    `json:"version"`
	Pending      map[string]diskPending `json:"pending"`
	Enrolled     map[string]string      `json:"enrolled"`
	DisplayNames map[string]string      `json:"display_names,omitempty"`
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
		Version:      2,
		Pending:      make(map[string]diskPending, len(r.pending)),
		Enrolled:     make(map[string]string, len(r.enrolled)),
		DisplayNames: make(map[string]string, len(r.displayNames)),
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
	for agentID, displayName := range r.displayNames {
		if _, pending := r.pending[agentID]; !pending {
			if _, enrolled := r.enrolled[agentID]; !enrolled {
				continue
			}
		}
		stored.DisplayNames[agentID] = displayName
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
