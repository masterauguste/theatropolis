package webui

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	accessFileVersion       = 1
	accessFileMaxBytes      = 4 << 10
	credentialBytes         = 32
	encodedCredentialLength = 43

	DefaultSessionIdleTimeout     = 30 * time.Minute
	DefaultSessionAbsoluteTimeout = 12 * time.Hour
	DefaultLoginFailureLimit      = 10
	DefaultLoginFailureWindow     = time.Minute
	defaultMaxSessions            = 64

	SessionCookieName = "__Host-theatropolis_session"
	CSRFHeaderName    = "X-CSRF-Token"
)

var (
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrLoginRateLimited     = errors.New("too many failed login attempts")
)

type accessDocument struct {
	Version         int
	AccessKeySHA256 string
}

// Session contains the plaintext browser credentials returned at login or
// successful authentication. ExpiresAt is the absolute session expiration;
// the server separately enforces the shorter sliding idle timeout.
type Session struct {
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

type memorySession struct {
	csrfSecret        [credentialBytes]byte
	createdAt         time.Time
	lastSeenAt        time.Time
	absoluteExpiresAt time.Time
}

type loginFailureLimiter struct {
	windowStartedAt time.Time
	failures        int
}

// AccessManager authenticates the persisted operator access key and owns
// ephemeral browser sessions. It never retains plaintext access or session
// tokens.
type AccessManager struct {
	accessKeyDigest [sha256.Size]byte

	mu       sync.Mutex
	sessions map[[sha256.Size]byte]*memorySession
	failures loginFailureLimiter

	sessionIdleTimeout     time.Duration
	sessionAbsoluteTimeout time.Duration
	loginFailureLimit      int
	loginFailureWindow     time.Duration
	maxSessions            int
	now                    func() time.Time
	random                 io.Reader
}

// InitializeAccess creates a new access file without replacing any existing
// path. The returned base64url key is the only plaintext copy and should be
// shown to the operator once.
func InitializeAccess(path string) (plaintextKey string, err error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("access file path is required")
	}

	var key [credentialBytes]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return "", fmt.Errorf("generate operator access key: %w", err)
	}
	defer clear(key[:])

	digest := sha256.Sum256(key[:])
	document, err := json.Marshal(struct {
		Version         int    `json:"version"`
		AccessKeySHA256 string `json:"access_key_sha256"`
	}{
		Version:         accessFileVersion,
		AccessKeySHA256: base64.RawURLEncoding.EncodeToString(digest[:]),
	})
	if err != nil {
		return "", fmt.Errorf("encode access file: %w", err)
	}
	document = append(document, '\n')

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create access file: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = file.Close()
		_ = os.Remove(path)
	}()

	if err := file.Chmod(0o600); err != nil {
		return "", fmt.Errorf("secure access file: %w", err)
	}
	if _, err := file.Write(document); err != nil {
		return "", fmt.Errorf("write access file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync access file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close access file: %w", err)
	}
	committed = true

	return base64.RawURLEncoding.EncodeToString(key[:]), nil
}

// LoadAccess loads the operator access-key digest from disk and creates an
// empty in-memory session manager.
func LoadAccess(path string) (*AccessManager, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("access file path is required")
	}

	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect access file: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, errors.New("access file must be a regular file, not a symbolic link")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open access file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open access file: %w", err)
	}
	if !fileInfo.Mode().IsRegular() || !os.SameFile(pathInfo, fileInfo) {
		return nil, errors.New("access file changed while it was being opened")
	}
	if runtime.GOOS != "windows" &&
		fileInfo.Mode().Perm() != 0o600 &&
		fileInfo.Mode().Perm() != 0o640 {
		return nil, errors.New("access file permissions must be 0600 or 0640")
	}

	encoded, err := io.ReadAll(io.LimitReader(file, accessFileMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read access file: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > accessFileMaxBytes {
		return nil, errors.New("access file is empty or exceeds the size limit")
	}

	document, err := decodeAccessDocument(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode access file: %w", err)
	}
	if document.Version != accessFileVersion {
		return nil, fmt.Errorf("unsupported access file version %d", document.Version)
	}

	decodedDigest, err := base64.RawURLEncoding.DecodeString(document.AccessKeySHA256)
	if err != nil ||
		len(decodedDigest) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(decodedDigest) != document.AccessKeySHA256 {
		return nil, errors.New("access file contains an invalid access-key digest")
	}
	var digest [sha256.Size]byte
	copy(digest[:], decodedDigest)
	clear(decodedDigest)

	return &AccessManager{
		accessKeyDigest:        digest,
		sessions:               make(map[[sha256.Size]byte]*memorySession),
		sessionIdleTimeout:     DefaultSessionIdleTimeout,
		sessionAbsoluteTimeout: DefaultSessionAbsoluteTimeout,
		loginFailureLimit:      DefaultLoginFailureLimit,
		loginFailureWindow:     DefaultLoginFailureWindow,
		maxSessions:            defaultMaxSessions,
		now:                    time.Now,
		random:                 rand.Reader,
	}, nil
}

func decodeAccessDocument(encoded []byte) (accessDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	first, err := decoder.Token()
	if err != nil {
		return accessDocument{}, err
	}
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return accessDocument{}, errors.New("access document must be a JSON object")
	}

	var document accessDocument
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return accessDocument{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return accessDocument{}, errors.New("access document contains a non-string field name")
		}
		if _, duplicate := seen[key]; duplicate {
			return accessDocument{}, fmt.Errorf("access document contains duplicate field %q", key)
		}
		seen[key] = struct{}{}

		switch key {
		case "version":
			if err := decoder.Decode(&document.Version); err != nil {
				return accessDocument{}, err
			}
		case "access_key_sha256":
			if err := decoder.Decode(&document.AccessKeySHA256); err != nil {
				return accessDocument{}, err
			}
		default:
			return accessDocument{}, fmt.Errorf("access document contains unknown field %q", key)
		}
	}
	last, err := decoder.Token()
	if err != nil {
		return accessDocument{}, err
	}
	if delimiter, ok := last.(json.Delim); !ok || delimiter != '}' {
		return accessDocument{}, errors.New("access document is not terminated")
	}
	if _, ok := seen["version"]; !ok {
		return accessDocument{}, errors.New("access document is missing version")
	}
	if _, ok := seen["access_key_sha256"]; !ok {
		return accessDocument{}, errors.New("access document is missing access_key_sha256")
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return accessDocument{}, errors.New("access document contains trailing JSON")
		}
		return accessDocument{}, err
	}
	return document, nil
}

// Login verifies an operator access key and creates a new in-memory session.
// Valid credentials bypass and reset the global failed-login limiter so an
// attacker cannot lock out an operator who still holds the high-entropy key.
func (m *AccessManager) Login(accessKey string) (Session, error) {
	now := m.currentTime()
	if !m.matchesAccessKey(accessKey) {
		m.mu.Lock()
		err := m.recordLoginFailureLocked(now)
		m.mu.Unlock()
		return Session{}, err
	}

	var token [credentialBytes]byte
	var csrf [credentialBytes]byte
	if _, err := io.ReadFull(m.random, token[:]); err != nil {
		return Session{}, fmt.Errorf("generate session token: %w", err)
	}
	defer clear(token[:])
	if _, err := io.ReadFull(m.random, csrf[:]); err != nil {
		return Session{}, fmt.Errorf("generate CSRF token: %w", err)
	}
	defer clear(csrf[:])

	tokenDigest := sha256.Sum256(token[:])
	absoluteExpiresAt := now.Add(m.sessionAbsoluteTimeout)
	session := &memorySession{
		csrfSecret:        csrf,
		createdAt:         now,
		lastSeenAt:        now,
		absoluteExpiresAt: absoluteExpiresAt,
	}

	m.mu.Lock()
	m.failures = loginFailureLimiter{}
	m.purgeExpiredSessionsLocked(now)
	if len(m.sessions) >= m.maxSessions {
		m.evictOldestSessionLocked()
	}
	m.sessions[tokenDigest] = session
	m.mu.Unlock()

	return Session{
		Token:     base64.RawURLEncoding.EncodeToString(token[:]),
		CSRFToken: base64.RawURLEncoding.EncodeToString(csrf[:]),
		ExpiresAt: absoluteExpiresAt,
	}, nil
}

// Authenticate verifies a session token, refreshes its idle deadline, and
// returns the CSRF token needed when rendering protected forms.
func (m *AccessManager) Authenticate(sessionToken string) (Session, error) {
	tokenDigest, valid := credentialDigest(sessionToken)
	now := m.currentTime()

	m.mu.Lock()
	defer m.mu.Unlock()
	session, exists := m.sessions[tokenDigest]
	if valid != 1 || !exists {
		return Session{}, ErrAuthenticationFailed
	}
	if m.sessionExpiredLocked(session, now) {
		delete(m.sessions, tokenDigest)
		return Session{}, ErrAuthenticationFailed
	}
	m.touchSessionLocked(session, now)
	return Session{
		Token:     sessionToken,
		CSRFToken: base64.RawURLEncoding.EncodeToString(session.csrfSecret[:]),
		ExpiresAt: session.absoluteExpiresAt,
	}, nil
}

// AuthorizeCSRF verifies both the session token and its synchronizer CSRF
// secret in constant time. A failed CSRF check does not extend the session.
func (m *AccessManager) AuthorizeCSRF(sessionToken, csrfToken string) bool {
	tokenDigest, tokenValid := credentialDigest(sessionToken)
	candidateCSRF, csrfValid := decodeCredential(csrfToken)
	defer clear(candidateCSRF[:])
	now := m.currentTime()

	m.mu.Lock()
	defer m.mu.Unlock()
	session, exists := m.sessions[tokenDigest]
	if tokenValid != 1 || !exists {
		return false
	}
	if m.sessionExpiredLocked(session, now) {
		delete(m.sessions, tokenDigest)
		return false
	}
	matches := subtle.ConstantTimeCompare(session.csrfSecret[:], candidateCSRF[:]) & csrfValid
	if matches != 1 {
		return false
	}
	m.touchSessionLocked(session, now)
	return true
}

// Logout removes a session when the supplied token is well formed.
func (m *AccessManager) Logout(sessionToken string) {
	tokenDigest, valid := credentialDigest(sessionToken)
	if valid != 1 {
		return
	}
	m.mu.Lock()
	delete(m.sessions, tokenDigest)
	m.mu.Unlock()
}

// NewSessionCookie returns the host-only cookie used by the public HTTPS
// handler. ExpiresAt should be Session.ExpiresAt.
func NewSessionCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// DeleteSessionCookie expires the browser's session cookie immediately.
func DeleteSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func (m *AccessManager) matchesAccessKey(accessKey string) bool {
	candidate, valid := decodeCredential(accessKey)
	defer clear(candidate[:])
	digest := sha256.Sum256(candidate[:])
	return subtle.ConstantTimeCompare(m.accessKeyDigest[:], digest[:])&valid == 1
}

func credentialDigest(encoded string) ([sha256.Size]byte, int) {
	decoded, valid := decodeCredential(encoded)
	defer clear(decoded[:])
	return sha256.Sum256(decoded[:]), valid
}

func decodeCredential(encoded string) ([credentialBytes]byte, int) {
	var credential [credentialBytes]byte
	if len(encoded) != encodedCredentialLength {
		return credential, 0
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != credentialBytes {
		clear(decoded)
		return credential, 0
	}
	copy(credential[:], decoded)
	canonical := base64.RawURLEncoding.EncodeToString(decoded)
	clear(decoded)
	if subtle.ConstantTimeCompare([]byte(canonical), []byte(encoded)) != 1 {
		clear(credential[:])
		return credential, 0
	}
	return credential, 1
}

func (m *AccessManager) recordLoginFailureLocked(now time.Time) error {
	if m.loginFailureLimit <= 0 {
		return ErrLoginRateLimited
	}
	windowExpired := m.failures.windowStartedAt.IsZero() ||
		now.Before(m.failures.windowStartedAt) ||
		!now.Before(m.failures.windowStartedAt.Add(m.loginFailureWindow))
	if windowExpired {
		m.failures = loginFailureLimiter{windowStartedAt: now}
	}
	if m.failures.failures >= m.loginFailureLimit {
		return ErrLoginRateLimited
	}
	m.failures.failures++
	return ErrAuthenticationFailed
}

func (m *AccessManager) purgeExpiredSessionsLocked(now time.Time) {
	for digest, session := range m.sessions {
		if m.sessionExpiredLocked(session, now) {
			delete(m.sessions, digest)
		}
	}
}

func (m *AccessManager) evictOldestSessionLocked() {
	var oldestDigest [sha256.Size]byte
	var oldest *memorySession
	for digest, session := range m.sessions {
		if oldest == nil ||
			session.lastSeenAt.Before(oldest.lastSeenAt) ||
			(session.lastSeenAt.Equal(oldest.lastSeenAt) &&
				session.createdAt.Before(oldest.createdAt)) {
			oldestDigest = digest
			oldest = session
		}
	}
	if oldest != nil {
		delete(m.sessions, oldestDigest)
	}
}

func (m *AccessManager) sessionExpiredLocked(session *memorySession, now time.Time) bool {
	return !now.Before(session.absoluteExpiresAt) ||
		!now.Before(session.lastSeenAt.Add(m.sessionIdleTimeout))
}

func (m *AccessManager) touchSessionLocked(session *memorySession, now time.Time) {
	if now.After(session.lastSeenAt) {
		session.lastSeenAt = now
	}
}

func (m *AccessManager) currentTime() time.Time {
	if m.now == nil {
		return time.Now().UTC()
	}
	return m.now().UTC()
}
