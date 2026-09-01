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
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	endUserAccessFileVersion   = 1
	unifiedIdentityFileVersion = 3
	endUserSessionFileVersion  = 1
	endUserAccessFileMaxBytes  = 16 << 20
	endUserSessionMaxBytes     = 16 << 20
	defaultEndUserMaxSessions  = 4096
	defaultUserInviteLifetime  = 24 * time.Hour

	EndUserSessionCookieName = "__Host-theatropolis_user_session"
	EndUserClaimCookieName   = "__Host-theatropolis_user_claim"
)

type identityRole string

const (
	identityRoleAdministrator identityRole = "administrator"
	identityRoleUser          identityRole = "user"
	administratorIdentityID                = "administrator"
	credentialTypeAccessKey                = "access_key"
	credentialTypePassword                 = "password"
)

type unifiedIdentityDocument struct {
	Version    int                        `json:"version"`
	Identities []persistedUnifiedIdentity `json:"identities"`
}

type persistedUnifiedIdentity struct {
	ID              string       `json:"id"`
	Role            identityRole `json:"role"`
	CredentialType  string       `json:"credential_type,omitempty"`
	LoginUsername   string       `json:"login_username,omitempty"`
	AuthRevision    uint64       `json:"auth_revision"`
	AccessKeySHA256 string       `json:"access_key_sha256,omitempty"`
	PasswordSalt    string       `json:"password_salt,omitempty"`
	PasswordHash    string       `json:"password_hash,omitempty"`
	InviteSHA256    string       `json:"invite_sha256,omitempty"`
	InviteExpiresAt time.Time    `json:"invite_expires_at,omitempty"`
	ClaimedAt       time.Time    `json:"claimed_at,omitempty"`
	UpdatedAt       time.Time    `json:"updated_at"`
}

type administratorIdentity struct {
	Mode            CredentialMode
	LoginUsername   string
	AuthRevision    uint64
	AccessKeyDigest [sha256.Size]byte
	PasswordSalt    [passwordSaltBytes]byte
	PasswordHash    [passwordHashBytes]byte
	UpdatedAt       time.Time
}

type AuthenticatedIdentity struct {
	Role        identityRole
	UserSession EndUserSession
}

var (
	ErrInvitationInvalid = errors.New("invitation is invalid or expired")
	ErrUsernameTaken     = errors.New("login username is already in use")
)

type endUserAccessDocument struct {
	Version  int                    `json:"version"`
	Accounts []persistedUserAccount `json:"accounts"`
}

type persistedUserAccount struct {
	UserID          string    `json:"user_id"`
	LoginUsername   string    `json:"login_username,omitempty"`
	AuthRevision    uint64    `json:"auth_revision"`
	PasswordSalt    string    `json:"password_salt,omitempty"`
	PasswordHash    string    `json:"password_hash,omitempty"`
	InviteSHA256    string    `json:"invite_sha256,omitempty"`
	InviteExpiresAt time.Time `json:"invite_expires_at,omitempty"`
	ClaimedAt       time.Time `json:"claimed_at,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type endUserSessionDocument struct {
	Version  int                       `json:"version"`
	Sessions []persistedEndUserSession `json:"sessions"`
}

type persistedEndUserSession struct {
	TokenSHA256  string    `json:"token_sha256"`
	CSRFSecret   string    `json:"csrf_secret"`
	UserID       string    `json:"user_id"`
	AuthRevision uint64    `json:"auth_revision"`
	CreatedAt    time.Time `json:"created_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type endUserAccount struct {
	UserID          string
	LoginUsername   string
	AuthRevision    uint64
	PasswordSalt    [passwordSaltBytes]byte
	PasswordHash    [passwordHashBytes]byte
	InviteDigest    [sha256.Size]byte
	HasInvite       bool
	InviteExpiresAt time.Time
	ClaimedAt       time.Time
	UpdatedAt       time.Time
}

type endUserMemorySession struct {
	csrfSecret   [credentialBytes]byte
	userID       string
	authRevision uint64
	createdAt    time.Time
	lastSeenAt   time.Time
	expiresAt    time.Time
}

type EndUserAccountStatus struct {
	Claimed         bool
	LoginUsername   string
	InvitationReady bool
	InviteExpiresAt time.Time
}

type EndUserSession struct {
	Token         string
	CSRFToken     string
	UserID        string
	LoginUsername string
	ExpiresAt     time.Time
}

// EndUserAccessManager owns browser-login identities for Proxy Node end users.
// It deliberately lives outside proxy-node-state.json so password hashes and
// browser sessions never enter topology or Agent configuration planes.
type EndUserAccessManager struct {
	accessPath  string
	sessionPath string
	unified     bool
	admin       administratorIdentity

	mu          sync.Mutex
	lifecycleMu sync.Mutex
	accounts    map[string]endUserAccount
	sessions    map[[sha256.Size]byte]endUserMemorySession
	failures    map[[sha256.Size]byte]loginFailureLimiter

	activityPersisting  bool
	activityPersistedAt time.Time
	activityInterval    time.Duration
	activityClosed      bool
	activityWG          sync.WaitGroup
	closeOnce           sync.Once
	closeErr            error

	dummySalt [passwordSaltBytes]byte
	dummyHash [passwordHashBytes]byte

	now                func() time.Time
	random             io.Reader
	derivePassword     passwordDeriver
	passwordKDFLimiter *passwordKDFLimiter
	sessionIdleTimeout time.Duration
	loginFailureLimit  int
	loginFailureWindow time.Duration
	maxLoginClients    int
	maxSessions        int
}

func (m *EndUserAccessManager) Unified() bool { return m != nil && m.unified }

func OpenEndUserAccess(accessPath, sessionPath string) (*EndUserAccessManager, error) {
	return openEndUserAccessWithPasswordDeriver(accessPath, sessionPath, deriveArgon2idPassword, rand.Reader)
}

// OpenUnifiedWebAccess loads the administrator and every claimed end-user
// identity from one role-tagged database. Existing v1/v2 administrator files
// and the pre-release end-user identity file are migrated atomically before
// authentication becomes available.
func OpenUnifiedWebAccess(
	accessPath, legacyEndUserPath, adminSessionPath, endUserSessionPath string,
) (*AccessManager, *EndUserAccessManager, error) {
	access, err := LoadAccessWithSessions(accessPath, adminSessionPath)
	if err != nil {
		return nil, nil, err
	}
	encoded, _, err := readPrivateJSONFile(accessPath, endUserAccessFileMaxBytes)
	if err != nil {
		return nil, nil, err
	}
	var version struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(encoded, &version); err != nil {
		return nil, nil, err
	}
	if version.Version == unifiedIdentityFileVersion {
		manager, err := openUnifiedEndUserAccess(
			accessPath, endUserSessionPath, deriveArgon2idPassword, rand.Reader,
		)
		return access, manager, err
	}

	manager, err := openEndUserAccessWithPasswordDeriver(
		legacyEndUserPath, endUserSessionPath, deriveArgon2idPassword, rand.Reader,
	)
	if err != nil {
		return nil, nil, err
	}
	manager.lifecycleMu.Lock()
	manager.mu.Lock()
	manager.unified = true
	manager.accessPath = filepath.Clean(accessPath)
	manager.admin = administratorIdentity{
		Mode: access.mode, AuthRevision: 1, UpdatedAt: manager.currentTime(),
		AccessKeyDigest: access.accessKeyDigest, PasswordSalt: access.passwordSalt,
		PasswordHash: access.passwordHash,
	}
	if access.mode == UsernamePassword {
		manager.admin.LoginUsername = accessUsername(access)
		for _, account := range manager.accounts {
			if strings.EqualFold(account.LoginUsername, manager.admin.LoginUsername) {
				manager.mu.Unlock()
				manager.lifecycleMu.Unlock()
				return nil, nil, errors.New("administrator and user login usernames overlap")
			}
		}
	}
	if err := manager.persistAccountsLocked(); err != nil {
		manager.mu.Unlock()
		manager.lifecycleMu.Unlock()
		return nil, nil, fmt.Errorf("persist unified web identities: %w", err)
	}
	manager.mu.Unlock()
	manager.lifecycleMu.Unlock()
	if filepath.Clean(legacyEndUserPath) != filepath.Clean(accessPath) {
		if err := os.Remove(legacyEndUserPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("remove migrated end-user identity file: %w", err)
		}
	}
	return access, manager, nil
}

// ValidateUnifiedWebAccessFile performs the same strict identity validation as
// startup without retaining either session manager. Migration restore uses it
// before a staged identity document can replace the live file.
func ValidateUnifiedWebAccessFile(path string) error {
	directory := filepath.Dir(path)
	legacy := filepath.Join(directory, ".migration-legacy-end-user-auth.json")
	adminSessions := filepath.Join(directory, ".migration-admin-sessions.json")
	userSessions := filepath.Join(directory, ".migration-user-sessions.json")
	access, users, err := OpenUnifiedWebAccess(path, legacy, adminSessions, userSessions)
	if err != nil {
		return err
	}
	_ = access
	if users != nil {
		if err := users.Close(); err != nil {
			return err
		}
	}
	for _, candidate := range []string{legacy, adminSessions, userSessions} {
		_ = os.Remove(candidate)
	}
	return nil
}

func accessUsername(access *AccessManager) string {
	if access == nil || access.mode != UsernamePassword {
		return ""
	}
	return access.username
}

func openUnifiedEndUserAccess(
	accessPath, sessionPath string,
	derivePassword passwordDeriver,
	random io.Reader,
) (*EndUserAccessManager, error) {
	manager, err := newEndUserAccessManager(accessPath, sessionPath, derivePassword, random)
	if err != nil {
		return nil, err
	}
	manager.unified = true
	if err := manager.loadAccounts(); err != nil {
		return nil, fmt.Errorf("load unified web identities: %w", err)
	}
	if err := manager.loadSessions(); err != nil {
		return nil, fmt.Errorf("load end-user sessions: %w", err)
	}
	return manager, nil
}

func openEndUserAccessWithPasswordDeriver(
	accessPath, sessionPath string,
	derivePassword passwordDeriver,
	random io.Reader,
) (*EndUserAccessManager, error) {
	manager, err := newEndUserAccessManager(accessPath, sessionPath, derivePassword, random)
	if err != nil {
		return nil, err
	}
	if err := manager.loadAccounts(); err != nil {
		return nil, fmt.Errorf("load end-user access: %w", err)
	}
	if err := manager.loadSessions(); err != nil {
		return nil, fmt.Errorf("load end-user sessions: %w", err)
	}
	return manager, nil
}

func newEndUserAccessManager(
	accessPath, sessionPath string,
	derivePassword passwordDeriver,
	random io.Reader,
) (*EndUserAccessManager, error) {
	manager := &EndUserAccessManager{
		accessPath:         filepath.Clean(accessPath),
		sessionPath:        filepath.Clean(sessionPath),
		accounts:           make(map[string]endUserAccount),
		sessions:           make(map[[sha256.Size]byte]endUserMemorySession),
		failures:           make(map[[sha256.Size]byte]loginFailureLimiter),
		now:                time.Now,
		random:             random,
		derivePassword:     derivePassword,
		passwordKDFLimiter: globalPasswordKDFLimiter,
		sessionIdleTimeout: DefaultSessionIdleTimeout,
		loginFailureLimit:  DefaultLoginFailureLimit,
		loginFailureWindow: DefaultLoginFailureWindow,
		maxLoginClients:    defaultMaxLoginClients,
		maxSessions:        defaultEndUserMaxSessions,
		activityInterval:   defaultSessionPersistInterval,
	}
	if _, err := io.ReadFull(manager.random, manager.dummySalt[:]); err != nil {
		return nil, fmt.Errorf("generate end-user dummy password salt: %w", err)
	}
	manager.dummyHash = manager.derivePassword([]byte("theatropolis-invalid-user-password"), manager.dummySalt[:])
	return manager, nil
}

func (m *EndUserAccessManager) Status(userID string) EndUserAccountStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	account, exists := m.accounts[userID]
	if !exists {
		return EndUserAccountStatus{}
	}
	now := m.currentTime()
	return EndUserAccountStatus{
		Claimed:         account.LoginUsername != "",
		LoginUsername:   account.LoginUsername,
		InvitationReady: account.HasInvite && now.Before(account.InviteExpiresAt),
		InviteExpiresAt: account.InviteExpiresAt,
	}
}

func (m *EndUserAccessManager) IssueInvitation(userID string, lifetime time.Duration) (string, time.Time, error) {
	if strings.TrimSpace(userID) == "" {
		return "", time.Time{}, errors.New("end-user ID is required")
	}
	if lifetime <= 0 || lifetime > 7*24*time.Hour {
		return "", time.Time{}, errors.New("invitation lifetime is invalid")
	}
	var token [credentialBytes]byte
	if _, err := io.ReadFull(m.random, token[:]); err != nil {
		return "", time.Time{}, fmt.Errorf("generate end-user invitation: %w", err)
	}
	defer clear(token[:])
	now := m.currentTime()
	digest := sha256.Sum256(token[:])
	expiresAt := now.Add(lifetime)

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	previous := cloneEndUserAccounts(m.accounts)
	account := m.accounts[userID]
	account.UserID = userID
	account.AuthRevision++
	if account.AuthRevision == 0 {
		account.AuthRevision = 1
	}
	account.LoginUsername = ""
	clear(account.PasswordSalt[:])
	clear(account.PasswordHash[:])
	account.InviteDigest = digest
	account.HasInvite = true
	account.InviteExpiresAt = expiresAt
	account.ClaimedAt = time.Time{}
	account.UpdatedAt = now
	m.accounts[userID] = account
	removeEndUserSessionsForUser(m.sessions, userID)
	if err := m.persistAccountsLocked(); err != nil {
		m.accounts = previous
		m.mu.Unlock()
		return "", time.Time{}, fmt.Errorf("persist end-user invitation: %w", err)
	}
	if err := m.persistSessionsLocked(); err != nil {
		m.mu.Unlock()
		return "", time.Time{}, fmt.Errorf("persist end-user session revocation: %w", err)
	}
	m.mu.Unlock()
	return base64.RawURLEncoding.EncodeToString(token[:]), expiresAt, nil
}

func (m *EndUserAccessManager) InvitationValid(token string) bool {
	digest, valid := credentialDigest(token)
	if valid != 1 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.accountForInviteLocked(digest, m.currentTime())
	return ok
}

func (m *EndUserAccessManager) ClaimInvitation(token, username, password string) (EndUserSession, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	if err := validateAdminUsername(username); err != nil {
		return EndUserSession{}, err
	}
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	if err := validateAdminPassword(username, passwordBytes, true); err != nil {
		return EndUserSession{}, err
	}
	digest, valid := credentialDigest(token)
	if valid != 1 {
		return EndUserSession{}, ErrInvitationInvalid
	}
	m.mu.Lock()
	_, invitationExists := m.accountForInviteLocked(digest, m.currentTime())
	m.mu.Unlock()
	if !invitationExists {
		return EndUserSession{}, ErrInvitationInvalid
	}
	if !m.acquirePasswordKDF() {
		return EndUserSession{}, ErrLoginRateLimited
	}
	var salt [passwordSaltBytes]byte
	if _, err := io.ReadFull(m.random, salt[:]); err != nil {
		m.releasePasswordKDF()
		return EndUserSession{}, fmt.Errorf("generate password salt: %w", err)
	}
	passwordHash := m.derivePassword(passwordBytes, salt[:])
	m.releasePasswordKDF()
	defer clear(salt[:])
	defer clear(passwordHash[:])

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	now := m.currentTime()
	userID, exists := m.accountForInviteLocked(digest, now)
	if !exists {
		m.mu.Unlock()
		return EndUserSession{}, ErrInvitationInvalid
	}
	for existingID, account := range m.accounts {
		if existingID != userID && strings.EqualFold(account.LoginUsername, username) {
			m.mu.Unlock()
			return EndUserSession{}, ErrUsernameTaken
		}
	}
	if m.unified && m.admin.LoginUsername != "" && strings.EqualFold(m.admin.LoginUsername, username) {
		m.mu.Unlock()
		return EndUserSession{}, ErrUsernameTaken
	}
	previous := cloneEndUserAccounts(m.accounts)
	account := m.accounts[userID]
	account.LoginUsername = username
	account.PasswordSalt = salt
	account.PasswordHash = passwordHash
	account.HasInvite = false
	clear(account.InviteDigest[:])
	account.InviteExpiresAt = time.Time{}
	account.ClaimedAt = now
	account.UpdatedAt = now
	m.accounts[userID] = account
	if err := m.persistAccountsLocked(); err != nil {
		m.accounts = previous
		m.mu.Unlock()
		return EndUserSession{}, fmt.Errorf("persist claimed end-user account: %w", err)
	}
	session, err := m.createSessionLocked(account, now)
	if err != nil {
		m.mu.Unlock()
		return EndUserSession{}, err
	}
	m.mu.Unlock()
	return session, nil
}

func (m *EndUserAccessManager) LoginForClient(client, username, password string) (EndUserSession, error) {
	identity, err := m.LoginIdentityForClient(client, username, password)
	if err != nil {
		return EndUserSession{}, err
	}
	if identity.Role != identityRoleUser {
		return EndUserSession{}, ErrAuthenticationFailed
	}
	return identity.UserSession, nil
}

// LoginIdentityForClient resolves one globally unique username, performs one
// credential check, and returns the persisted role. It never guesses a role by
// falling through from administrator authentication to user authentication.
func (m *EndUserAccessManager) LoginIdentityForClient(
	client, username, password string,
) (AuthenticatedIdentity, error) {
	if !m.unified {
		return m.loginUserIdentityForClient(client, username, password)
	}
	now := m.currentTime()
	clientDigest := sha256.Sum256([]byte(client))
	if err := m.reserveLoginAttempt(clientDigest, now); err != nil {
		return AuthenticatedIdentity{}, err
	}
	username = strings.TrimSpace(strings.ToLower(username))
	passwordBytes := []byte(password)
	defer clear(passwordBytes)

	m.mu.Lock()
	admin := m.admin
	var user endUserAccount
	foundUser := false
	if username != "" {
		for _, account := range m.accounts {
			if account.LoginUsername == username {
				user = account
				foundUser = true
				break
			}
		}
	}
	m.mu.Unlock()

	if admin.Mode == LegacyAccessKey && username == "" {
		digest := sha256.Sum256(passwordBytes)
		if subtle.ConstantTimeCompare(digest[:], admin.AccessKeyDigest[:]) != 1 {
			return AuthenticatedIdentity{}, ErrAuthenticationFailed
		}
		m.mu.Lock()
		delete(m.failures, clientDigest)
		m.mu.Unlock()
		return AuthenticatedIdentity{Role: identityRoleAdministrator}, nil
	}

	role := identityRole("")
	salt := m.dummySalt
	hash := m.dummyHash
	authRevision := uint64(0)
	if admin.Mode == UsernamePassword && username == admin.LoginUsername {
		role, salt, hash, authRevision = identityRoleAdministrator, admin.PasswordSalt, admin.PasswordHash, admin.AuthRevision
	} else if foundUser {
		role, salt, hash, authRevision = identityRoleUser, user.PasswordSalt, user.PasswordHash, user.AuthRevision
	}
	shapeValid := validateAdminUsername(username) == nil && validateAdminPassword("", passwordBytes, false) == nil
	if !shapeValid {
		return AuthenticatedIdentity{}, ErrAuthenticationFailed
	}
	if !m.acquirePasswordKDF() {
		return AuthenticatedIdentity{}, ErrLoginRateLimited
	}
	candidateHash := m.derivePassword(passwordBytes, salt[:])
	m.releasePasswordKDF()
	passwordMatches := subtle.ConstantTimeCompare(candidateHash[:], hash[:])
	clear(candidateHash[:])
	if role == "" || passwordMatches != 1 {
		return AuthenticatedIdentity{}, ErrAuthenticationFailed
	}

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.failures, clientDigest)
	if role == identityRoleAdministrator {
		if m.admin.AuthRevision != authRevision || m.admin.LoginUsername != username ||
			subtle.ConstantTimeCompare(m.admin.PasswordHash[:], hash[:]) != 1 {
			return AuthenticatedIdentity{}, ErrAuthenticationFailed
		}
		return AuthenticatedIdentity{Role: identityRoleAdministrator}, nil
	}
	current, exists := m.accounts[user.UserID]
	if !exists || current.AuthRevision != authRevision || current.LoginUsername != username ||
		subtle.ConstantTimeCompare(current.PasswordHash[:], hash[:]) != 1 {
		return AuthenticatedIdentity{}, ErrAuthenticationFailed
	}
	session, err := m.createSessionLocked(current, now)
	if err != nil {
		return AuthenticatedIdentity{}, err
	}
	return AuthenticatedIdentity{Role: identityRoleUser, UserSession: session}, nil
}

func (m *EndUserAccessManager) loginUserIdentityForClient(
	client, username, password string,
) (AuthenticatedIdentity, error) {
	now := m.currentTime()
	clientDigest := sha256.Sum256([]byte(client))
	if err := m.reserveLoginAttempt(clientDigest, now); err != nil {
		return AuthenticatedIdentity{}, err
	}
	username = strings.TrimSpace(strings.ToLower(username))
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	shapeValid := validateAdminUsername(username) == nil && validateAdminPassword("", passwordBytes, false) == nil

	m.mu.Lock()
	var snapshot endUserAccount
	found := false
	if shapeValid {
		for _, account := range m.accounts {
			if account.LoginUsername == username {
				snapshot = account
				found = true
				break
			}
		}
	}
	if !found {
		snapshot.PasswordSalt = m.dummySalt
		snapshot.PasswordHash = m.dummyHash
	}
	m.mu.Unlock()
	if !shapeValid || !m.acquirePasswordKDF() {
		if shapeValid {
			return AuthenticatedIdentity{}, ErrLoginRateLimited
		}
		return AuthenticatedIdentity{}, ErrAuthenticationFailed
	}
	candidateHash := m.derivePassword(passwordBytes, snapshot.PasswordSalt[:])
	m.releasePasswordKDF()
	passwordMatches := subtle.ConstantTimeCompare(candidateHash[:], snapshot.PasswordHash[:])
	clear(candidateHash[:])
	if !found || passwordMatches != 1 {
		return AuthenticatedIdentity{}, ErrAuthenticationFailed
	}

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	current, exists := m.accounts[snapshot.UserID]
	if !exists || current.AuthRevision != snapshot.AuthRevision || current.LoginUsername != username ||
		subtle.ConstantTimeCompare(current.PasswordHash[:], snapshot.PasswordHash[:]) != 1 {
		m.mu.Unlock()
		return AuthenticatedIdentity{}, ErrAuthenticationFailed
	}
	delete(m.failures, clientDigest)
	session, err := m.createSessionLocked(current, now)
	m.mu.Unlock()
	return AuthenticatedIdentity{Role: identityRoleUser, UserSession: session}, err
}

func (m *EndUserAccessManager) Authenticate(sessionToken string) (EndUserSession, error) {
	digest, valid := credentialDigest(sessionToken)
	now := m.currentTime()
	m.mu.Lock()
	session, exists := m.sessions[digest]
	if valid != 1 || !exists || !now.Before(session.expiresAt) {
		if exists {
			delete(m.sessions, digest)
		}
		m.mu.Unlock()
		return EndUserSession{}, ErrAuthenticationFailed
	}
	account, exists := m.accounts[session.userID]
	if !exists || account.LoginUsername == "" || account.AuthRevision != session.authRevision {
		delete(m.sessions, digest)
		m.mu.Unlock()
		return EndUserSession{}, ErrAuthenticationFailed
	}
	session.lastSeenAt = now
	session.expiresAt = now.Add(m.sessionIdleTimeout)
	m.sessions[digest] = session
	result := EndUserSession{
		Token: sessionToken, CSRFToken: base64.RawURLEncoding.EncodeToString(session.csrfSecret[:]),
		UserID: session.userID, LoginUsername: account.LoginUsername, ExpiresAt: session.expiresAt,
	}
	persist := m.scheduleActivityPersistenceLocked(now)
	m.mu.Unlock()
	if persist {
		go m.persistSessionActivity()
	}
	return result, nil
}

func (m *EndUserAccessManager) AuthorizeCSRF(sessionToken, csrfToken string) bool {
	digest, tokenValid := credentialDigest(sessionToken)
	candidate, csrfValid := decodeCredential(csrfToken)
	defer clear(candidate[:])
	now := m.currentTime()

	m.mu.Lock()
	session, exists := m.sessions[digest]
	if tokenValid != 1 || !exists || !now.Before(session.expiresAt) {
		m.mu.Unlock()
		return false
	}
	account, exists := m.accounts[session.userID]
	if !exists || account.LoginUsername == "" || account.AuthRevision != session.authRevision {
		m.mu.Unlock()
		return false
	}
	if csrfValid&subtle.ConstantTimeCompare(session.csrfSecret[:], candidate[:]) != 1 {
		m.mu.Unlock()
		return false
	}
	session.lastSeenAt = now
	session.expiresAt = now.Add(m.sessionIdleTimeout)
	m.sessions[digest] = session
	persist := m.scheduleActivityPersistenceLocked(now)
	m.mu.Unlock()
	if persist {
		go m.persistSessionActivity()
	}
	return true
}

func (m *EndUserAccessManager) Logout(sessionToken string) error {
	digest, valid := credentialDigest(sessionToken)
	if valid != 1 {
		return nil
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := cloneEndUserSessions(m.sessions)
	delete(m.sessions, digest)
	if err := m.persistSessionsLocked(); err != nil {
		m.sessions = previous
		return fmt.Errorf("persist end-user logout: %w", err)
	}
	return nil
}

func (m *EndUserAccessManager) RemoveUser(userID string) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	previousAccounts := cloneEndUserAccounts(m.accounts)
	previousSessions := cloneEndUserSessions(m.sessions)
	delete(m.accounts, userID)
	removeEndUserSessionsForUser(m.sessions, userID)
	if err := m.persistAccountsLocked(); err != nil {
		m.accounts = previousAccounts
		m.sessions = previousSessions
		return err
	}
	if err := m.persistSessionsLocked(); err != nil {
		m.sessions = previousSessions
		return err
	}
	return nil
}

func (m *EndUserAccessManager) ReconcileUsers(validUserIDs map[string]struct{}) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	previousAccounts := cloneEndUserAccounts(m.accounts)
	previousSessions := cloneEndUserSessions(m.sessions)
	changed := false
	for userID := range m.accounts {
		if _, exists := validUserIDs[userID]; !exists {
			delete(m.accounts, userID)
			removeEndUserSessionsForUser(m.sessions, userID)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := m.persistAccountsLocked(); err != nil {
		m.accounts = previousAccounts
		m.sessions = previousSessions
		return err
	}
	if err := m.persistSessionsLocked(); err != nil {
		// The account file is already authoritative. Keep the in-memory account
		// and session removal fail-closed; stale disk sessions cannot authenticate
		// without their matching account and are discarded on the next load.
		return err
	}
	return nil
}

func (m *EndUserAccessManager) createSessionLocked(account endUserAccount, now time.Time) (EndUserSession, error) {
	var token [credentialBytes]byte
	var csrf [credentialBytes]byte
	if _, err := io.ReadFull(m.random, token[:]); err != nil {
		return EndUserSession{}, fmt.Errorf("generate end-user session token: %w", err)
	}
	defer clear(token[:])
	if _, err := io.ReadFull(m.random, csrf[:]); err != nil {
		return EndUserSession{}, fmt.Errorf("generate end-user CSRF token: %w", err)
	}
	defer clear(csrf[:])
	m.purgeExpiredSessionsLocked(now)
	if len(m.sessions) >= m.maxSessions {
		m.evictOldestSessionLocked()
	}
	digest := sha256.Sum256(token[:])
	expiresAt := now.Add(m.sessionIdleTimeout)
	m.sessions[digest] = endUserMemorySession{
		csrfSecret: csrf, userID: account.UserID, authRevision: account.AuthRevision,
		createdAt: now, lastSeenAt: now, expiresAt: expiresAt,
	}
	if err := m.persistSessionsLocked(); err != nil {
		delete(m.sessions, digest)
		return EndUserSession{}, fmt.Errorf("persist end-user browser session: %w", err)
	}
	return EndUserSession{
		Token:     base64.RawURLEncoding.EncodeToString(token[:]),
		CSRFToken: base64.RawURLEncoding.EncodeToString(csrf[:]),
		UserID:    account.UserID, LoginUsername: account.LoginUsername, ExpiresAt: expiresAt,
	}, nil
}

func (m *EndUserAccessManager) accountForInviteLocked(digest [sha256.Size]byte, now time.Time) (string, bool) {
	for userID, account := range m.accounts {
		if account.HasInvite && now.Before(account.InviteExpiresAt) &&
			subtle.ConstantTimeCompare(account.InviteDigest[:], digest[:]) == 1 {
			return userID, true
		}
	}
	return "", false
}

func (m *EndUserAccessManager) reserveLoginAttempt(client [sha256.Size]byte, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	failure := m.failures[client]
	if failure.windowStartedAt.IsZero() || !now.Before(failure.windowStartedAt.Add(m.loginFailureWindow)) {
		failure = loginFailureLimiter{windowStartedAt: now}
	}
	if failure.attempts >= m.loginFailureLimit {
		return ErrLoginRateLimited
	}
	failure.attempts++
	if _, exists := m.failures[client]; !exists && len(m.failures) >= m.maxLoginClients {
		var oldestKey [sha256.Size]byte
		var oldest time.Time
		for key, candidate := range m.failures {
			if oldest.IsZero() || candidate.windowStartedAt.Before(oldest) {
				oldestKey, oldest = key, candidate.windowStartedAt
			}
		}
		delete(m.failures, oldestKey)
	}
	m.failures[client] = failure
	return nil
}

func (m *EndUserAccessManager) acquirePasswordKDF() bool {
	return m.passwordKDFLimiter.acquire()
}

func (m *EndUserAccessManager) releasePasswordKDF() { m.passwordKDFLimiter.release() }

func (m *EndUserAccessManager) purgeExpiredSessionsLocked(now time.Time) {
	for digest, session := range m.sessions {
		if !now.Before(session.expiresAt) {
			delete(m.sessions, digest)
		}
	}
}

func (m *EndUserAccessManager) evictOldestSessionLocked() {
	var selected [sha256.Size]byte
	var oldest time.Time
	for digest, session := range m.sessions {
		if oldest.IsZero() || session.lastSeenAt.Before(oldest) {
			selected, oldest = digest, session.lastSeenAt
		}
	}
	delete(m.sessions, selected)
}

func (m *EndUserAccessManager) currentTime() time.Time {
	if m.now == nil {
		return time.Now().UTC()
	}
	return m.now().UTC()
}

func (m *EndUserAccessManager) loadAccounts() error {
	encoded, exists, err := readPrivateJSONFile(m.accessPath, endUserAccessFileMaxBytes)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if m.unified {
		return m.loadUnifiedIdentities(encoded)
	}
	var document endUserAccessDocument
	if err := decodeStrictJSON(encoded, &document); err != nil {
		return err
	}
	if document.Version != endUserAccessFileVersion {
		return fmt.Errorf("unsupported end-user access file version %d", document.Version)
	}
	loginUsernames := make(map[string]struct{}, len(document.Accounts))
	inviteDigests := make(map[[sha256.Size]byte]struct{}, len(document.Accounts))
	for _, stored := range document.Accounts {
		if strings.TrimSpace(stored.UserID) == "" || stored.AuthRevision == 0 || stored.UpdatedAt.IsZero() {
			return errors.New("end-user access file contains an invalid account")
		}
		if _, duplicate := m.accounts[stored.UserID]; duplicate {
			return errors.New("end-user access file contains a duplicate user")
		}
		account := endUserAccount{
			UserID: stored.UserID, LoginUsername: stored.LoginUsername, AuthRevision: stored.AuthRevision,
			InviteExpiresAt: stored.InviteExpiresAt.UTC(), ClaimedAt: stored.ClaimedAt.UTC(), UpdatedAt: stored.UpdatedAt.UTC(),
		}
		if stored.LoginUsername != "" {
			if validateAdminUsername(stored.LoginUsername) != nil || stored.PasswordSalt == "" || stored.PasswordHash == "" {
				return errors.New("end-user access file contains invalid login credentials")
			}
			if _, duplicate := loginUsernames[stored.LoginUsername]; duplicate {
				return errors.New("end-user access file contains a duplicate login username")
			}
			loginUsernames[stored.LoginUsername] = struct{}{}
			salt, err := decodeCanonicalBase64(stored.PasswordSalt, passwordSaltBytes)
			if err != nil {
				return errors.New("end-user access file contains an invalid password salt")
			}
			hash, err := decodeCanonicalBase64(stored.PasswordHash, passwordHashBytes)
			if err != nil {
				clear(salt)
				return errors.New("end-user access file contains an invalid password hash")
			}
			copy(account.PasswordSalt[:], salt)
			copy(account.PasswordHash[:], hash)
			clear(salt)
			clear(hash)
		}
		if stored.InviteSHA256 != "" {
			if stored.LoginUsername != "" {
				return errors.New("end-user access file contains conflicting login and invitation state")
			}
			invite, err := decodeCanonicalBase64(stored.InviteSHA256, sha256.Size)
			if err != nil || stored.InviteExpiresAt.IsZero() {
				clear(invite)
				return errors.New("end-user access file contains an invalid invitation")
			}
			copy(account.InviteDigest[:], invite)
			clear(invite)
			if _, duplicate := inviteDigests[account.InviteDigest]; duplicate {
				return errors.New("end-user access file contains a duplicate invitation")
			}
			inviteDigests[account.InviteDigest] = struct{}{}
			account.HasInvite = true
		}
		m.accounts[stored.UserID] = account
	}
	return nil
}

func (m *EndUserAccessManager) loadUnifiedIdentities(encoded []byte) error {
	var document unifiedIdentityDocument
	if err := decodeStrictJSON(encoded, &document); err != nil {
		return err
	}
	if document.Version != unifiedIdentityFileVersion {
		return fmt.Errorf("unsupported unified identity file version %d", document.Version)
	}
	usernames := make(map[string]struct{}, len(document.Identities))
	identityIDs := make(map[string]struct{}, len(document.Identities))
	invites := make(map[[sha256.Size]byte]struct{}, len(document.Identities))
	adminCount := 0
	for _, stored := range document.Identities {
		if stored.ID == "" || stored.AuthRevision == 0 || stored.UpdatedAt.IsZero() {
			return errors.New("unified identity file contains an invalid identity")
		}
		if _, duplicate := identityIDs[stored.ID]; duplicate {
			return errors.New("unified identity file contains a duplicate identity ID")
		}
		identityIDs[stored.ID] = struct{}{}
		if stored.LoginUsername != "" {
			if validateAdminUsername(stored.LoginUsername) != nil {
				return errors.New("unified identity file contains an invalid username")
			}
			if _, duplicate := usernames[stored.LoginUsername]; duplicate {
				return errors.New("unified identity file contains a duplicate username")
			}
			usernames[stored.LoginUsername] = struct{}{}
		}
		switch stored.Role {
		case identityRoleAdministrator:
			adminCount++
			if adminCount != 1 || stored.ID != administratorIdentityID || stored.InviteSHA256 != "" {
				return errors.New("unified identity file contains an invalid administrator")
			}
			admin, err := decodeAdministratorIdentity(stored)
			if err != nil {
				return err
			}
			m.admin = admin
		case identityRoleUser:
			if _, duplicate := m.accounts[stored.ID]; duplicate {
				return errors.New("unified identity file contains a duplicate user")
			}
			account, err := decodeUnifiedUserIdentity(stored)
			if err != nil {
				return err
			}
			if account.HasInvite {
				if _, duplicate := invites[account.InviteDigest]; duplicate {
					return errors.New("unified identity file contains a duplicate invitation")
				}
				invites[account.InviteDigest] = struct{}{}
			}
			m.accounts[stored.ID] = account
		default:
			return errors.New("unified identity file contains an unsupported role")
		}
	}
	if adminCount != 1 {
		return errors.New("unified identity file must contain exactly one administrator")
	}
	return nil
}

func decodeAdministratorIdentity(stored persistedUnifiedIdentity) (administratorIdentity, error) {
	admin := administratorIdentity{
		LoginUsername: stored.LoginUsername, AuthRevision: stored.AuthRevision,
		UpdatedAt: stored.UpdatedAt.UTC(),
	}
	switch stored.CredentialType {
	case credentialTypeAccessKey:
		if stored.LoginUsername != "" || stored.AccessKeySHA256 == "" || stored.PasswordSalt != "" || stored.PasswordHash != "" {
			return administratorIdentity{}, errors.New("unified identity file contains an invalid administrator access key")
		}
		digest, err := decodeCanonicalBase64(stored.AccessKeySHA256, sha256.Size)
		if err != nil {
			return administratorIdentity{}, errors.New("unified identity file contains an invalid administrator access key")
		}
		copy(admin.AccessKeyDigest[:], digest)
		clear(digest)
		admin.Mode = LegacyAccessKey
	case credentialTypePassword:
		if stored.LoginUsername == "" || stored.AccessKeySHA256 != "" {
			return administratorIdentity{}, errors.New("unified identity file contains invalid administrator credentials")
		}
		salt, hash, err := decodePasswordMaterial(stored.PasswordSalt, stored.PasswordHash)
		if err != nil {
			return administratorIdentity{}, errors.New("unified identity file contains invalid administrator credentials")
		}
		copy(admin.PasswordSalt[:], salt)
		copy(admin.PasswordHash[:], hash)
		clear(salt)
		clear(hash)
		admin.Mode = UsernamePassword
	default:
		return administratorIdentity{}, errors.New("unified identity file contains an unsupported administrator credential")
	}
	return admin, nil
}

func decodeUnifiedUserIdentity(stored persistedUnifiedIdentity) (endUserAccount, error) {
	if stored.CredentialType != "" && stored.CredentialType != credentialTypePassword || stored.AccessKeySHA256 != "" {
		return endUserAccount{}, errors.New("unified identity file contains an invalid user credential type")
	}
	account := endUserAccount{
		UserID: stored.ID, LoginUsername: stored.LoginUsername, AuthRevision: stored.AuthRevision,
		InviteExpiresAt: stored.InviteExpiresAt.UTC(), ClaimedAt: stored.ClaimedAt.UTC(), UpdatedAt: stored.UpdatedAt.UTC(),
	}
	if stored.LoginUsername != "" {
		if stored.CredentialType != credentialTypePassword || stored.InviteSHA256 != "" {
			return endUserAccount{}, errors.New("unified identity file contains conflicting user credential state")
		}
		salt, hash, err := decodePasswordMaterial(stored.PasswordSalt, stored.PasswordHash)
		if err != nil {
			return endUserAccount{}, errors.New("unified identity file contains invalid user credentials")
		}
		copy(account.PasswordSalt[:], salt)
		copy(account.PasswordHash[:], hash)
		clear(salt)
		clear(hash)
	} else if stored.CredentialType != "" || stored.PasswordSalt != "" || stored.PasswordHash != "" {
		return endUserAccount{}, errors.New("unified identity file contains credentials without a username")
	}
	if stored.InviteSHA256 != "" {
		if stored.LoginUsername != "" || stored.InviteExpiresAt.IsZero() {
			return endUserAccount{}, errors.New("unified identity file contains conflicting user invitation state")
		}
		invite, err := decodeCanonicalBase64(stored.InviteSHA256, sha256.Size)
		if err != nil {
			return endUserAccount{}, errors.New("unified identity file contains an invalid user invitation")
		}
		copy(account.InviteDigest[:], invite)
		clear(invite)
		account.HasInvite = true
	}
	return account, nil
}

func decodePasswordMaterial(encodedSalt, encodedHash string) ([]byte, []byte, error) {
	salt, err := decodeCanonicalBase64(encodedSalt, passwordSaltBytes)
	if err != nil {
		return nil, nil, err
	}
	hash, err := decodeCanonicalBase64(encodedHash, passwordHashBytes)
	if err != nil {
		clear(salt)
		return nil, nil, err
	}
	return salt, hash, nil
}

func (m *EndUserAccessManager) loadSessions() error {
	encoded, exists, err := readPrivateJSONFile(m.sessionPath, endUserSessionMaxBytes)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	var document endUserSessionDocument
	if err := decodeStrictJSON(encoded, &document); err != nil {
		return err
	}
	if document.Version != endUserSessionFileVersion || len(document.Sessions) > m.maxSessions {
		return errors.New("end-user session file is invalid")
	}
	now := m.currentTime()
	for _, stored := range document.Sessions {
		digest, err := decodeCanonicalBase64(stored.TokenSHA256, sha256.Size)
		if err != nil {
			return errors.New("end-user session file contains an invalid token digest")
		}
		csrf, err := decodeCanonicalBase64(stored.CSRFSecret, credentialBytes)
		if err != nil {
			clear(digest)
			return errors.New("end-user session file contains an invalid CSRF secret")
		}
		var tokenDigest [sha256.Size]byte
		var csrfSecret [credentialBytes]byte
		copy(tokenDigest[:], digest)
		copy(csrfSecret[:], csrf)
		clear(digest)
		clear(csrf)
		account, accountExists := m.accounts[stored.UserID]
		if !accountExists || account.AuthRevision != stored.AuthRevision || !now.Before(stored.ExpiresAt) {
			continue
		}
		if _, duplicate := m.sessions[tokenDigest]; duplicate || stored.CreatedAt.IsZero() || stored.LastSeenAt.Before(stored.CreatedAt) {
			return errors.New("end-user session file contains an invalid session")
		}
		m.sessions[tokenDigest] = endUserMemorySession{
			csrfSecret: csrfSecret, userID: stored.UserID, authRevision: stored.AuthRevision,
			createdAt: stored.CreatedAt.UTC(), lastSeenAt: stored.LastSeenAt.UTC(), expiresAt: stored.ExpiresAt.UTC(),
		}
	}
	m.activityPersistedAt = now
	return nil
}

func (m *EndUserAccessManager) persistAccountsLocked() error {
	if m.unified {
		return m.persistUnifiedIdentitiesLocked()
	}
	document := endUserAccessDocument{Version: endUserAccessFileVersion, Accounts: make([]persistedUserAccount, 0, len(m.accounts))}
	for _, account := range m.accounts {
		stored := persistedUserAccount{
			UserID: account.UserID, LoginUsername: account.LoginUsername, AuthRevision: account.AuthRevision,
			InviteExpiresAt: account.InviteExpiresAt.UTC(), ClaimedAt: account.ClaimedAt.UTC(), UpdatedAt: account.UpdatedAt.UTC(),
		}
		if account.LoginUsername != "" {
			stored.PasswordSalt = base64.RawURLEncoding.EncodeToString(account.PasswordSalt[:])
			stored.PasswordHash = base64.RawURLEncoding.EncodeToString(account.PasswordHash[:])
		}
		if account.HasInvite {
			stored.InviteSHA256 = base64.RawURLEncoding.EncodeToString(account.InviteDigest[:])
		}
		document.Accounts = append(document.Accounts, stored)
	}
	sort.Slice(document.Accounts, func(i, j int) bool { return document.Accounts[i].UserID < document.Accounts[j].UserID })
	return writePrivateJSONFile(m.accessPath, document, endUserAccessFileMaxBytes)
}

func (m *EndUserAccessManager) persistUnifiedIdentitiesLocked() error {
	document := unifiedIdentityDocument{
		Version:    unifiedIdentityFileVersion,
		Identities: make([]persistedUnifiedIdentity, 0, len(m.accounts)+1),
	}
	admin := persistedUnifiedIdentity{
		ID: administratorIdentityID, Role: identityRoleAdministrator,
		LoginUsername: m.admin.LoginUsername, AuthRevision: m.admin.AuthRevision,
		UpdatedAt: m.admin.UpdatedAt.UTC(),
	}
	switch m.admin.Mode {
	case LegacyAccessKey:
		admin.CredentialType = credentialTypeAccessKey
		admin.AccessKeySHA256 = base64.RawURLEncoding.EncodeToString(m.admin.AccessKeyDigest[:])
	case UsernamePassword:
		admin.CredentialType = credentialTypePassword
		admin.PasswordSalt = base64.RawURLEncoding.EncodeToString(m.admin.PasswordSalt[:])
		admin.PasswordHash = base64.RawURLEncoding.EncodeToString(m.admin.PasswordHash[:])
	default:
		return errors.New("administrator identity has an unsupported credential mode")
	}
	document.Identities = append(document.Identities, admin)
	for _, account := range m.accounts {
		stored := persistedUnifiedIdentity{
			ID: account.UserID, Role: identityRoleUser, LoginUsername: account.LoginUsername,
			AuthRevision: account.AuthRevision, InviteExpiresAt: account.InviteExpiresAt.UTC(),
			ClaimedAt: account.ClaimedAt.UTC(), UpdatedAt: account.UpdatedAt.UTC(),
		}
		if account.LoginUsername != "" {
			stored.CredentialType = credentialTypePassword
			stored.PasswordSalt = base64.RawURLEncoding.EncodeToString(account.PasswordSalt[:])
			stored.PasswordHash = base64.RawURLEncoding.EncodeToString(account.PasswordHash[:])
		}
		if account.HasInvite {
			stored.InviteSHA256 = base64.RawURLEncoding.EncodeToString(account.InviteDigest[:])
		}
		document.Identities = append(document.Identities, stored)
	}
	sort.Slice(document.Identities, func(i, j int) bool {
		if document.Identities[i].Role != document.Identities[j].Role {
			return document.Identities[i].Role < document.Identities[j].Role
		}
		return document.Identities[i].ID < document.Identities[j].ID
	})
	return writePrivateJSONFile(m.accessPath, document, endUserAccessFileMaxBytes)
}

func (m *EndUserAccessManager) persistSessionsLocked() error {
	if err := m.persistSessionSnapshot(m.sessions); err != nil {
		return err
	}
	m.activityPersistedAt = m.currentTime()
	return nil
}

func (m *EndUserAccessManager) persistSessionSnapshot(
	sessions map[[sha256.Size]byte]endUserMemorySession,
) error {
	document := endUserSessionDocument{Version: endUserSessionFileVersion, Sessions: make([]persistedEndUserSession, 0, len(sessions))}
	for digest, session := range sessions {
		document.Sessions = append(document.Sessions, persistedEndUserSession{
			TokenSHA256: base64.RawURLEncoding.EncodeToString(digest[:]),
			CSRFSecret:  base64.RawURLEncoding.EncodeToString(session.csrfSecret[:]),
			UserID:      session.userID, AuthRevision: session.authRevision,
			CreatedAt: session.createdAt.UTC(), LastSeenAt: session.lastSeenAt.UTC(), ExpiresAt: session.expiresAt.UTC(),
		})
	}
	sort.Slice(document.Sessions, func(i, j int) bool { return document.Sessions[i].TokenSHA256 < document.Sessions[j].TokenSHA256 })
	return writePrivateJSONFile(m.sessionPath, document, endUserSessionMaxBytes)
}

func (m *EndUserAccessManager) scheduleActivityPersistenceLocked(now time.Time) bool {
	if m.sessionPath == "" || m.activityInterval <= 0 || m.activityPersisting || m.activityClosed {
		return false
	}
	if !m.activityPersistedAt.IsZero() &&
		now.Before(m.activityPersistedAt.Add(m.activityInterval)) {
		return false
	}
	m.activityPersisting = true
	m.activityWG.Add(1)
	return true
}

// persistSessionActivity coalesces routine rolling-expiry updates without
// making authenticated requests wait for a full file sync. lifecycleMu keeps
// this snapshot from overwriting a concurrent login, logout, or login reset.
func (m *EndUserAccessManager) persistSessionActivity() {
	defer m.activityWG.Done()
	m.lifecycleMu.Lock()
	m.mu.Lock()
	snapshot := cloneEndUserSessions(m.sessions)
	m.mu.Unlock()
	err := m.persistSessionSnapshot(snapshot)
	now := m.currentTime()
	m.mu.Lock()
	m.activityPersisting = false
	if err == nil {
		m.activityPersistedAt = now
	}
	m.mu.Unlock()
	m.lifecycleMu.Unlock()
	if err != nil {
		slog.Error("persist end-user browser session activity", "error", err)
	}
}

// Close stops new background activity snapshots, waits for an in-flight
// snapshot, and durably records the latest rolling session deadlines. Call it
// after the HTTP server has stopped accepting requests.
func (m *EndUserAccessManager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.activityClosed = true
		m.mu.Unlock()
		m.activityWG.Wait()

		m.lifecycleMu.Lock()
		defer m.lifecycleMu.Unlock()
		m.mu.Lock()
		defer m.mu.Unlock()
		if err := m.persistSessionsLocked(); err != nil {
			m.closeErr = fmt.Errorf("persist final end-user sessions: %w", err)
		}
	})
	return m.closeErr
}

func readPrivateJSONFile(path string, limit int64) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, errors.New("private state file must be a regular file")
	}
	if info.Mode().Perm() != 0o600 && info.Mode().Perm() != 0o640 {
		return nil, false, errors.New("private state file permissions must be 0600 or 0640")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, false, errors.New("private state file changed while opening")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > limit {
		return nil, false, errors.New("private state file is empty, unreadable, or too large")
	}
	return encoded, true, nil
}

func decodeStrictJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("private state file contains trailing JSON")
	}
	return nil
}

func writePrivateJSONFile(path string, value any, limit int) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > limit {
		return errors.New("private state file exceeds the size limit")
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(encoded); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	committed = true
	return syncParentDirectory(path)
}

func cloneEndUserAccounts(source map[string]endUserAccount) map[string]endUserAccount {
	copyMap := make(map[string]endUserAccount, len(source))
	for key, value := range source {
		copyMap[key] = value
	}
	return copyMap
}

func cloneEndUserSessions(source map[[sha256.Size]byte]endUserMemorySession) map[[sha256.Size]byte]endUserMemorySession {
	copyMap := make(map[[sha256.Size]byte]endUserMemorySession, len(source))
	for key, value := range source {
		copyMap[key] = value
	}
	return copyMap
}

func removeEndUserSessionsForUser(sessions map[[sha256.Size]byte]endUserMemorySession, userID string) {
	for digest, session := range sessions {
		if session.userID == userID {
			delete(sessions, digest)
		}
	}
}

func NewEndUserSessionCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{Name: EndUserSessionCookieName, Value: token, Path: "/", Expires: expiresAt.UTC(), Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func DeleteEndUserSessionCookie() *http.Cookie {
	return &http.Cookie{Name: EndUserSessionCookieName, Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func NewEndUserClaimCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{Name: EndUserClaimCookieName, Value: token, Path: "/", Expires: expiresAt.UTC(), Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func DeleteEndUserClaimCookie() *http.Cookie {
	return &http.Cookie{Name: EndUserClaimCookieName, Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}
