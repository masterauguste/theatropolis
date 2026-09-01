package webui

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testEndUserPassword = "Cobalt-River!Signal-482"

func TestUnifiedIdentityMigrationAndSingleRoleLookup(t *testing.T) {
	directory := t.TempDir()
	accessPath := filepath.Join(directory, "web-auth.json")
	legacyUserPath := filepath.Join(directory, "end-user-auth.json")
	adminSessions := filepath.Join(directory, "web-sessions.json")
	userSessions := filepath.Join(directory, "end-user-sessions.json")
	if err := initializeAdminAccessWithPasswordDeriver(
		accessPath, testAdminUsername, []byte(testAdminPassword), fastTestPasswordDeriver,
		bytes.NewReader(bytes.Repeat([]byte{0x31}, passwordSaltBytes)),
	); err != nil {
		t.Fatal(err)
	}
	legacy, err := openEndUserAccessWithPasswordDeriver(
		legacyUserPath, userSessions, fastTestPasswordDeriver, nilSafeRandomReader{},
	)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := legacy.IssueInvitation("usr_member", defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ClaimInvitation(token, "member", testEndUserPassword); err != nil {
		t.Fatal(err)
	}

	access, identities, err := OpenUnifiedWebAccess(
		accessPath, legacyUserPath, adminSessions, userSessions,
	)
	if err != nil {
		t.Fatal(err)
	}
	identities.derivePassword = fastTestPasswordDeriver
	identities.passwordKDFLimiter = newPasswordKDFLimiter(1, 8, time.Second)
	if !identities.Unified() || access.Mode() != UsernamePassword {
		t.Fatalf("unified managers were not configured")
	}
	admin, err := identities.LoginIdentityForClient("admin-client", testAdminUsername, testAdminPassword)
	if err != nil || admin.Role != identityRoleAdministrator {
		t.Fatalf("administrator identity = %+v, %v", admin, err)
	}
	member, err := identities.LoginIdentityForClient("member-client", "member", testEndUserPassword)
	if err != nil || member.Role != identityRoleUser || member.UserSession.UserID != "usr_member" {
		t.Fatalf("user identity = %+v, %v", member, err)
	}
	if _, err := os.Stat(legacyUserPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy user identity file still exists: %v", err)
	}

	encoded, err := os.ReadFile(accessPath)
	if err != nil {
		t.Fatal(err)
	}
	var document unifiedIdentityDocument
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if document.Version != unifiedIdentityFileVersion || len(document.Identities) != 2 {
		t.Fatalf("unified identity document = %+v", document)
	}
	roles := map[identityRole]int{}
	for _, identity := range document.Identities {
		roles[identity.Role]++
	}
	if roles[identityRoleAdministrator] != 1 || roles[identityRoleUser] != 1 {
		t.Fatalf("persisted roles = %+v", roles)
	}
	if err := replaceAdminAccessWithPasswordDeriver(
		accessPath, "new.admin", []byte("New-Administrator!Password-593"),
		fastTestPasswordDeriver,
		bytes.NewReader(bytes.Repeat([]byte{0x41}, passwordSaltBytes)),
	); err != nil {
		t.Fatal(err)
	}
	encoded, err = os.ReadFile(accessPath)
	if err != nil {
		t.Fatal(err)
	}
	document = unifiedIdentityDocument{}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Identities) != 2 {
		t.Fatalf("administrator replacement removed user identities: %+v", document)
	}
	for _, identity := range document.Identities {
		if identity.Role == identityRoleUser && identity.LoginUsername != "member" {
			t.Fatalf("administrator replacement changed user identity: %+v", identity)
		}
	}
}

func TestUnifiedIdentityMigrationRejectsAdministratorUsernameOverlap(t *testing.T) {
	directory := t.TempDir()
	accessPath := filepath.Join(directory, "web-auth.json")
	legacyUserPath := filepath.Join(directory, "end-user-auth.json")
	if err := initializeAdminAccessWithPasswordDeriver(
		accessPath, testAdminUsername, []byte(testAdminPassword), fastTestPasswordDeriver,
		bytes.NewReader(bytes.Repeat([]byte{0x32}, passwordSaltBytes)),
	); err != nil {
		t.Fatal(err)
	}
	legacy, err := openEndUserAccessWithPasswordDeriver(
		legacyUserPath, filepath.Join(directory, "end-user-sessions.json"),
		fastTestPasswordDeriver, nilSafeRandomReader{},
	)
	if err != nil {
		t.Fatal(err)
	}
	token, _, _ := legacy.IssueInvitation("usr_overlap", defaultUserInviteLifetime)
	if _, err := legacy.ClaimInvitation(token, testAdminUsername, testEndUserPassword); err != nil {
		t.Fatal(err)
	}
	_, _, err = OpenUnifiedWebAccess(
		accessPath, legacyUserPath, filepath.Join(directory, "web-sessions.json"),
		filepath.Join(directory, "end-user-sessions.json"),
	)
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("overlap migration error = %v", err)
	}
}

func TestEndUserInvitationClaimAndSessionLifecycle(t *testing.T) {
	t.Parallel()
	manager, accessPath, sessionPath, now := newTestEndUserAccessManager(t)
	if defaultUserInviteLifetime != 24*time.Hour {
		t.Fatalf("default invitation lifetime = %v", defaultUserInviteLifetime)
	}

	token, expiresAt, err := manager.IssueInvitation("usr_alice", defaultUserInviteLifetime)
	if err != nil {
		t.Fatalf("IssueInvitation() error = %v", err)
	}
	if len(token) != encodedCredentialLength || !expiresAt.Equal(now().Add(defaultUserInviteLifetime)) {
		t.Fatalf("IssueInvitation() returned malformed result: token length %d, expires %v", len(token), expiresAt)
	}
	status := manager.Status("usr_alice")
	if status.Claimed || !status.InvitationReady {
		t.Fatalf("Status() after invitation = %+v", status)
	}
	assertFileOmitsSecrets(t, accessPath, token, testEndUserPassword)

	session, err := manager.ClaimInvitation(token, "Alice.Login", testEndUserPassword)
	if err != nil {
		t.Fatalf("ClaimInvitation() error = %v", err)
	}
	if session.UserID != "usr_alice" || session.LoginUsername != "alice.login" || len(session.Token) != encodedCredentialLength {
		t.Fatalf("ClaimInvitation() session = %+v", session)
	}
	if _, err := manager.ClaimInvitation(token, "another", testEndUserPassword); !errors.Is(err, ErrInvitationInvalid) {
		t.Fatalf("reused invitation error = %v, want ErrInvitationInvalid", err)
	}
	assertFileOmitsSecrets(t, accessPath, token, testEndUserPassword)
	assertFileOmitsSecrets(t, sessionPath, session.Token, testEndUserPassword)
	assertPrivateFileMode(t, accessPath)
	assertPrivateFileMode(t, sessionPath)

	authenticated, err := manager.Authenticate(session.Token)
	if err != nil || authenticated.UserID != "usr_alice" {
		t.Fatalf("Authenticate() = %+v, %v", authenticated, err)
	}
	if manager.AuthorizeCSRF(session.Token, strings.Repeat("A", encodedCredentialLength)) {
		t.Fatal("AuthorizeCSRF() accepted an invalid synchronizer token")
	}
	if !manager.AuthorizeCSRF(session.Token, session.CSRFToken) {
		t.Fatal("AuthorizeCSRF() rejected valid credentials")
	}

	reopened, err := openEndUserAccessWithPasswordDeriver(accessPath, sessionPath, fastTestPasswordDeriver, nilSafeRandomReader{})
	if err != nil {
		t.Fatalf("reopen end-user access: %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened end-user access: %v", err)
		}
	})
	reopened.now = now
	if _, err := reopened.Authenticate(session.Token); err != nil {
		t.Fatalf("persisted session did not survive reopen: %v", err)
	}
	if _, err := reopened.LoginForClient("client-a", "alice.login", testEndUserPassword); err != nil {
		t.Fatalf("LoginForClient() error = %v", err)
	}
	if _, err := reopened.LoginForClient("client-b", "alice.login", "wrong-but-long-enough-password"); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong password error = %v", err)
	}

	if _, _, err := reopened.IssueInvitation("usr_alice", defaultUserInviteLifetime); err != nil {
		t.Fatalf("reset IssueInvitation() error = %v", err)
	}
	if _, err := reopened.Authenticate(session.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("reset login left old session valid: %v", err)
	}
	resetStatus := reopened.Status("usr_alice")
	if resetStatus.Claimed || resetStatus.LoginUsername != "" || !resetStatus.InvitationReady {
		t.Fatalf("Status() after reset = %+v", resetStatus)
	}
}

func TestInvalidInvitationIsRejectedBeforePasswordKDF(t *testing.T) {
	t.Parallel()
	manager, _, _, _ := newTestEndUserAccessManager(t)
	calls := 0
	manager.derivePassword = func(password, salt []byte) [passwordHashBytes]byte {
		calls++
		return fastTestPasswordDeriver(password, salt)
	}
	if _, err := manager.ClaimInvitation(strings.Repeat("A", encodedCredentialLength), "unused.user", testEndUserPassword); !errors.Is(err, ErrInvitationInvalid) {
		t.Fatalf("ClaimInvitation() error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("invalid invitation ran %d password derivations", calls)
	}
}

func TestEndUserInvitationExpiresAfterTwentyFourHours(t *testing.T) {
	t.Parallel()
	manager, _, _, current := newTestEndUserAccessManager(t)
	token, _, err := manager.IssueInvitation("usr_expiring", defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	deadline := current().Add(24 * time.Hour)
	manager.now = func() time.Time { return deadline }
	if manager.InvitationValid(token) {
		t.Fatal("invitation remained valid at its 24-hour deadline")
	}
	if _, err := manager.ClaimInvitation(token, "expired.user", testEndUserPassword); !errors.Is(err, ErrInvitationInvalid) {
		t.Fatalf("expired invitation error = %v", err)
	}
}

func TestEndUserSessionActivityPersistenceIsCoalesced(t *testing.T) {
	t.Parallel()
	manager, _, sessionPath, current := newTestEndUserAccessManager(t)
	token, _, err := manager.IssueInvitation("usr_activity", defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.ClaimInvitation(token, "activity.user", testEndUserPassword)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	manager.activityInterval = 24 * time.Hour
	advanced := current().Add(time.Hour)
	manager.now = func() time.Time { return advanced }
	refreshed, err := manager.Authenticate(session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed.ExpiresAt.Equal(advanced.Add(DefaultSessionIdleTimeout)) {
		t.Fatalf("refreshed expiry = %v", refreshed.ExpiresAt)
	}
	after, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("routine session activity synchronously rewrote the session file")
	}
}

func TestEndUserLoginUsernameIsUnique(t *testing.T) {
	t.Parallel()
	manager, _, _, _ := newTestEndUserAccessManager(t)
	firstToken, _, err := manager.IssueInvitation("usr_first", defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	secondToken, _, err := manager.IssueInvitation("usr_second", defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ClaimInvitation(firstToken, "shared.name", testEndUserPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ClaimInvitation(secondToken, "SHARED.NAME", testEndUserPassword); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("duplicate username error = %v", err)
	}
	if !manager.InvitationValid(secondToken) {
		t.Fatal("username conflict consumed the second invitation")
	}
}

func TestEndUserFailedCSRFDoesNotExtendSession(t *testing.T) {
	t.Parallel()
	manager, _, _, current := newTestEndUserAccessManager(t)
	token, _, err := manager.IssueInvitation("usr_csrf", defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.ClaimInvitation(token, "csrf.user", testEndUserPassword)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := credentialDigest(session.Token)
	manager.mu.Lock()
	originalExpiry := manager.sessions[digest].expiresAt
	manager.mu.Unlock()

	advanced := current().Add(time.Hour)
	manager.now = func() time.Time { return advanced }
	if manager.AuthorizeCSRF(session.Token, strings.Repeat("B", encodedCredentialLength)) {
		t.Fatal("AuthorizeCSRF() accepted invalid token")
	}
	manager.mu.Lock()
	afterFailure := manager.sessions[digest].expiresAt
	manager.mu.Unlock()
	if !afterFailure.Equal(originalExpiry) {
		t.Fatalf("failed CSRF extended session from %v to %v", originalExpiry, afterFailure)
	}
	if !manager.AuthorizeCSRF(session.Token, session.CSRFToken) {
		t.Fatal("AuthorizeCSRF() rejected valid token")
	}
	manager.mu.Lock()
	afterSuccess := manager.sessions[digest].expiresAt
	manager.mu.Unlock()
	if !afterSuccess.Equal(advanced.Add(DefaultSessionIdleTimeout)) {
		t.Fatalf("successful CSRF expiry = %v", afterSuccess)
	}
}

func TestEndUserReconcileRemovesDeletedIdentity(t *testing.T) {
	t.Parallel()
	manager, _, _, _ := newTestEndUserAccessManager(t)
	token, _, err := manager.IssueInvitation("usr_deleted", defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	session, err := manager.ClaimInvitation(token, "deleted.user", testEndUserPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ReconcileUsers(map[string]struct{}{}); err != nil {
		t.Fatal(err)
	}
	if status := manager.Status("usr_deleted"); status != (EndUserAccountStatus{}) {
		t.Fatalf("deleted account status = %+v", status)
	}
	if _, err := manager.Authenticate(session.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("deleted account session error = %v", err)
	}
}

func newTestEndUserAccessManager(t *testing.T) (*EndUserAccessManager, string, string, func() time.Time) {
	t.Helper()
	directory := t.TempDir()
	accessPath := filepath.Join(directory, "end-user-auth.json")
	sessionPath := filepath.Join(directory, "end-user-sessions.json")
	manager, err := openEndUserAccessWithPasswordDeriver(
		accessPath,
		sessionPath,
		fastTestPasswordDeriver,
		nilSafeRandomReader{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close end-user access: %v", err)
		}
	})
	fixed := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return fixed }
	manager.now = now
	manager.passwordKDFLimiter = newPasswordKDFLimiter(1, 8, time.Second)
	return manager, accessPath, sessionPath, now
}

func assertFileOmitsSecrets(t *testing.T, path string, secrets ...string) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(string(encoded), secret) {
			t.Fatalf("%s contains plaintext secret", filepath.Base(path))
		}
	}
}

func assertPrivateFileMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode = %o, want 0600", filepath.Base(path), info.Mode().Perm())
	}
}
