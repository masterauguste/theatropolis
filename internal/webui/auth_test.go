package webui

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestInitializeAccessCreatesExclusiveDigestOnlyFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.json")
	accessKey, err := InitializeAccess(path)
	if err != nil {
		t.Fatalf("InitializeAccess() error = %v", err)
	}
	decodedKey, err := base64.RawURLEncoding.DecodeString(accessKey)
	if err != nil || len(decodedKey) != credentialBytes {
		t.Fatalf("InitializeAccess() returned malformed key %q", accessKey)
	}

	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), accessKey) {
		t.Fatal("access file contains the plaintext access key")
	}
	var document struct {
		Version         int    `json:"version"`
		AccessKeySHA256 string `json:"access_key_sha256"`
	}
	if err := json.Unmarshal(stored, &document); err != nil {
		t.Fatal(err)
	}
	expectedDigest := sha256.Sum256(decodedKey)
	if document.Version != accessFileVersion ||
		document.AccessKeySHA256 != base64.RawURLEncoding.EncodeToString(expectedDigest[:]) {
		t.Fatalf("unexpected persisted access document: %+v", document)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("access file permissions = %o, want 0600", info.Mode().Perm())
	}

	before := string(stored)
	if _, err := InitializeAccess(path); err == nil {
		t.Fatal("second InitializeAccess() unexpectedly replaced the file")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != before {
		t.Fatal("failed exclusive initialization changed the existing access file")
	}

	manager, err := LoadAccess(path)
	if err != nil {
		t.Fatalf("LoadAccess() error = %v", err)
	}
	if _, err := manager.Login(accessKey); err != nil {
		t.Fatalf("Login() with initialized key error = %v", err)
	}
}

func TestLoadAccessRejectsMalformedDocuments(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("test access key"))
	encodedDigest := base64.RawURLEncoding.EncodeToString(digest[:])
	tests := map[string]string{
		"not object":        `[]`,
		"unknown field":     `{"version":1,"access_key_sha256":"` + encodedDigest + `","extra":true}`,
		"duplicate version": `{"version":1,"version":1,"access_key_sha256":"` + encodedDigest + `"}`,
		"missing version":   `{"access_key_sha256":"` + encodedDigest + `"}`,
		"missing digest":    `{"version":1}`,
		"wrong version":     `{"version":2,"access_key_sha256":"` + encodedDigest + `"}`,
		"invalid digest":    `{"version":1,"access_key_sha256":"not-a-digest"}`,
		"trailing JSON":     `{"version":1,"access_key_sha256":"` + encodedDigest + `"} {}`,
		"empty":             ``,
	}

	for name, contents := range tests {
		name, contents := name, contents
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "access.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadAccess(path); err == nil {
				t.Fatal("LoadAccess() unexpectedly accepted malformed access JSON")
			}
		})
	}
}

func TestLoadAccessRejectsInsecureFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix file permission bits")
	}
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.json")
	if _, err := InitializeAccess(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccess(path); err == nil {
		t.Fatal("LoadAccess() accepted a group/world-readable access file")
	}
}

func TestLoadAccessAcceptsRootOwnedGroupReadableMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix file permission bits")
	}
	t.Parallel()

	path := filepath.Join(t.TempDir(), "web-auth.json")
	if _, err := InitializeAccess(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccess(path); err != nil {
		t.Fatalf("LoadAccess() rejected mode 0640: %v", err)
	}
}

func TestLoadAccessRejectsSymbolicLink(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	target := filepath.Join(directory, "access.json")
	if _, err := InitializeAccess(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "access-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := LoadAccess(link); err == nil {
		t.Fatal("LoadAccess() accepted a symbolic link")
	}
}

func TestSessionAuthenticationIdleExpiryCSRFAndLogout(t *testing.T) {
	t.Parallel()

	manager, accessKey := newTestAccessManager(t)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.sessionIdleTimeout = 10 * time.Minute
	manager.sessionAbsoluteTimeout = time.Hour

	session, err := manager.Login(accessKey)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if len(session.Token) != encodedCredentialLength ||
		len(session.CSRFToken) != encodedCredentialLength {
		t.Fatalf("Login() returned malformed session: %+v", session)
	}
	if want := now.Add(time.Hour); !session.ExpiresAt.Equal(want) {
		t.Fatalf("session ExpiresAt = %v, want %v", session.ExpiresAt, want)
	}

	authenticated, err := manager.Authenticate(session.Token)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if authenticated != session {
		t.Fatalf("Authenticate() = %+v, want %+v", authenticated, session)
	}
	if _, err := manager.Authenticate("not-a-session"); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Authenticate(invalid) error = %v, want ErrAuthenticationFailed", err)
	}
	if manager.AuthorizeCSRF(session.Token, "not-a-csrf-token") {
		t.Fatal("AuthorizeCSRF() accepted an invalid token")
	}
	if !manager.AuthorizeCSRF(session.Token, session.CSRFToken) {
		t.Fatal("AuthorizeCSRF() rejected valid credentials")
	}

	now = now.Add(9 * time.Minute)
	if _, err := manager.Authenticate(session.Token); err != nil {
		t.Fatalf("Authenticate() before idle expiry error = %v", err)
	}
	now = now.Add(9 * time.Minute)
	if _, err := manager.Authenticate(session.Token); err != nil {
		t.Fatalf("Authenticate() after idle refresh error = %v", err)
	}
	now = now.Add(10 * time.Minute)
	if _, err := manager.Authenticate(session.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Authenticate() at idle expiry error = %v, want ErrAuthenticationFailed", err)
	}

	replacement, err := manager.Login(accessKey)
	if err != nil {
		t.Fatal(err)
	}
	manager.Logout(replacement.Token)
	if _, err := manager.Authenticate(replacement.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Authenticate() after logout error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestFailedCSRFAttemptDoesNotRefreshIdleExpiry(t *testing.T) {
	t.Parallel()

	manager, accessKey := newTestAccessManager(t)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.sessionIdleTimeout = 10 * time.Minute

	session, err := manager.Login(accessKey)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Minute)
	if manager.AuthorizeCSRF(session.Token, strings.Repeat("A", encodedCredentialLength)) {
		t.Fatal("AuthorizeCSRF() accepted the wrong token")
	}
	now = now.Add(2 * time.Minute)
	if _, err := manager.Authenticate(session.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("failed CSRF kept session alive; Authenticate() error = %v", err)
	}
}

func TestSessionAbsoluteExpiryCannotBeExtended(t *testing.T) {
	t.Parallel()

	manager, accessKey := newTestAccessManager(t)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.sessionIdleTimeout = 10 * time.Minute
	manager.sessionAbsoluteTimeout = 25 * time.Minute

	session, err := manager.Login(accessKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, elapsed := range []time.Duration{9, 18, 24} {
		now = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC).
			Add(elapsed * time.Minute)
		if _, err := manager.Authenticate(session.Token); err != nil {
			t.Fatalf("Authenticate() at %v error = %v", elapsed*time.Minute, err)
		}
	}
	now = time.Date(2026, 7, 27, 12, 25, 0, 0, time.UTC)
	if _, err := manager.Authenticate(session.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Authenticate() at absolute expiry error = %v", err)
	}
}

func TestGlobalLoginFailureLimiterIsBoundedAndDoesNotLockOutValidKey(t *testing.T) {
	t.Parallel()

	manager, accessKey := newTestAccessManager(t)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	for attempt := 0; attempt < manager.loginFailureLimit; attempt++ {
		if _, err := manager.Login("invalid"); !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("failed Login() attempt %d error = %v", attempt+1, err)
		}
	}
	if _, err := manager.Login("invalid"); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("Login() beyond failure limit error = %v, want ErrLoginRateLimited", err)
	}
	if _, err := manager.Login(accessKey); err != nil {
		t.Fatalf("valid Login() while limiter active error = %v", err)
	}
	if _, err := manager.Login("invalid"); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("valid login did not reset limiter: %v", err)
	}

	for attempt := 1; attempt < manager.loginFailureLimit; attempt++ {
		_, _ = manager.Login("invalid")
	}
	now = now.Add(manager.loginFailureWindow)
	if _, err := manager.Login("invalid"); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("expired failure window was not reset: %v", err)
	}
}

func TestSessionsAreBounded(t *testing.T) {
	t.Parallel()

	manager, accessKey := newTestAccessManager(t)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.maxSessions = 2

	first, err := manager.Login(accessKey)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	second, err := manager.Login(accessKey)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	third, err := manager.Login(accessKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Authenticate(first.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("oldest session was not evicted: %v", err)
	}
	if _, err := manager.Authenticate(second.Token); err != nil {
		t.Fatalf("second session was unexpectedly evicted: %v", err)
	}
	if _, err := manager.Authenticate(third.Token); err != nil {
		t.Fatalf("newest session was unexpectedly evicted: %v", err)
	}
}

func TestSessionCookieSecurityAttributes(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 7, 28, 0, 0, 0, 0, time.FixedZone("test", 3600))
	cookie := NewSessionCookie("session-token", expiresAt)
	if cookie.Name != SessionCookieName ||
		cookie.Path != "/" ||
		cookie.Domain != "" ||
		!cookie.Secure ||
		!cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteStrictMode ||
		!cookie.Expires.Equal(expiresAt.UTC()) {
		t.Fatalf("insecure session cookie: %+v", cookie)
	}

	deleted := DeleteSessionCookie()
	if deleted.Name != SessionCookieName ||
		deleted.Value != "" ||
		deleted.Path != "/" ||
		deleted.Domain != "" ||
		!deleted.Secure ||
		!deleted.HttpOnly ||
		deleted.SameSite != http.SameSiteStrictMode ||
		deleted.MaxAge != -1 ||
		!deleted.Expires.Before(time.Now()) {
		t.Fatalf("insecure deletion cookie: %+v", deleted)
	}
}

func newTestAccessManager(t *testing.T) (*AccessManager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.json")
	accessKey, err := InitializeAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := LoadAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	return manager, accessKey
}
