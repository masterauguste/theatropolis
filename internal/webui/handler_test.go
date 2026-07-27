package webui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/identity"
)

const testPublicURL = "https://master.example.com:8443"

type testSessions map[string]bool

func (s testSessions) IsOnline(agentID string) bool {
	return s[agentID]
}

type webFixture struct {
	handler  http.Handler
	registry *identity.Registry
	access   *AccessManager
	username string
	password string
	session  Session
	now      time.Time
}

func TestProtectedPagesRequireAuthenticationAndConfiguredHost(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	request := fixture.request(http.MethodGet, "/servers", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated GET /servers = %d %q", response.Code, response.Header().Get("Location"))
	}
	if response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("unauthenticated GET /servers changed cookies: %q", response.Header().Get("Set-Cookie"))
	}
	assertSecurityHeaders(t, response.Header())

	request = fixture.request(http.MethodGet, "/servers", "")
	request.Host = "attacker.example:8443"
	request.AddCookie(NewSessionCookie(fixture.session.Token, fixture.session.ExpiresAt))
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("wrong Host status = %d, want %d", response.Code, http.StatusMisdirectedRequest)
	}

	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/healthz", nil)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != `{"status":"ok"}`+"\n" {
		t.Fatalf("loopback health response = %d %q", response.Code, response.Body.String())
	}
	assertSecurityHeaders(t, response.Header())
}

func TestLoginRequiresSameOriginAndCreatesSecureSession(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	form := url.Values{
		"username": {fixture.username},
		"password": {fixture.password},
	}.Encode()

	request := fixture.request(http.MethodPost, "/login", form)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("login without Origin status = %d, want %d", response.Code, http.StatusForbidden)
	}

	request = fixture.request(http.MethodPost, "/login", form)
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login status = %d, want %d", response.Code, http.StatusForbidden)
	}

	request = fixture.mutationRequest(http.MethodPost, "/login", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/servers" {
		t.Fatalf("valid login response = %d %q", response.Code, response.Header().Get("Location"))
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login set %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != SessionCookieName ||
		!cookie.Secure ||
		!cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteStrictMode ||
		cookie.Path != "/" ||
		cookie.Domain != "" {
		t.Fatalf("login set insecure cookie: %+v", cookie)
	}
	if strings.Contains(response.Body.String(), fixture.password) {
		t.Fatal("login response reflected the operator password")
	}
}

func TestUsernamePasswordLoginFormIsAccessibleAndDoesNotReflectSecrets(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	request := fixture.request(http.MethodGet, "/login", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /login status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, expected := range []string{
		`name="username"`,
		`autocomplete="username"`,
		`autocapitalize="none"`,
		`spellcheck="false"`,
		`pattern="[a-z0-9][a-z0-9._-]{0,63}"`,
		`name="password"`,
		`autocomplete="current-password"`,
		`maxlength="512"`,
		`aria-label="Show password"`,
		`data-secret-label="password"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("login form does not contain %q", expected)
		}
	}
	if strings.Contains(body, `name="access_key"`) {
		t.Fatal("username/password login page exposed the legacy access-key form")
	}

	untrustedUsername := `operator"><script>alert(1)</script>`
	submittedPassword := "password-that-must-not-be-reflected"
	form := url.Values{
		"username": {untrustedUsername},
		"password": {submittedPassword},
	}.Encode()
	request = fixture.mutationRequest(http.MethodPost, "/login", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf(
			"invalid login status = %d, want %d",
			response.Code,
			http.StatusUnauthorized,
		)
	}
	body = response.Body.String()
	if !strings.Contains(body, "The username or password was not accepted.") {
		t.Fatal("invalid login did not return the generic credential error")
	}
	if strings.Contains(body, untrustedUsername) ||
		!strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("invalid login did not safely preserve the submitted username")
	}
	if strings.Contains(body, submittedPassword) {
		t.Fatal("invalid login reflected the submitted password")
	}
	if count := strings.Count(body, `aria-invalid="true"`); count != 2 {
		t.Fatalf("invalid login marked %d fields invalid, want 2", count)
	}
}

func TestUsernamePasswordLoginRequiresExactBoundedFields(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	tests := map[string]string{
		"missing username": url.Values{
			"password": {fixture.password},
		}.Encode(),
		"missing password": url.Values{
			"username": {fixture.username},
		}.Encode(),
		"duplicate username": url.Values{
			"username": {fixture.username, "other"},
			"password": {fixture.password},
		}.Encode(),
		"unexpected field": url.Values{
			"username": {fixture.username},
			"password": {fixture.password},
			"remember": {"yes"},
		}.Encode(),
		"legacy field": url.Values{
			"access_key": {fixture.password},
		}.Encode(),
		"oversized password": url.Values{
			"username": {fixture.username},
			"password": {strings.Repeat("A", maxLoginBodyBytes)},
		}.Encode(),
	}
	for name, form := range tests {
		t.Run(name, func(t *testing.T) {
			request := fixture.mutationRequest(http.MethodPost, "/login", form)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf(
					"malformed login status = %d, want %d",
					response.Code,
					http.StatusBadRequest,
				)
			}
			if response.Header().Get("Set-Cookie") != "" {
				t.Fatalf(
					"malformed login changed cookies: %q",
					response.Header().Get("Set-Cookie"),
				)
			}
		})
	}
}

func TestLegacyAccessKeyLoginRemainsAvailableDuringMigration(t *testing.T) {
	t.Parallel()

	fixture := newLegacyWebFixture(t)
	request := fixture.request(http.MethodGet, "/login", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("legacy GET /login status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Legacy sign-in",
		`name="access_key"`,
		`data-secret-label="access key"`,
		`aria-label="Show access key"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("legacy login form does not contain %q", expected)
		}
	}
	if strings.Contains(body, `name="username"`) ||
		strings.Contains(body, `name="password"`) {
		t.Fatal("legacy login page exposed username/password fields")
	}

	form := url.Values{
		"username": {"operator"},
		"password": {"correct-horse-battery-staple"},
	}.Encode()
	request = fixture.mutationRequest(http.MethodPost, "/login", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"legacy login accepted v2 fields with status %d",
			response.Code,
		)
	}

	rejectedKey := strings.Repeat("B", encodedCredentialLength)
	form = url.Values{"access_key": {rejectedKey}}.Encode()
	request = fixture.mutationRequest(http.MethodPost, "/login", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized ||
		!strings.Contains(response.Body.String(), "The access key was not accepted.") {
		t.Fatalf(
			"invalid legacy login response = %d %q",
			response.Code,
			response.Body.String(),
		)
	}
	if strings.Contains(response.Body.String(), rejectedKey) {
		t.Fatal("invalid legacy login reflected the submitted access key")
	}

	form = url.Values{"access_key": {fixture.password}}.Encode()
	request = fixture.mutationRequest(http.MethodPost, "/login", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/servers" {
		t.Fatalf(
			"valid legacy login response = %d %q",
			response.Code,
			response.Header().Get("Location"),
		)
	}
	if cookies := response.Result().Cookies(); len(cookies) != 1 ||
		cookies[0].Name != SessionCookieName {
		t.Fatalf("valid legacy login cookies = %+v", cookies)
	}
}

func TestLoginAllowsTrustedOriginWithBrowserInitiatedFetchMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		fetchSite string
		origin    string
	}{
		{name: "browser initiated", fetchSite: "none", origin: testPublicURL},
		{name: "future metadata", fetchSite: "future-value", origin: testPublicURL},
		{name: "private same origin", fetchSite: "same-origin"},
		{name: "private browser initiated", fetchSite: "none"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebFixture(t)
			form := url.Values{
				"username": {fixture.username},
				"password": {fixture.password},
			}.Encode()
			request := httptest.NewRequest(
				http.MethodPost,
				"http://127.0.0.1:8080/login",
				strings.NewReader(form),
			)
			request.Host = "master.example.com:8443"
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			request.Header.Set("Sec-Fetch-Site", test.fetchSite)

			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)

			if response.Code != http.StatusSeeOther ||
				response.Header().Get("Location") != "/servers" {
				t.Fatalf(
					"trusted login with Sec-Fetch-Site %q = %d %q",
					test.fetchSite,
					response.Code,
					response.Header().Get("Location"),
				)
			}
		})
	}
}

func TestLoginRejectsUntrustedOrAmbiguousOriginMetadata(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	form := url.Values{
		"username": {fixture.username},
		"password": {fixture.password},
	}.Encode()
	tests := []struct {
		name            string
		path            string
		contentEncoding string
		fetchSites      []string
		origins         []string
		reason          string
	}{
		{
			name:       "mismatched origin overrides metadata",
			fetchSites: []string{"same-origin"},
			origins:    []string{"https://attacker.example"},
			reason:     "origin_mismatch",
		},
		{
			name:       "opaque origin",
			fetchSites: []string{"same-origin"},
			origins:    []string{"null"},
			reason:     "invalid_origin",
		},
		{
			name:       "cross-site metadata overrides origin",
			fetchSites: []string{"cross-site"},
			origins:    []string{testPublicURL},
			reason:     "cross_site",
		},
		{
			name:       "same-site metadata overrides origin",
			fetchSites: []string{"same-site"},
			origins:    []string{testPublicURL},
			reason:     "same_site",
		},
		{name: "missing origin and metadata", reason: "missing_origin"},
		{
			name:       "missing origin with unknown metadata",
			fetchSites: []string{"future-value"},
			reason:     "missing_origin",
		},
		{
			name:       "duplicate origin",
			fetchSites: []string{"same-origin"},
			origins:    []string{testPublicURL, testPublicURL},
			reason:     "multiple_origin_headers",
		},
		{
			name:       "duplicate fetch metadata",
			fetchSites: []string{"same-origin", "none"},
			origins:    []string{testPublicURL},
			reason:     "multiple_fetch_site_headers",
		},
		{
			name:            "encoded body",
			contentEncoding: "gzip",
			fetchSites:      []string{"same-origin"},
			origins:         []string{testPublicURL},
			reason:          "content_encoding",
		},
		{
			name:       "query string",
			path:       "/login?source=test",
			fetchSites: []string{"same-origin"},
			origins:    []string{testPublicURL},
			reason:     "query_string",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := test.path
			if path == "" {
				path = "/login"
			}
			request := httptest.NewRequest(
				http.MethodPost,
				"http://127.0.0.1:8080"+path,
				strings.NewReader(form),
			)
			request.Host = "master.example.com:8443"
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.contentEncoding != "" {
				request.Header.Set("Content-Encoding", test.contentEncoding)
			}
			for _, fetchSite := range test.fetchSites {
				request.Header.Add("Sec-Fetch-Site", fetchSite)
			}
			for _, origin := range test.origins {
				request.Header.Add("Origin", origin)
			}

			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)

			if response.Code != http.StatusForbidden {
				t.Fatalf(
					"untrusted login response = %d, want %d",
					response.Code,
					http.StatusForbidden,
				)
			}
			expectedBody := "request origin is not allowed (" + test.reason + ")\n"
			if response.Body.String() != expectedBody {
				t.Fatalf(
					"untrusted login body = %q, want %q",
					response.Body.String(),
					expectedBody,
				)
			}
		})
	}
}

func TestServersPageUsesRealEnrollmentAndConnectionState(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	ctx := context.Background()

	if _, err := fixture.registry.CreateEnrollment(
		ctx,
		"edge-pending",
		fixture.now.Add(10*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.registry.CreateEnrollment(
		ctx,
		"edge-expired",
		time.Now().Add(time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-offline")

	request := fixture.authenticatedRequest(http.MethodGet, "/servers", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /servers status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{
		"edge-pending",
		"edge-expired",
		"edge-online",
		"edge-offline",
		">Online<",
		"Offline",
		">Pending<",
		"Expired",
		"4 total",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("servers page does not contain %q", expected)
		}
	}
	if strings.Contains(body, "fake") || strings.Contains(body, "TOKEN") {
		t.Fatal("servers page contains placeholder data")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("servers Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
}

func TestCreateServerRequiresCSRFAndRevealsCommandOnce(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	form := url.Values{
		"agent_id":    {"edge-paris-1"},
		"csrf_token":  {fixture.session.CSRFToken},
		"ttl_seconds": {"900"},
	}.Encode()

	request := fixture.authenticatedRequest(http.MethodPost, "/servers", form)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("mutation without Origin status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if len(fixture.registry.Snapshot(fixture.now)) != 0 {
		t.Fatal("cross-site request created a server entry")
	}

	badCSRF := url.Values{
		"agent_id":    {"edge-paris-1"},
		"csrf_token":  {strings.Repeat("A", encodedCredentialLength)},
		"ttl_seconds": {"900"},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers", badCSRF)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("bad-CSRF status = %d, want %d", response.Code, http.StatusForbidden)
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("valid enrollment status = %d, body = %s", response.Code, response.Body.String())
	}
	resultLocation := response.Header().Get("Location")
	if !strings.HasPrefix(resultLocation, "/servers/enrollment-result?id=") {
		t.Fatalf("valid enrollment redirect = %q", resultLocation)
	}
	if strings.Contains(response.Body.String(), "--token") {
		t.Fatal("POST response exposed an enrollment token before the authenticated result GET")
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate pending enrollment status = %d, want %d", response.Code, http.StatusConflict)
	}
	if !strings.Contains(response.Body.String(), "already has a valid enrollment command") {
		t.Fatal("duplicate pending enrollment did not explain how to use the existing command")
	}

	request = fixture.authenticatedRequest(http.MethodGet, resultLocation, "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("result GET status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Install edge-paris-1",
		"--master &#39;master.example.com:8443&#39;",
		"--agent-id &#39;edge-paris-1&#39;",
		"Shown once.",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("created page does not contain %q", expected)
		}
	}
	tokenPattern := regexp.MustCompile(`--token &#39;([A-Za-z0-9_-]{43})&#39;`)
	match := tokenPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("created page does not contain one valid enrollment token")
	}
	token := match[1]

	request = fixture.authenticatedRequest(http.MethodGet, resultLocation, "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/servers" {
		t.Fatalf(
			"consumed result response = %d %q, want redirect to servers",
			response.Code,
			response.Header().Get("Location"),
		)
	}

	snapshots := fixture.registry.Snapshot(fixture.now)
	if len(snapshots) != 1 ||
		snapshots[0].ID != "edge-paris-1" ||
		snapshots[0].State != identity.AgentStatePending {
		t.Fatalf("unexpected registry snapshot: %+v", snapshots)
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/servers", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if strings.Contains(response.Body.String(), token) {
		t.Fatal("plaintext enrollment token was returned by the server list")
	}
}

func TestEnrollmentFormRejectsExtraAndDuplicateFields(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	tests := map[string]url.Values{
		"extra": {
			"agent_id":    {"edge-1"},
			"csrf_token":  {fixture.session.CSRFToken},
			"ttl_seconds": {"900"},
			"surprise":    {"true"},
		},
		"duplicate": {
			"agent_id":    {"edge-1", "edge-2"},
			"csrf_token":  {fixture.session.CSRFToken},
			"ttl_seconds": {"900"},
		},
	}
	for name, values := range tests {
		name, values := name, values
		t.Run(name, func(t *testing.T) {
			request := fixture.authenticatedMutationRequest(http.MethodPost, "/servers", values.Encode())
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("malformed form status = %d, want %d", response.Code, http.StatusForbidden)
			}
		})
	}
}

func TestEnrollmentResultIsBoundToCreatingSession(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	form := url.Values{
		"agent_id":    {"edge-session-bound"},
		"csrf_token":  {fixture.session.CSRFToken},
		"ttl_seconds": {"900"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("create status = %d", response.Code)
	}
	resultLocation := response.Header().Get("Location")

	otherSession, err := fixture.access.Login(fixture.username, fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	request = fixture.request(http.MethodGet, resultLocation, "")
	request.AddCookie(NewSessionCookie(otherSession.Token, otherSession.ExpiresAt))
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/servers" {
		t.Fatalf("other session received result: %d %q", response.Code, response.Body.String())
	}

	request = fixture.authenticatedRequest(http.MethodGet, resultLocation, "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "--token") {
		t.Fatalf("creating session could not receive result: %d", response.Code)
	}
}

func TestPublicURLValidation(t *testing.T) {
	t.Parallel()

	valid := map[string]string{
		"https://master.example.com:8443": "master.example.com:8443",
		"https://master.example.com:443":  "master.example.com:443",
		"https://[2001:db8::1]:8443":      "[2001:db8::1]:8443",
	}
	for raw, expectedAddress := range valid {
		parsed, err := parsePublicURL(raw)
		if err != nil {
			t.Errorf("parsePublicURL(%q) error = %v", raw, err)
			continue
		}
		if address := netJoinHostPort(parsed.hostname, parsed.port); address != expectedAddress {
			t.Errorf("parsePublicURL(%q) address = %q, want %q", raw, address, expectedAddress)
		}
	}

	for _, raw := range []string{
		"",
		"http://master.example.com:8443",
		"http://127.0.0.1:8080",
		"https://single-label",
		"https://user:pass@master.example.com",
		"https://master.example.com/path",
		"https://master.example.com?query=yes",
		"https://master.example.com:0",
		"https://master.example.com:99999",
	} {
		if _, err := parsePublicURL(raw); err == nil {
			t.Errorf("parsePublicURL(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestLogoutRejectsCrossOriginRequestsWithoutChangingCookies(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	request := fixture.request(http.MethodPost, "/logout", "")
	request.Header.Set("Origin", "https://attacker.example")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin logout status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("cross-origin logout changed cookies: %q", response.Header().Get("Set-Cookie"))
	}
}

func TestEnrollmentRateLimitReturnsTooManyRequests(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	for index := 0; index < enrollmentLimit; index++ {
		form := url.Values{
			"agent_id":    {fmt.Sprintf("edge-%d", index)},
			"csrf_token":  {fixture.session.CSRFToken},
			"ttl_seconds": {"900"},
		}.Encode()
		request := fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusSeeOther {
			t.Fatalf("enrollment %d status = %d", index, response.Code)
		}
	}

	form := url.Values{
		"agent_id":    {"edge-limited"},
		"csrf_token":  {fixture.session.CSRFToken},
		"ttl_seconds": {"900"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited status = %d, want %d", response.Code, http.StatusTooManyRequests)
	}
	if response.Header().Get("Retry-After") != "60" {
		t.Fatalf("rate-limited Retry-After = %q", response.Header().Get("Retry-After"))
	}
}

func TestEnrollmentPersistenceFailureReturnsInternalServerError(t *testing.T) {
	t.Parallel()

	registryPath := filepath.Join(t.TempDir(), "identities.json")
	registry, err := identity.OpenRegistry(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(registryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := newWebFixtureWithRegistry(t, registry)
	form := url.Values{
		"agent_id":    {"edge-storage-failure"},
		"csrf_token":  {fixture.session.CSRFToken},
		"ttl_seconds": {"900"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf(
			"persistence failure status = %d, want %d",
			response.Code,
			http.StatusInternalServerError,
		)
	}
	if strings.Contains(response.Body.String(), "replace identity registry") {
		t.Fatal("persistence failure exposed an internal error")
	}
}

func TestAssetsAreSelfHostedAndSecurityHeadersApplyToErrors(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	request := fixture.request(http.MethodGet, "/assets/app.js", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.HasPrefix(response.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("app.js response = %d %q", response.Code, response.Header().Get("Content-Type"))
	}
	assertSecurityHeaders(t, response.Header())

	request = fixture.request(http.MethodGet, "/not-found", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want %d", response.Code, http.StatusNotFound)
	}
	assertSecurityHeaders(t, response.Header())
}

func newWebFixture(t *testing.T) webFixture {
	t.Helper()
	return newWebFixtureWithRegistry(t, identity.NewRegistry())
}

func newWebFixtureWithRegistry(t *testing.T, registry *identity.Registry) webFixture {
	t.Helper()
	access, username, password := newTestAdminAccessManager(t)
	session, err := access.Login(username, password)
	if err != nil {
		t.Fatal(err)
	}
	return newWebFixtureWithAccess(
		t,
		registry,
		access,
		username,
		password,
		session,
	)
}

func newLegacyWebFixture(t *testing.T) webFixture {
	t.Helper()
	access, accessKey := newTestAccessManager(t)
	session, err := access.Login("", accessKey)
	if err != nil {
		t.Fatal(err)
	}
	return newWebFixtureWithAccess(
		t,
		identity.NewRegistry(),
		access,
		"",
		accessKey,
		session,
	)
}

func newWebFixtureWithAccess(
	t *testing.T,
	registry *identity.Registry,
	access *AccessManager,
	username, password string,
	session Session,
) webFixture {
	t.Helper()
	now := time.Now().UTC().Add(2 * time.Hour)
	handler, err := New(Options{
		Registry:  registry,
		Sessions:  testSessions{"edge-online": true},
		Access:    access,
		PublicURL: testPublicURL,
		Version:   "test",
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return webFixture{
		handler:  handler,
		registry: registry,
		access:   access,
		username: username,
		password: password,
		session:  session,
		now:      now,
	}
}

func (f webFixture) request(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, testPublicURL+path, strings.NewReader(body))
	request.Host = "master.example.com:8443"
	if body != "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return request
}

func (f webFixture) mutationRequest(method, path, body string) *http.Request {
	request := f.request(method, path, body)
	request.Header.Set("Origin", testPublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	return request
}

func (f webFixture) authenticatedRequest(method, path, body string) *http.Request {
	request := f.request(method, path, body)
	request.AddCookie(NewSessionCookie(f.session.Token, f.session.ExpiresAt))
	return request
}

func (f webFixture) authenticatedMutationRequest(method, path, body string) *http.Request {
	request := f.authenticatedRequest(method, path, body)
	request.Header.Set("Origin", testPublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	return request
}

func enrollAgent(t *testing.T, registry *identity.Registry, agentID string) {
	t.Helper()
	token, err := registry.CreateEnrollment(context.Background(), agentID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Enroll(context.Background(), agentID, token, publicKey, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func assertSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	for _, name := range []string{
		"Content-Security-Policy",
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
		"Permissions-Policy",
		"Referrer-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-Robots-Tag",
	} {
		if header.Get(name) == "" {
			t.Errorf("security header %s is missing", name)
		}
	}
	if got := header.Get("Referrer-Policy"); got != "strict-origin" {
		t.Errorf("Referrer-Policy = %q, want strict-origin", got)
	}
}

func netJoinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
