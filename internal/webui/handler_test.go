package webui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
)

const testPublicURL = "https://master.example.com:8443"

type testSessions map[string]bool

func (s testSessions) IsOnline(agentID string) bool {
	return s[agentID]
}

type testReleaseCatalog struct {
	releases []AgentRelease
	err      error
}

func (c testReleaseCatalog) Versions(context.Context) ([]AgentRelease, error) {
	return append([]AgentRelease(nil), c.releases...), c.err
}

type testRuleSetOptions struct {
	options []string
	err     error
}

func (c testRuleSetOptions) Options(context.Context) ([]string, error) {
	return append([]string(nil), c.options...), c.err
}

func (s testSessions) AgentInfo(agentID string) (control.AgentInfo, bool) {
	if !s[agentID] {
		return control.AgentInfo{}, false
	}
	info := control.AgentInfo{
		Version:         "v0.0.9",
		SingBoxVersion:  "v1.14.0-beta.2",
		OperatingSystem: "linux",
		Architecture:    "amd64",
	}
	if agentID == "edge-online" {
		info.ObservedAddress = "203.0.113.10"
	}
	return info, true
}

type probeRequest struct {
	agentID string
	family  string
}

type testAgentController struct {
	registry            *identity.Registry
	sessions            testSessions
	store               deployment.Store
	deployable          map[string]bool
	updatable           map[string]bool
	updates             map[string]control.AgentUpdateState
	singBoxUpdates      map[string]control.SingBoxUpdateState
	queueErr            error
	revokeErr           error
	poolRegistry        *pool.Registry
	propagateCalls      int
	deploymentListCalls int
	probeErr            error
	probeRequests       []probeRequest
}

func (c *testAgentController) DeploymentRecords(
	ctx context.Context,
) ([]deployment.Record, error) {
	c.deploymentListCalls++
	return c.store.List(ctx)
}

func (c *testAgentController) PoolRegistry() *pool.Registry {
	return c.poolRegistry
}

func (c *testAgentController) PropagateManualPoolChange(context.Context) {
	c.propagateCalls++
}

func (c *testAgentController) RequestAddressProbe(agentID, family string) error {
	if c.probeErr != nil {
		return c.probeErr
	}
	c.probeRequests = append(c.probeRequests, probeRequest{agentID: agentID, family: family})
	return nil
}

func (c *testAgentController) CanUpdateAgent(agentID string) bool {
	if c.updatable != nil {
		return c.updatable[agentID]
	}
	return c.sessions[agentID]
}

func (c *testAgentController) CanUpdateSingBox(agentID string) bool {
	return c.CanUpdateAgent(agentID)
}

func (c *testAgentController) LatestSingBoxUpdate(
	agentID string,
) (control.SingBoxUpdateState, bool) {
	state, exists := c.singBoxUpdates[agentID]
	return state, exists
}

func (c *testAgentController) QueueSingBoxUpdate(
	_ context.Context,
	agentID string,
	requestID string,
	targetVersion string,
) error {
	if c.queueErr != nil {
		return c.queueErr
	}
	if c.singBoxUpdates == nil {
		c.singBoxUpdates = make(map[string]control.SingBoxUpdateState)
	}
	c.singBoxUpdates[agentID] = control.SingBoxUpdateState{
		RequestID:      requestID,
		TargetVersion:  targetVersion,
		RunningVersion: "v1.14.0-beta.2",
		Status:         "requested",
		UpdatedAt:      time.Now().UTC(),
	}
	return nil
}

func (c *testAgentController) LatestAgentUpdate(
	agentID string,
) (control.AgentUpdateState, bool) {
	state, exists := c.updates[agentID]
	return state, exists
}

func (c *testAgentController) QueueAgentUpdate(
	_ context.Context,
	agentID string,
	requestID string,
	targetVersion string,
) error {
	if c.queueErr != nil {
		return c.queueErr
	}
	if c.updates == nil {
		c.updates = make(map[string]control.AgentUpdateState)
	}
	c.updates[agentID] = control.AgentUpdateState{
		RequestID:      requestID,
		TargetVersion:  targetVersion,
		RunningVersion: "v0.0.9",
		Status:         "requested",
		UpdatedAt:      time.Now().UTC(),
	}
	return nil
}

func (c *testAgentController) CanDeployConfiguration(agentID string) bool {
	if c.deployable != nil {
		return c.deployable[agentID]
	}
	return c.sessions[agentID]
}

func (c *testAgentController) LatestDeployment(
	ctx context.Context,
	agentID string,
) (deployment.Record, error) {
	return c.store.LatestForAgent(ctx, agentID)
}

func (c *testAgentController) QueueDeployment(
	ctx context.Context,
	agentID string,
	deploymentID string,
	revisionID string,
	config []byte,
	_ time.Duration,
) (deployment.Record, error) {
	if c.queueErr != nil {
		return deployment.Record{}, c.queueErr
	}
	record, err := deployment.New(
		deploymentID,
		agentID,
		revisionID,
		config,
		time.Now().UTC(),
	)
	if err != nil {
		return deployment.Record{}, err
	}
	if err := c.store.Create(ctx, record); err != nil {
		return deployment.Record{}, err
	}
	return c.store.Transition(
		ctx,
		record.ID,
		deployment.StatusDeploying,
		"",
		time.Now().UTC(),
	)
}

func (c *testAgentController) RevokeAgent(
	ctx context.Context,
	agentID string,
) error {
	if c.revokeErr != nil {
		return c.revokeErr
	}
	if err := c.registry.Revoke(ctx, agentID); err != nil {
		return err
	}
	c.sessions[agentID] = false
	if err := c.store.RemoveAgent(ctx, agentID); err != nil &&
		!errors.Is(err, deployment.ErrNotFound) {
		return err
	}
	return nil
}

type webFixture struct {
	handler    http.Handler
	registry   *identity.Registry
	controller *testAgentController
	access     *AccessManager
	username   string
	password   string
	session    Session
	now        time.Time
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
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `data-async-url="/servers/content"`) ||
		!strings.Contains(response.Body.String(), "Loading servers…") {
		t.Fatalf("GET /servers did not render the loading shell: %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "edge-online") {
		t.Fatal("GET /servers blocked on and embedded fleet data instead of rendering its shell")
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/servers/content", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /servers/content status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{
		`<h2 id="fleet-heading">Servers</h2>`,
		"edge-pending",
		"edge-expired",
		"edge-online",
		"edge-offline",
		"Established",
		"Not established",
		"4 total",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("servers page does not contain %q", expected)
		}
	}
	if strings.Contains(body, "fake") || strings.Contains(body, "TOKEN") {
		t.Fatal("servers page contains placeholder data")
	}
	for _, unexpected := range []string{
		"Singers",
		"Troupe summary",
		"server-name__avatar",
		"Agent-managed server",
		`data-label="Actions"`,
	} {
		if strings.Contains(body, unexpected) {
			t.Errorf("servers page still contains %q", unexpected)
		}
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("servers Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
}

func TestAuthenticatedHeaderLinksServersAndSettings(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	request := fixture.authenticatedRequest(http.MethodGet, "/servers", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /servers status = %d, body = %s", response.Code, response.Body.String())
	}

	body := response.Body.String()
	for _, unexpected := range []string{
		"Master endpoint",
		"endpoint-card",
		testPublicURL,
	} {
		if strings.Contains(body, unexpected) {
			t.Errorf("authenticated header contains %q", unexpected)
		}
	}
	for _, expected := range []string{
		`class="global-header"`,
		`href="/servers"`,
		`href="/pool"`,
		`href="/settings"`,
		`action="/logout"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("authenticated header does not contain %q", expected)
		}
	}
	if strings.Contains(body, `class="sidebar"`) {
		t.Fatal("authenticated page still renders the removed sidebar")
	}
}

func TestSettingsPageOwnsMasterSoftwareManagement(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	request := fixture.authenticatedRequest(http.MethodGet, "/settings", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /settings status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Global settings",
		"Master software",
		`action="/master-update"`,
		`data-master-latest-label`,
		`data-agent-catalog-loading`,
		`data-master-version-refresh`,
		`data-version-catalog-url="/settings/versions"`,
		`href="/settings" class="is-active"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("settings page does not contain %q", expected)
		}
	}
}

func TestServerManagementPageShowsConfigurationAndRevocationControls(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")

	request := fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/manage",
		"",
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf(
			"GET server management status = %d, body = %s",
			response.Code,
			response.Body.String(),
		)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Server management",
		"edge-online",
		"sing-box configuration",
		"Validate and deploy",
		"Self-signed by agent",
		`<option value="all">All traffic</option>`,
		`<option value="inbound">Inbound</option>`,
		`<option value="domain">Domain</option>`,
		`<option value="domain_keyword">Domain Keyword</option>`,
		`<option value="domain_regex">Regex</option>`,
		`<option value="geosite">Geosite</option>`,
		`action="/servers/edge-online/revoke"`,
		`name="confirm_revoke"`,
		"Revoke access",
		"does not uninstall the remote agent",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("server management page does not contain %q", expected)
		}
	}
	if strings.Contains(body, testPublicURL) {
		t.Fatal("server management page exposed the master endpoint")
	}
	if strings.Contains(body, "Master software") || strings.Contains(body, `action="/master-update"`) {
		t.Fatal("server management page still contains global master controls")
	}
	for _, removed := range []string{
		"All traffic on this agent",
		"A specific inbound",
		"Exact domain",
		"Domain regular expression",
		"Geosite domains",
	} {
		if strings.Contains(body, removed) {
			t.Errorf("server management page still contains verbose routing label %q", removed)
		}
	}

	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/unknown/manage",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown server detail status = %d, want 404", response.Code)
	}
}

func TestReservedLookingAgentIDsUseUnambiguousManagementRoute(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	for _, agentID := range []string{"new", "enrollment-result"} {
		enrollAgent(t, fixture.registry, agentID)
		request := fixture.authenticatedRequest(
			http.MethodGet,
			"/servers/"+agentID+"/manage",
			"",
		)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK ||
			!strings.Contains(response.Body.String(), agentID) {
			t.Fatalf(
				"management page for %q = %d %q",
				agentID,
				response.Code,
				response.Body.String(),
			)
		}
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/servers/content", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	for _, expected := range []string{
		`href="/servers/new/manage"`,
		`href="/servers/enrollment-result/manage"`,
	} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("servers page does not contain %q", expected)
		}
	}
}

func TestReadExactFormAcceptsOnlyUTF8ContentTypeParameter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		wantError   bool
	}{
		{
			name:        "native form",
			contentType: "application/x-www-form-urlencoded",
		},
		{
			name:        "URLSearchParams fetch",
			contentType: "application/x-www-form-urlencoded;charset=UTF-8",
		},
		{
			name:        "unsupported charset",
			contentType: "application/x-www-form-urlencoded;charset=iso-8859-1",
			wantError:   true,
		},
		{
			name:        "unexpected parameter",
			contentType: "application/x-www-form-urlencoded;profile=browser",
			wantError:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				testPublicURL+"/form",
				strings.NewReader("field=value"),
			)
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			form, err := readExactForm(response, request, 1024, "field")
			if test.wantError {
				if err == nil {
					t.Fatalf("readExactForm() = %v, want an error", form)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if form.Get("field") != "value" {
				t.Fatalf("field = %q, want value", form.Get("field"))
			}
		})
	}
}

func TestConfigurationDeploymentRequiresAuthorizationAndValidJSONObject(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	validConfig := "{\n  \"log\": {\"level\": \"warn\"},\n  \"inbounds\": []\n}\n"
	form := url.Values{
		"config_json": {validConfig},
		"csrf_token":  {fixture.session.CSRFToken},
	}.Encode()

	request := fixture.authenticatedRequest(
		http.MethodPost,
		"/servers/edge-online/configuration",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("configuration without Origin status = %d, want 403", response.Code)
	}
	if _, err := fixture.controller.store.LatestForAgent(
		context.Background(),
		"edge-online",
	); !errors.Is(err, deployment.ErrNotFound) {
		t.Fatalf("unauthorized configuration created deployment: %v", err)
	}

	duplicateConfig := `{"log":{"level":"info"},"log":{"level":"debug"}}`
	invalidForm := url.Values{
		"config_json": {duplicateConfig},
		"csrf_token":  {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/configuration",
		invalidForm,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "duplicate object key") {
		t.Fatalf(
			"duplicate-key configuration response = %d %q",
			response.Code,
			response.Body.String(),
		)
	}

	reservedPortForm := url.Values{
		"config_json": {`{"inbounds":[{"type":"anytls","listen_port":80}]}`},
		"csrf_token":  {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/configuration",
		reservedPortForm,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "reserved for ACME HTTP-01") {
		t.Fatalf(
			"reserved-port configuration response = %d %q",
			response.Code,
			response.Body.String(),
		)
	}

	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/configuration",
		form,
	)
	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded;charset=UTF-8",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/servers/edge-online/manage" {
		t.Fatalf(
			"valid deployment response = %d %q, body = %s",
			response.Code,
			response.Header().Get("Location"),
			response.Body.String(),
		)
	}
	record, err := fixture.controller.store.LatestForAgent(
		context.Background(),
		"edge-online",
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != deployment.StatusDeploying ||
		string(record.ConfigJSON) != validConfig {
		t.Fatalf(
			"queued deployment = status %q config %q",
			record.Status,
			string(record.ConfigJSON),
		)
	}

	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/manage",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK ||
		!strings.Contains(
			body,
			`data-deployment-refresh-url="/servers/edge-online/manage"`,
		) ||
		!strings.Contains(
			body,
			`data-deployment-status-url="/servers/edge-online/deployment-status"`,
		) ||
		!strings.Contains(body, "Wait for the current deployment result") ||
		!strings.Contains(body, hex.EncodeToString(record.ConfigSHA256[:])) {
		t.Fatalf(
			"pending deployment page = %d %q",
			response.Code,
			body,
		)
	}

	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/deployment-status",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != "application/json" ||
		!strings.Contains(response.Body.String(), `"pending":true`) {
		t.Fatalf(
			"deployment polling status = %d %q",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestConfigurationDeploymentFetchReportsExpiredSession(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	if err := fixture.access.Logout(fixture.session.Token); err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"config_json": {`{"inbounds":[]}`},
		"csrf_token":  {fixture.session.CSRFToken},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/configuration",
		form,
	)
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired deployment fetch status = %d, want 401", response.Code)
	}
}

func TestConfigurationDeploymentJSONFlowReportsTerminalStatus(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	form := url.Values{
		"config_json": {`{"inbounds":[],"outbounds":[]}`},
		"csrf_token":  {fixture.session.CSRFToken},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/configuration",
		form,
	)
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted ||
		!strings.Contains(
			response.Body.String(),
			`"status_url":"/servers/edge-online/deployment-status"`,
		) {
		t.Fatalf(
			"JSON deployment response = %d %q",
			response.Code,
			response.Body.String(),
		)
	}
	record, err := fixture.controller.store.LatestForAgent(
		context.Background(),
		"edge-online",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.controller.store.Transition(
		context.Background(),
		record.ID,
		deployment.StatusApplied,
		"",
		fixture.now,
	); err != nil {
		t.Fatal(err)
	}

	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/deployment-status",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK ||
		!strings.Contains(body, `"pending":false`) ||
		!strings.Contains(body, `"status_label":"Applied"`) ||
		!strings.Contains(body, `"status_class":"online"`) {
		t.Fatalf("terminal deployment status = %d %q", response.Code, body)
	}
}

func TestConfigurationDeploymentRejectsOfflineOrOutdatedAgent(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-offline")
	form := url.Values{
		"config_json": {`{}`},
		"csrf_token":  {fixture.session.CSRFToken},
	}.Encode()

	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-offline/configuration",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), "agent is offline") {
		t.Fatalf(
			"offline deployment response = %d %q",
			response.Code,
			response.Body.String(),
		)
	}

	fixture.controller.sessions["edge-offline"] = true
	fixture.controller.deployable = map[string]bool{"edge-offline": false}
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-offline/configuration",
		form,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), "Update the agent") {
		t.Fatalf(
			"outdated deployment response = %d %q",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestAgentUpdateQueuesExactSelectedVersion(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	form := url.Values{
		"csrf_token":     {fixture.session.CSRFToken},
		"target_version": {"v1.14.0-beta.7"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/agent-update",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("update response = %d %q", response.Code, response.Body.String())
	}
	state, exists := fixture.controller.updates["edge-online"]
	if !exists || state.TargetVersion != "v1.14.0-beta.7" {
		t.Fatalf("queued update = %+v, exists=%v", state, exists)
	}
	if !regexp.MustCompile(`\Aupdate_[A-Za-z0-9_-]+\z`).MatchString(state.RequestID) {
		t.Fatalf("generated update request ID = %q", state.RequestID)
	}
}

func TestAgentUpdateRejectsUnversionedTarget(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	form := url.Values{
		"csrf_token":     {fixture.session.CSRFToken},
		"target_version": {"latest"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/agent-update",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "Enter an exact release") {
		t.Fatalf("invalid update response = %d %q", response.Code, response.Body.String())
	}
	if _, exists := fixture.controller.updates["edge-online"]; exists {
		t.Fatal("invalid update was queued")
	}
}

func TestAgentUpdateRejectsTagWithoutPublishedBinaries(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	form := url.Values{
		"csrf_token":     {fixture.session.CSRFToken},
		"target_version": {"v1.14.0-beta.8"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/agent-update",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "required downloadable binaries") {
		t.Fatalf("unpublished update response = %d %q", response.Code, response.Body.String())
	}
	if _, exists := fixture.controller.updates["edge-online"]; exists {
		t.Fatal("release without binaries was queued")
	}
}

func TestAgentUpdateFailureIsVisibleOnlyToRequestingSession(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	form := url.Values{
		"csrf_token":     {fixture.session.CSRFToken},
		"target_version": {"v1.14.0-beta.7"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/agent-update",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	update := fixture.controller.updates["edge-online"]
	update.Status = "failed"
	update.Diagnostic = "download failed"
	fixture.controller.updates["edge-online"] = update

	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/manage",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), "download failed") {
		t.Fatal("requesting session did not receive its update failure")
	}

	other, err := fixture.access.Login(fixture.username, fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	request = fixture.request(http.MethodGet, "/servers/edge-online/manage", "")
	request.AddCookie(NewSessionCookie(other.Token, other.ExpiresAt))
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if strings.Contains(response.Body.String(), "download failed") {
		t.Fatal("agent update failure leaked into a later browser session")
	}
}

func TestSingBoxUpdateQueuesExactPrerelease(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	form := url.Values{
		"csrf_token":     {fixture.session.CSRFToken},
		"target_version": {"v1.14.0-alpha.27"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/sing-box-update",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf(
			"sing-box update response = %d %q",
			response.Code,
			response.Body.String(),
		)
	}
	state, exists := fixture.controller.singBoxUpdates["edge-online"]
	if !exists || state.TargetVersion != "v1.14.0-alpha.27" {
		t.Fatalf("queued sing-box update = %+v, exists=%v", state, exists)
	}
}

func TestServerPageRendersSingBoxUpdateForm(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.handler.(*Handler).singBoxReleases = testReleaseCatalog{
		releases: []AgentRelease{
			{Tag: "v1.14.0-alpha.27", Prerelease: true},
			{Tag: "v1.14.0", Prerelease: false},
		},
	}
	request := fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/manage",
		"",
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK ||
		!strings.Contains(
			body,
			`action="/servers/edge-online/sing-box-update"`,
		) ||
		!strings.Contains(body, "Running v1.14.0-beta.2") {
		t.Fatalf(
			"sing-box update form response = %d %q",
			response.Code,
			body,
		)
	}
}

func TestServerVersionsEndpointReturnsIndependentCatalogs(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.handler.(*Handler).releases = testReleaseCatalog{releases: []AgentRelease{
		{Tag: "v1.14.0-beta.7", Prerelease: true},
		{Tag: "v1.13.2"},
	}}
	fixture.handler.(*Handler).singBoxReleases = testReleaseCatalog{
		releases: []AgentRelease{
			{Tag: "v1.14.0-alpha.27", Prerelease: true},
			{Tag: "v1.14.0", Prerelease: false},
		},
	}
	for _, test := range []struct {
		catalog string
		want    []string
		reject  string
	}{
		{catalog: "agent", want: []string{"v1.14.0-beta.7", "v1.13.2"}, reject: "v1.14.0-alpha.27"},
		{catalog: "sing-box", want: []string{"v1.14.0-alpha.27", "v1.14.0"}, reject: "v1.13.2"},
	} {
		request := fixture.authenticatedRequest(
			http.MethodGet,
			"/servers/edge-online/versions?catalog="+test.catalog,
			"",
		)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s versions response = %d %q", test.catalog, response.Code, response.Body.String())
		}
		body := response.Body.String()
		for _, want := range test.want {
			if !strings.Contains(body, want) {
				t.Fatalf("%s versions response missing %q: %q", test.catalog, want, body)
			}
		}
		if strings.Contains(body, test.reject) {
			t.Fatalf("%s versions response unexpectedly contains %q: %q", test.catalog, test.reject, body)
		}
	}
}

func TestServerRuleSetOptionsEndpoint(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.handler.(*Handler).geositeRuleSets = testRuleSetOptions{
		options: []string{"category-ads-all", "cn", "openai"},
	}
	fixture.handler.(*Handler).geoipRuleSets = testRuleSetOptions{
		options: []string{"cn", "private"},
	}

	request := fixture.request(
		http.MethodGet,
		"/servers/edge-online/rule-set-options?kind=geosite",
		"",
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated rule-set options status = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	for _, test := range []struct {
		kind   string
		want   []string
		reject string
	}{
		{kind: "geosite", want: []string{"category-ads-all", "openai"}, reject: "private"},
		{kind: "geoip", want: []string{"private"}, reject: "openai"},
	} {
		request := fixture.authenticatedRequest(
			http.MethodGet,
			"/servers/edge-online/rule-set-options?kind="+test.kind,
			"",
		)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s rule-set options response = %d %q", test.kind, response.Code, response.Body.String())
		}
		if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
			t.Fatalf("%s rule-set options Content-Type = %q", test.kind, contentType)
		}
		body := response.Body.String()
		for _, want := range test.want {
			if !strings.Contains(body, want) {
				t.Fatalf("%s rule-set options response missing %q: %q", test.kind, want, body)
			}
		}
		if strings.Contains(body, test.reject) {
			t.Fatalf("%s rule-set options response unexpectedly contains %q: %q", test.kind, test.reject, body)
		}
	}

	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/rule-set-options?kind=bogus",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("bogus rule-set kind status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestServerPageRendersAgentUpdateForm(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.handler.(*Handler).releases = testReleaseCatalog{releases: []AgentRelease{
		{Tag: "v1.14.0-beta.7", Prerelease: true},
		{Tag: "v1.13.2", Prerelease: false},
	}}
	request := fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/manage",
		"",
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK ||
		!strings.Contains(body, "Update agent to latest") ||
		!strings.Contains(body, "data-latest-agent-version") ||
		!strings.Contains(body, `data-version-catalog-url="/servers/edge-online/versions"`) ||
		strings.Contains(body, "fetch(versionURL") {
		t.Fatalf("agent update form response = %d %q", response.Code, body)
	}
}

func TestServerPageShowsCurrentAgentVersion(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.controller.updates = map[string]control.AgentUpdateState{
		"edge-online": {
			RequestID:     "update_previous123",
			TargetVersion: "v1.13.2",
			Status:        "applied",
			UpdatedAt:     time.Now().UTC(),
		},
	}
	fixture.handler.(*Handler).releases = testReleaseCatalog{releases: []AgentRelease{
		{Tag: "v1.14.0-beta.7", Prerelease: true},
		{Tag: "v1.13.2"},
	}}
	request := fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/manage",
		"",
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK ||
		!strings.Contains(body, "data-latest-agent-version") {
		t.Fatalf("agent update form missing latest version hook: %d %q", response.Code, body)
	}
}

func TestMasterUpdateQueuesOnlyLatestRelease(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	stateDirectory := t.TempDir()
	updater, err := agentupdate.NewScheduler(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	handler := fixture.handler.(*Handler)
	handler.masterUpdater = updater
	handler.version = "v1.13.2"
	handler.releases = testReleaseCatalog{releases: []AgentRelease{
		{Tag: "v1.14.0-beta.7", Prerelease: true},
		{Tag: "v1.13.2"},
	}}
	form := url.Values{"csrf_token": {fixture.session.CSRFToken}}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/master-update",
		form,
	)
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("master update response = %d %q", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"status_url":"/settings/update-status?request_id=`) {
		t.Fatalf("master update JSON response = %q", response.Body.String())
	}
	encoded, err := os.ReadFile(filepath.Join(stateDirectory, "update-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var updateRequest agentupdate.Request
	if err := json.Unmarshal(encoded, &updateRequest); err != nil {
		t.Fatal(err)
	}
	if updateRequest.TargetVersion != "v1.14.0-beta.7" {
		t.Fatalf("master update target = %q, want latest", updateRequest.TargetVersion)
	}
	if !strings.HasPrefix(updateRequest.RequestID, "master_") {
		t.Fatalf("master update request ID = %q", updateRequest.RequestID)
	}
	result := agentupdate.Result{
		Version:        1,
		RequestID:      updateRequest.RequestID,
		TargetVersion:  updateRequest.TargetVersion,
		RunningVersion: updateRequest.TargetVersion,
		Status:         "applied",
		ObservedAt:     time.Now().UTC(),
	}
	encodedResult, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(stateDirectory, "update-result.json"),
		append(encodedResult, '\n'),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	handler.version = updateRequest.TargetVersion
	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/settings/update-status?request_id="+url.QueryEscape(updateRequest.RequestID),
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"applied"`) {
		t.Fatalf("master update status = %d %q", response.Code, response.Body.String())
	}
}

func TestMasterUpdateRejectsClientSelectedVersion(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	stateDirectory := t.TempDir()
	updater, err := agentupdate.NewScheduler(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	handler := fixture.handler.(*Handler)
	handler.masterUpdater = updater
	handler.releases = testReleaseCatalog{releases: []AgentRelease{
		{Tag: "v1.14.0-beta.7", Prerelease: true},
	}}
	form := url.Values{
		"csrf_token":     {fixture.session.CSRFToken},
		"target_version": {"v1.13.2"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/master-update",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("client-selected master update response = %d %q", response.Code, response.Body.String())
	}
	if _, err := os.Stat(filepath.Join(stateDirectory, "update-request.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("client-selected master update created a request: %v", err)
	}
}

func TestMasterUpdateFailureIsDiscardedWhenSettingsSessionLoads(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	stateDirectory := t.TempDir()
	updater, err := agentupdate.NewScheduler(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	handler := fixture.handler.(*Handler)
	handler.masterUpdater = updater
	result := agentupdate.Result{
		Version:        1,
		RequestID:      "master_0123456789abcdef",
		TargetVersion:  "v1.14.0-beta.7",
		RunningVersion: "v1.13.2",
		Status:         "failed",
		Diagnostic:     "release asset was missing",
		ObservedAt:     time.Now().UTC(),
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(stateDirectory, "update-result.json")
	if err := os.WriteFile(resultPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/settings", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		strings.Contains(response.Body.String(), "release asset was missing") {
		t.Fatalf("settings retained stale failure: %d %q", response.Code, response.Body.String())
	}
	if _, err := os.Stat(resultPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale result still exists: %v", err)
	}
}

func TestRevokeServerRequiresOriginCSRFAndMatchingIdentity(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	form := url.Values{
		"agent_id":       {"edge-online"},
		"confirm_revoke": {"yes"},
		"csrf_token":     {fixture.session.CSRFToken},
	}.Encode()

	request := fixture.authenticatedRequest(
		http.MethodPost,
		"/servers/edge-online/revoke",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("revoke without Origin status = %d, want 403", response.Code)
	}
	if _, err := fixture.registry.PublicKey(
		context.Background(),
		"edge-online",
	); err != nil {
		t.Fatalf("unauthorized revoke removed identity: %v", err)
	}

	mismatch := url.Values{
		"agent_id":       {"another-server"},
		"confirm_revoke": {"yes"},
		"csrf_token":     {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/revoke",
		mismatch,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("mismatched revoke identity status = %d, want 403", response.Code)
	}

	unconfirmed := url.Values{
		"agent_id":       {"edge-online"},
		"confirm_revoke": {"no"},
		"csrf_token":     {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/revoke",
		unconfirmed,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unconfirmed revoke status = %d, want 403", response.Code)
	}

	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/revoke",
		form,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/servers" {
		t.Fatalf(
			"valid revoke response = %d %q",
			response.Code,
			response.Header().Get("Location"),
		)
	}
	if snapshots := fixture.registry.Snapshot(fixture.now); len(snapshots) != 0 {
		t.Fatalf("revoked identity remains in registry: %+v", snapshots)
	}
	if fixture.controller.sessions["edge-online"] {
		t.Fatal("revoked agent remains online")
	}
}

func TestCreateServerRequiresCSRFAndRevealsCommandOnce(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	form := url.Values{
		"agent_id":            {"edge-paris-1"},
		"csrf_token":          {fixture.session.CSRFToken},
		"default_tls_address": {""},
		"ttl_seconds":         {"900"},
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
		"agent_id":            {"edge-paris-1"},
		"csrf_token":          {strings.Repeat("A", encodedCredentialLength)},
		"default_tls_address": {""},
		"ttl_seconds":         {"900"},
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
		"Shown once.",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("created page does not contain %q", expected)
		}
	}
	if strings.Contains(body, "--agent-id") {
		t.Fatal("token-only enrollment command redundantly contains an agent ID")
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
		"agent_id":            {"edge-session-bound"},
		"csrf_token":          {fixture.session.CSRFToken},
		"default_tls_address": {""},
		"ttl_seconds":         {"900"},
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

func TestCreateServerStoresDefaultTLSAddress(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	poolRegistry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.controller.poolRegistry = poolRegistry
	form := url.Values{
		"agent_id":            {"edge-tls-default"},
		"csrf_token":          {fixture.session.CSRFToken},
		"default_tls_address": {"Proxy.Example.COM."},
		"ttl_seconds":         {"900"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("create status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := poolRegistry.DefaultTLSAddress("edge-tls-default"); got != "proxy.example.com" {
		t.Fatalf("DefaultTLSAddress() = %q, want proxy.example.com", got)
	}

	form = url.Values{
		"agent_id":            {"edge-invalid-tls"},
		"csrf_token":          {fixture.session.CSRFToken},
		"default_tls_address": {"https://proxy.example.com"},
		"ttl_seconds":         {"900"},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "DNS hostname only") {
		t.Fatalf("invalid address response = %d, body = %s", response.Code, response.Body.String())
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
			"agent_id":            {fmt.Sprintf("edge-%d", index)},
			"csrf_token":          {fixture.session.CSRFToken},
			"default_tls_address": {""},
			"ttl_seconds":         {"900"},
		}.Encode()
		request := fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusSeeOther {
			t.Fatalf("enrollment %d status = %d", index, response.Code)
		}
	}

	form := url.Values{
		"agent_id":            {"edge-limited"},
		"csrf_token":          {fixture.session.CSRFToken},
		"default_tls_address": {""},
		"ttl_seconds":         {"900"},
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
		"agent_id":            {"edge-storage-failure"},
		"csrf_token":          {fixture.session.CSRFToken},
		"default_tls_address": {""},
		"ttl_seconds":         {"900"},
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
	for _, path := range []string{
		"/assets/app.js",
		"/assets/config-editor.js",
		"/assets/dropdown.js",
	} {
		request := fixture.request(http.MethodGet, path, "")
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK ||
			!strings.HasPrefix(
				response.Header().Get("Content-Type"),
				"text/javascript",
			) ||
			response.Body.Len() == 0 {
			t.Fatalf(
				"%s response = %d %q (%d bytes)",
				path,
				response.Code,
				response.Header().Get("Content-Type"),
				response.Body.Len(),
			)
		}
		assertSecurityHeaders(t, response.Header())
		if path == "/assets/config-editor.js" &&
			!strings.Contains(response.Body.String(), `option.addEventListener("pointerdown"`) {
			t.Fatal("config editor rule-set options do not commit before popover dismissal")
		}
	}

	request := fixture.request(http.MethodGet, "/not-found", "")
	response := httptest.NewRecorder()
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
	sessions := testSessions{"edge-online": true}
	controller := &testAgentController{
		registry: registry,
		sessions: sessions,
		store:    deployment.NewMemoryStore(),
	}
	handler, err := New(Options{
		Registry:   registry,
		Sessions:   sessions,
		Controller: controller,
		Access:     access,
		Releases: testReleaseCatalog{releases: []AgentRelease{
			{Tag: "v1.14.0-beta.7", Prerelease: true},
		}},
		PublicURL: testPublicURL,
		Version:   "test",
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return webFixture{
		handler:    handler,
		registry:   registry,
		controller: controller,
		access:     access,
		username:   username,
		password:   password,
		session:    session,
		now:        now,
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
