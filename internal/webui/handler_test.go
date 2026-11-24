package webui

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/agentupdate"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
	"github.com/masterauguste/theatropolis/internal/singbox"
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
	if agentID == "edge-managed-version" {
		info.SingBoxVersion = "v1.14.0-rc.2.theatropolis.2"
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
	acmeRelay           map[string]bool
	updatable           map[string]bool
	updates             map[string]control.AgentUpdateState
	singBoxUpdates      map[string]control.SingBoxUpdateState
	queueErr            error
	revokeErr           error
	revokeForce         bool
	poolRegistry        *pool.Registry
	propagateCalls      int
	deploymentListCalls int
	probeErr            error
	probeRequests       []probeRequest
	trafficRequests     []string
	autoApply           bool
	migrationAddress    string
	migrationQueued     int
	migrationSkipped    int
	linkLatencies       map[string]control.LinkLatencyState
	peerLatencies       map[control.PeerLatencyKey]control.LinkLatencyState
	linkProbeResult     control.LinkLatencyState
	linkProbeErr        error
	linkProbeAgent      string
	linkProbeAddress    string
	linkProbePort       uint16
	linkProbeType       string
}

func (c *testAgentController) LinkLatency(agentID, outboundTag string) (control.LinkLatencyState, bool) {
	value, exists := c.linkLatencies[agentID+"/"+outboundTag]
	return value, exists
}

func (c *testAgentController) PeerLatency(sourceAgentID, targetAgentID string) (control.LinkLatencyState, bool) {
	value, exists := c.peerLatencies[control.PeerLatencyKey{SourceAgentID: sourceAgentID, TargetAgentID: targetAgentID}]
	return value, exists
}

func (c *testAgentController) RecordPeerLatency(sourceAgentID, targetAgentID string, state control.LinkLatencyState) {
	if c.peerLatencies == nil {
		c.peerLatencies = make(map[control.PeerLatencyKey]control.LinkLatencyState)
	}
	c.peerLatencies[control.PeerLatencyKey{SourceAgentID: sourceAgentID, TargetAgentID: targetAgentID}] = state
}

func (c *testAgentController) RequestLinkLatencyProbe(_ context.Context, agentID string, target control.LinkLatencyProbeTarget) (control.LinkLatencyState, error) {
	c.linkProbeAgent = agentID
	c.linkProbeAddress = target.Address
	c.linkProbePort = target.Port
	c.linkProbeType = target.ProbeType
	return c.linkProbeResult, c.linkProbeErr
}

func (c *testAgentController) QueueOnlineMasterMigration(_ context.Context, _ string, address string) (int, int, error) {
	c.migrationAddress = address
	return c.migrationQueued, c.migrationSkipped, c.queueErr
}

type testMasterMigrationService struct {
	exportPassphrase  string
	restorePassphrase string
	restoredArchive   []byte
	exportErr         error
	restoreErr        error
}

func (s *testMasterMigrationService) Export(_ context.Context, passphrase string) (string, []byte, error) {
	s.exportPassphrase = passphrase
	return "migration.zip", []byte("migration-archive"), s.exportErr
}

func (s *testMasterMigrationService) StageRestore(_ context.Context, archive []byte, passphrase string) (string, int, int, int, error) {
	s.restorePassphrase = passphrase
	s.restoredArchive = append([]byte(nil), archive...)
	return "migration_test", 3, 4, 2, s.restoreErr
}

type testProxyUserSync struct {
	deployer *proxynode.Deployer
}

func (s testProxyUserSync) TriggerDeployment() {
	_, _ = s.deployer.StartUserSync()
}

func waitForProxyDeployment(t *testing.T, deployer *proxynode.Deployer) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		job, exists := deployer.Current()
		if exists && job.Status == proxynode.FleetDeploymentApplied {
			return
		}
		if exists && job.Status == proxynode.FleetDeploymentFailed {
			t.Fatalf("Proxy Node deployment failed: %s", job.Error)
		}
		if time.Now().After(deadline) {
			t.Fatal("Proxy Node deployment did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForFailedProxyDeployment(t *testing.T, deployer *proxynode.Deployer) proxynode.FleetDeployment {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		job, exists := deployer.Current()
		if exists && job.Status == proxynode.FleetDeploymentFailed {
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("Proxy Node deployment did not fail: %#v", job)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type fixedProxyResolver struct{}

func (fixedProxyResolver) AgentAddressForFamily(string, pool.Family) (string, bool) {
	return "203.0.113.42", true
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

func (c *testAgentController) HasAgentIdentity(agentID string) bool {
	if c.registry == nil {
		return false
	}
	return c.registry.HasRecord(agentID)
}

func (c *testAgentController) CanDeployProxyNodeConfiguration(agentID string) bool {
	return c.CanDeployConfiguration(agentID)
}

func (c *testAgentController) CanRelayACMEHTTP01(agentID string) bool {
	return c.acmeRelay[agentID]
}

func (c *testAgentController) CanSyncManagedUserAuthority(agentID string) bool {
	return c.CanDeployConfiguration(agentID)
}

func (c *testAgentController) RequestManagedUserTraffic(_ context.Context, agentID string) error {
	c.trafficRequests = append(c.trafficRequests, agentID)
	return nil
}

func (c *testAgentController) QueueManagedUserAuthority(
	context.Context,
	string,
	uint64,
	[]singbox.ManagedUserAuthorityVariant,
) error {
	return c.queueErr
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
	record, err = c.store.Transition(
		ctx,
		record.ID,
		deployment.StatusDeploying,
		"",
		time.Now().UTC(),
	)
	if err != nil || !c.autoApply {
		return record, err
	}
	return c.store.Transition(ctx, record.ID, deployment.StatusApplied, "", time.Now().UTC())
}

func (c *testAgentController) RevokeAgent(
	ctx context.Context,
	agentID string,
	force bool,
) error {
	if c.revokeErr != nil {
		return c.revokeErr
	}
	c.revokeForce = force
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
	proxyNodes *proxynode.Store
	access     *AccessManager
	endUsers   *EndUserAccessManager
	username   string
	password   string
	session    Session
	now        time.Time
	migration  *testMasterMigrationService
	restarts   chan struct{}
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

	rollingNow := time.Now().UTC().Add(4 * 24 * time.Hour).Truncate(time.Second)
	fixture.access.now = func() time.Time { return rollingNow }
	request = fixture.request(http.MethodGet, "/servers", "")
	request.AddCookie(NewSessionCookie(fixture.session.Token, fixture.session.ExpiresAt))
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated GET /servers after four idle days = %d", response.Code)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != SessionCookieName ||
		!cookies[0].Expires.Equal(rollingNow.Add(DefaultSessionIdleTimeout)) {
		t.Fatalf("rolling session cookie was not refreshed: %#v", cookies)
	}

	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/healthz", nil)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != `{"status":"ok"}`+"\n" {
		t.Fatalf("loopback health response = %d %q", response.Code, response.Body.String())
	}
	assertSecurityHeaders(t, response.Header())
}

func TestWebUINegotiatesPersistsAndHonorsLanguagePreference(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	request := fixture.requestWithoutLocale(http.MethodGet, "/login", "")
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("English login status = %d, body = %s", response.Code, response.Body.String())
	}
	env := decodeSPA(t, response)
	if env.Locale != localeEnglish || env.View != "login" || env.Data.Title != "Sign in" {
		t.Errorf("English login envelope = %+v", env)
	}
	if got := response.Header().Get("Content-Language"); got != localeEnglish {
		t.Errorf("English Content-Language = %q", got)
	}
	assertLanguagePreferenceCookie(t, response, localeEnglish, fixture.now)

	request = fixture.mutationRequestWithoutLocale(
		http.MethodPost,
		"/login",
		url.Values{"username": {fixture.username}, "password": {"incorrect"}}.Encode(),
	)
	request.Header.Set("Accept-Language", "en-US;q=0.4, zh-CN;q=0.9")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "用户名或密码不正确。") {
		t.Fatalf("Chinese login validation = %d %q", response.Code, response.Body.String())
	}
	assertLanguagePreferenceCookie(t, response, localeSimplifiedChinese, fixture.now)

	request = fixture.authenticatedRequest(http.MethodGet, "/servers", "")
	request.Header.Set("Accept-Language", "zh-CN")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if env.Locale != localeEnglish || env.Data.Title != "Servers" {
		t.Fatalf("English preference did not override browser language: %+v", env)
	}
	for _, header := range []string{"fr-FR, de;q=0.8", "zh-CN;q=0, en;q=0.7", "zh-CN;q=bogus"} {
		request = fixture.requestWithoutLocale(http.MethodGet, "/login", "")
		request.Header.Set("Accept-Language", header)
		response = httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if got := response.Header().Get("Content-Language"); got != localeEnglish {
			t.Errorf("Accept-Language %q selected %q, want English", header, got)
		}
		assertLanguagePreferenceCookie(t, response, localeEnglish, fixture.now)
	}

	// Verify static SPA assets do not set language cookies.
	entries, err := webFiles.ReadDir("dist/assets")
	if err != nil || len(entries) == 0 {
		t.Fatalf("read dist/assets: %v (len=%d)", err, len(entries))
	}
	request = fixture.requestWithoutLocale(http.MethodGet, "/assets/"+entries[0].Name(), "")
	request.Header.Set("Accept-Language", "zh-CN")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("static asset response = %d cookie %q", response.Code, response.Header().Get("Set-Cookie"))
	}
}

func assertLanguagePreferenceCookie(t *testing.T, response *httptest.ResponseRecorder, locale string, now time.Time) {
	t.Helper()
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != languageCookieName || cookies[0].Value != locale ||
		cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" ||
		cookies[0].MaxAge != int(languageCookieLifetime.Seconds()) || !cookies[0].Expires.Equal(now.Add(languageCookieLifetime).Truncate(time.Second)) {
		t.Fatalf("language preference cookie = %+v", cookies)
	}
}

func TestLanguageSwitchPersistsOnlySupportedLocaleAndRedirectsSafely(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	request := fixture.authenticatedRequest(http.MethodGet, "/language/zh-CN", "")
	request.Header.Set("Referer", testPublicURL+"/users?inspect=profile")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/users?inspect=profile" {
		t.Fatalf("language switch response = %d %q", response.Code, response.Header().Get("Location"))
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != languageCookieName || cookies[0].Value != localeSimplifiedChinese ||
		cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" {
		t.Fatalf("language preference cookie = %#v", cookies)
	}

	request = fixture.requestWithoutLocale(http.MethodGet, "/language/zh-CN", "")
	request.Header.Set("Accept-Language", "en-US")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("first-visit language switch response = %d %q", response.Code, response.Header().Get("Location"))
	}
	assertLanguagePreferenceCookie(t, response, localeSimplifiedChinese, fixture.now)

	request = fixture.authenticatedRequest(http.MethodGet, "/language/en", "")
	request.Header.Set("Referer", "https://attacker.example/steal")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/servers" {
		t.Fatalf("cross-origin language return = %d %q", response.Code, response.Header().Get("Location"))
	}

	request = fixture.request(http.MethodGet, "/language/fr", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("unsupported language response = %d cookie %q", response.Code, response.Header().Get("Set-Cookie"))
	}
}

func TestSimplifiedChineseCoversPrimaryWebUIRoutes(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	for _, tc := range []struct {
		path string
		view string
	}{
		{path: "/servers", view: "servers"},
		{path: "/servers/content", view: "servers-content"},
		{path: "/servers/new", view: "new-server"},
		{path: "/proxy-nodes", view: "proxy-nodes"},
		{path: "/users", view: "users"},
		{path: "/subscriptions", view: "subscription-policy"},
		{path: "/settings", view: "settings"},
	} {
		request := fixture.authenticatedRequestWithLocale(http.MethodGet, tc.path, "", localeSimplifiedChinese)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("GET %s in Chinese = %d, body = %s", tc.path, response.Code, response.Body.String())
			continue
		}
		env := decodeSPA(t, response)
		if env.Locale != localeSimplifiedChinese || env.View != tc.view {
			t.Errorf("GET %s in Chinese = locale=%q view=%q, want zh-CN/%s", tc.path, env.Locale, env.View, tc.view)
		}
	}
}

func TestLocalizedCountUsesNaturalClassifiersAndPluralization(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		locale string
		count  int
		kind   string
		want   string
	}{
		{locale: localeSimplifiedChinese, count: 4, kind: "hop", want: "4 个节点"},
		{locale: localeSimplifiedChinese, count: 3, kind: "link", want: "3 条链路"},
		{locale: localeSimplifiedChinese, count: 3, kind: "user", want: "3 位用户"},
		{locale: localeEnglish, count: 1, kind: "hop", want: "1 Hop"},
		{locale: localeEnglish, count: 2, kind: "hop", want: "2 Hops"},
	} {
		if got := localizedCount(test.locale, test.count, test.kind); got != test.want {
			t.Errorf("localizedCount(%q, %d, %q) = %q, want %q", test.locale, test.count, test.kind, got, test.want)
		}
	}
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
	env := decodeSPA(t, response)
	if env.View != "login" || env.Data.LegacyLogin {
		t.Fatalf("unexpected login envelope: %+v", env)
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
	env = decodeSPA(t, response)
	if !strings.Contains(env.Error, "The username or password was not accepted.") {
		t.Fatal("invalid login did not return the generic credential error")
	}
	if env.Data.Username != untrustedUsername {
		t.Fatalf("invalid login did not preserve submitted username: %q", env.Data.Username)
	}
	if strings.Contains(response.Body.String(), submittedPassword) {
		t.Fatal("invalid login reflected the submitted password")
	}
}

func TestUnifiedLoginRoutesPersistedRolesWithoutAuthenticationFallback(t *testing.T) {
	fixture := newWebFixture(t)
	fixture.endUsers.mu.Lock()
	fixture.endUsers.unified = true
	fixture.endUsers.admin = administratorIdentity{
		Mode: UsernamePassword, LoginUsername: fixture.access.username, AuthRevision: 1,
		PasswordSalt: fixture.access.passwordSalt, PasswordHash: fixture.access.passwordHash,
		UpdatedAt: fixture.now,
	}
	fixture.endUsers.mu.Unlock()

	request := fixture.request(http.MethodGet, "/portal/login", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("portal login redirect = %d %q", response.Code, response.Header().Get("Location"))
	}

	form := url.Values{"username": {fixture.username}, "password": {fixture.password}}.Encode()
	request = fixture.mutationRequest(http.MethodPost, "/login", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/servers" {
		t.Fatalf("administrator unified login = %d %q", response.Code, response.Header().Get("Location"))
	}
	if cookies := response.Result().Cookies(); len(cookies) != 1 || cookies[0].Name != SessionCookieName {
		t.Fatalf("administrator unified cookies = %+v", cookies)
	}

	token, _, err := fixture.endUsers.IssueInvitation("usr_portal", defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.endUsers.ClaimInvitation(token, "portal.user", testEndUserPassword); err != nil {
		t.Fatal(err)
	}
	form = url.Values{"username": {"portal.user"}, "password": {testEndUserPassword}}.Encode()
	request = fixture.mutationRequest(http.MethodPost, "/login", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/portal" {
		t.Fatalf("user unified login = %d %q", response.Code, response.Header().Get("Location"))
	}
	if cookies := response.Result().Cookies(); len(cookies) != 1 || cookies[0].Name != EndUserSessionCookieName {
		t.Fatalf("user unified cookies = %+v", cookies)
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
	env := decodeSPA(t, response)
	if env.View != "login" || !env.Data.LegacyLogin {
		t.Fatalf("legacy login envelope = %+v", env)
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
			expectedBody := "(" + test.reason + ")"
			if !strings.Contains(response.Body.String(), expectedBody) {
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
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.View != "servers" || len(env.Data.Agents) != 0 {
		t.Fatalf("GET /servers did not return the lightweight shell: %d %+v", response.Code, env)
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/servers/content", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /servers/content status = %d, body = %s", response.Code, response.Body.String())
	}
	env = decodeSPA(t, response)
	if env.Data.Stats.Total != 4 || len(env.Data.Agents) != 4 {
		t.Fatalf("servers content stats = %+v len=%d", env.Data.Stats, len(env.Data.Agents))
	}
	var sawOnline, sawOffline bool
	for _, agent := range env.Data.Agents {
		if agent.ConnectionClass == "online" {
			sawOnline = true
		} else {
			sawOffline = true
		}
	}
	if !sawOnline || !sawOffline {
		t.Fatalf("servers agents missing online/offline mix: %+v", env.Data.Agents)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"edge-pending",
		"edge-expired",
		"edge-online",
		"edge-offline",
		"v0.0.9",
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

func TestServerDetailHidesManagedSingBoxPatchSuffix(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-managed-version")
	fixture.controller.sessions["edge-managed-version"] = true

	request := fixture.authenticatedRequest(http.MethodGet, "/servers/edge-managed-version/manage", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.Agent == nil || env.Data.Agent.SingBoxVersion != "v1.14.0-rc.2" {
		t.Fatalf("server detail omitted simplified sing-box version: %d %+v", response.Code, env.Data.Agent)
	}
	if strings.Contains(response.Body.String(), "v1.14.0-rc.2.theatropolis.2") {
		t.Fatal("servers content exposed the managed sing-box patch suffix")
	}

	request = fixture.authenticatedRequestWithLocale(
		http.MethodGet,
		"/servers/edge-managed-version/manage",
		"",
		localeSimplifiedChinese,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Locale != localeSimplifiedChinese || env.Data.Agent.SingBoxVersion != "v1.14.0-rc.2" {
		t.Errorf("Chinese server detail = %d locale=%q agent=%+v", response.Code, env.Locale, env.Data.Agent)
	}
}

func TestDisplaySingBoxVersionRemovesOnlyManagedBuildSuffix(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "v1.14.0-rc.2.theatropolis.2", want: "v1.14.0-rc.2"},
		{input: "1.14.0-theatropolis.12", want: "1.14.0"},
		{input: "  v1.14.0-beta.2  ", want: "v1.14.0-beta.2"},
		{input: "development", want: "development"},
	} {
		if got := displaySingBoxVersion(test.input); got != test.want {
			t.Errorf("displaySingBoxVersion(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestAuthenticatedHeaderLinksServersAndSettings(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	request := fixture.authenticatedRequest(http.MethodGet, "/servers", "")
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /servers status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `<div id="root"></div>`) || strings.Contains(body, testPublicURL) {
		t.Fatalf("unexpected SPA HTML shell: %s", body)
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
	env := decodeSPA(t, response)
	if env.View != "settings" || env.Data.ActiveNav != "settings" || env.Data.MasterVersion == "" || env.Data.AdministratorProxyAccessEnabled {
		t.Fatalf("unexpected settings envelope: %+v", env)
	}
}

func TestSettingsToggleControlsAdministratorProxyAccess(t *testing.T) {
	fixture := newWebFixture(t)
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.authenticatedRequest(http.MethodGet, "/subscriptions", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.AdministratorProxyAccessEnabled {
		t.Fatalf("disabled administrator subscription state = %d %+v", response.Code, env.Data.AdministratorProxyAccessEnabled)
	}
	request = fixture.authenticatedRequest(http.MethodGet, "/subscriptions/admin", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled administrator subscription status = %d", response.Code)
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/settings/administrator-proxy-access", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "enabled": {"true"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Notice != "Administrator proxy access enabled." || !env.Data.AdministratorProxyAccessEnabled {
		t.Fatalf("enable administrator access = %d %+v", response.Code, env)
	}
	state := fixture.proxyNodes.Snapshot()
	current, _ := fixture.proxyNodes.ProxyNode(node.ID)
	if !state.AdministratorProxyAccessEnabled || len(state.Users) != 1 ||
		current.Memberships[0].UserID != proxynode.SystemAdministratorUserID {
		t.Fatalf("enabled administrator state = %#v node=%#v", state, current)
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/settings/administrator-proxy-access", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "enabled": {"false"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Notice != "Administrator proxy access disabled." || env.Data.AdministratorProxyAccessEnabled {
		t.Fatalf("disable administrator access = %d %+v", response.Code, env)
	}
	state = fixture.proxyNodes.Snapshot()
	current, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if state.AdministratorProxyAccessEnabled || len(state.Users) != 0 || len(current.Memberships) != 0 {
		t.Fatalf("disabled administrator state = %#v node=%#v", state, current)
	}
}

func TestMasterMigrationExportRequiresMatchingPassphraseAndDownloadsArchive(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	form := url.Values{
		"csrf_token":         {fixture.session.CSRFToken},
		"passphrase":         {"correct horse battery staple"},
		"passphrase_confirm": {"correct horse battery staple"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/settings/migration/export", form)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("export status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Body.String() != "migration-archive" || fixture.migration.exportPassphrase != "correct horse battery staple" {
		t.Fatalf("export = %q, passphrase = %q", response.Body.String(), fixture.migration.exportPassphrase)
	}
	if disposition := response.Header().Get("Content-Disposition"); !strings.Contains(disposition, "migration.zip") {
		t.Fatalf("Content-Disposition = %q", disposition)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
}

func TestMasterMigrationRestoreStagesArchiveAndRequestsRestart(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, value := range map[string]string{
		"csrf_token":   fixture.session.CSRFToken,
		"passphrase":   "correct horse battery staple",
		"confirmation": "RESTORE",
	} {
		if err := writer.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile("archive", "migration.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("encrypted-migration")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/settings/migration/restore", "")
	request.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	request.ContentLength = int64(body.Len())
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("restore status = %d, body = %s", response.Code, response.Body.String())
	}
	if string(fixture.migration.restoredArchive) != "encrypted-migration" || fixture.migration.restorePassphrase != "correct horse battery staple" {
		t.Fatalf("restore archive = %q, passphrase = %q", fixture.migration.restoredArchive, fixture.migration.restorePassphrase)
	}
	select {
	case <-fixture.restarts:
	case <-time.After(2 * time.Second):
		t.Fatal("restore did not request a Master restart")
	}
}

func TestMasterMigrationCutoverTargetsOnlyTheEnteredAddress(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	fixture.controller.migrationQueued = 2
	fixture.controller.migrationSkipped = 1
	form := url.Values{
		"csrf_token":     {fixture.session.CSRFToken},
		"master_address": {"new-master.example:443"},
		"confirmation":   {"MIGRATE"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/settings/migration/cutover", form)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("cutover status = %d, body = %s", response.Code, response.Body.String())
	}
	if fixture.controller.migrationAddress != "new-master.example:443" {
		t.Fatalf("migration address = %q", fixture.controller.migrationAddress)
	}
	if !strings.Contains(response.Body.String(), "2 online servers") || !strings.Contains(response.Body.String(), "1 offline") {
		t.Fatalf("cutover notice missing counts: %s", response.Body.String())
	}
}

func TestSettingsPageShowsAccountingFailureHistory(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	user, err := fixture.proxyNodes.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootName: "Entrance", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(
		fixture.proxyNodes.Snapshot().Revision, []string{"edge-online"},
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.RecordAccountingFailure(
		"edge-online",
		proxynode.AccountingFailureCollection,
		fixture.now.Add(-time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.RecordAccountingFailure(
		"edge-online",
		proxynode.AccountingFailurePersistence,
		fixture.now,
	); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/settings", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /settings status = %d, body = %s", response.Code, response.Body.String())
	}
	env := decodeSPA(t, response)
	if env.Data.AccountingFailureTotal != 2 || len(env.Data.AccountingFailures) != 2 {
		t.Fatalf("settings accounting failures = total:%d len:%d", env.Data.AccountingFailureTotal, len(env.Data.AccountingFailures))
	}
	if env.Data.AccountingFailures[0].AgentID != "edge-online" ||
		!strings.Contains(env.Data.AccountingFailures[0].Reason, "Master could not persist usage") ||
		!strings.Contains(env.Data.AccountingFailures[1].Reason, "Entrance sample collection failed") {
		t.Fatalf("settings accounting failures not newest-first: %+v", env.Data.AccountingFailures)
	}
}

func TestSettingsCanClearAccountingFailureHistory(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	user, _ := fixture.proxyNodes.CreateUser("Alice")
	node, _ := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if _, err := fixture.proxyNodes.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online"}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.RecordAccountingFailure("edge-online", proxynode.AccountingFailureCollection, fixture.now); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf_token": {fixture.session.CSRFToken}, "confirmation": {"clear"}}
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/settings/accounting-errors/clear", form.Encode())
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Accounting error log cleared.") {
		t.Fatalf("clear accounting history = %d %q", response.Code, response.Body.String())
	}
	if failures := fixture.proxyNodes.Snapshot().AccountingFailures; len(failures) != 0 {
		t.Fatalf("accounting failures remain: %#v", failures)
	}
}

func TestAdminAndPortalShowDailyUserTraffic(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	user, _ := fixture.proxyNodes.CreateUser("Alice")
	node, _ := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if _, err := fixture.proxyNodes.AddMembershipWithPlan(node.ID, user.ID, proxynode.MembershipPlan{
		MonthlyQuotaBytes: 10 << 30,
		SubscriptionValue: 1,
		SubscriptionUnit:  proxynode.SubscriptionMonths,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online"}); err != nil {
		t.Fatal(err)
	}
	listenerID := proxynode.ListenerPresetID("edge-online", node.Entrance.Endpoint)
	if _, err := fixture.proxyNodes.ApplyTrafficDeltaReport("edge-online", fixture.now, []proxynode.UserTraffic{{
		InboundPath: "/tp-in-" + strings.TrimPrefix(listenerID, "listener-"),
		Username:    "Cinema-Alice", UplinkBytes: 3 << 20, DownlinkBytes: 2 << 20,
	}}); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/users/"+url.PathEscape(user.ID), "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.EndUser == nil || len(env.Data.EndUser.DailyUsage) != 1 ||
		env.Data.EndUser.DailyUsage[0].TotalLabel != "5.00 MiB" || !strings.Contains(response.Body.String(), "Cinema") {
		t.Fatalf("admin daily traffic = %d %+v", response.Code, env.Data.EndUser)
	}

	invitation, _, err := fixture.endUsers.IssueInvitation(user.ID, defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	portalSession, err := fixture.endUsers.ClaimInvitation(invitation, "alice.daily", testEndUserPassword)
	if err != nil {
		t.Fatal(err)
	}
	request = fixture.request(http.MethodGet, "/portal", "")
	request.AddCookie(NewEndUserSessionCookie(portalSession.Token, portalSession.ExpiresAt))
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.EndUserPortal == nil || len(env.Data.EndUserPortal.DailyUsage) != 1 ||
		env.Data.EndUserPortal.DailyUsage[0].TotalLabel != "5.00 MiB" || !strings.Contains(response.Body.String(), "Cinema") {
		t.Fatalf("portal daily traffic = %d %+v", response.Code, env.Data.EndUserPortal)
	}

	request = fixture.requestWithLocale(http.MethodGet, "/portal", "", localeSimplifiedChinese)
	request.AddCookie(NewEndUserSessionCookie(portalSession.Token, portalSession.ExpiresAt))
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.EndUserPortal == nil || len(env.Data.EndUserPortal.Nodes) != 1 ||
		!regexp.MustCompile(`^\d{4}年\d{1,2}月\d{1,2}日 \d{2}:\d{2}$`).MatchString(env.Data.EndUserPortal.Nodes[0].ResetLabel) ||
		strings.Contains(response.Body.String(), "（UTC+8）") ||
		strings.Contains(response.Body.String(), "到期时间：") {
		t.Fatalf("localized portal dates = %d %+v", response.Code, env.Data.EndUserPortal)
	}
}

func TestEndUserPortalDoesNotPresentDesiredOnlyNodeAsAvailable(t *testing.T) {
	fixture := newWebFixture(t)
	user, err := fixture.proxyNodes.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Draft Cinema", RootAgent: "edge-draft",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "draft.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	invitation, _, err := fixture.endUsers.IssueInvitation(user.ID, defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	portalSession, err := fixture.endUsers.ClaimInvitation(invitation, "alice.pending", testEndUserPassword)
	if err != nil {
		t.Fatal(err)
	}

	render := func(locale string) spaEnvelope {
		request := fixture.requestWithLocale(http.MethodGet, "/portal", "", locale)
		request.AddCookie(NewEndUserSessionCookie(portalSession.Token, portalSession.ExpiresAt))
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET portal with desired-only Node = %d %q", response.Code, response.Body.String())
		}
		return decodeSPA(t, response)
	}
	en := render(localeEnglish)
	if en.Data.EndUserPortal == nil || len(en.Data.EndUserPortal.Nodes) != 1 {
		t.Fatalf("unexpected pending portal payload: %+v", en.Data.EndUserPortal)
	}
	pendingNode := en.Data.EndUserPortal.Nodes[0]
	if pendingNode.Name != "Draft Cinema" || !pendingNode.PendingApply || pendingNode.StatusClass != "pending" || pendingNode.StatusLabel != "Pending Apply" {
		t.Fatalf("desired-only portal Node = %+v", pendingNode)
	}

	zh := render(localeSimplifiedChinese)
	if zh.Data.EndUserPortal.Nodes[0].StatusLabel != "等待应用" || !zh.Data.EndUserPortal.Nodes[0].PendingApply {
		t.Fatalf("Chinese pending portal Node = %+v", zh.Data.EndUserPortal.Nodes[0])
	}
}

func TestServerManagementPageShowsProxyNodeRoleAndRevocationControls(t *testing.T) {
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
	env := decodeSPA(t, response)
	if env.View != "server" || env.Data.Agent == nil || env.Data.Agent.ID != "edge-online" {
		t.Fatalf("server management view = %q agent = %+v", env.View, env.Data.Agent)
	}
	if env.Data.Agent.URL != "/servers/edge-online/manage" {
		t.Fatalf("server manage URL = %q", env.Data.Agent.URL)
	}
	if env.Data.MasterUpdateEnabled {
		t.Fatal("server management page still exposes global master update controls")
	}
	if strings.Contains(response.Body.String(), "/servers/edge-online/configuration") {
		t.Fatal("server management page still contains retired configuration endpoint")
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

func TestReplaceServerCreatesTokenWithoutRevokingCurrentKey(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-replacement")
	currentKey, err := fixture.registry.PublicKey(context.Background(), "edge-replacement")
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"agent_id":    {"edge-replacement"},
		"csrf_token":  {fixture.session.CSRFToken},
		"ttl_seconds": {"900"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-replacement/replace",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("replacement status = %d, body = %s", response.Code, response.Body.String())
	}
	resultLocation := response.Header().Get("Location")
	request = fixture.authenticatedRequest(http.MethodGet, resultLocation, "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("replacement result status = %d", response.Code)
	}
	env := decodeSPA(t, response)
	if env.Data.Created == nil {
		t.Fatal("replacement result did not contain Created payload")
	}
	match := regexp.MustCompile(`--token '([A-Za-z0-9_-]{43})'`).FindStringSubmatch(env.Data.Created.InstallCommand)
	if len(match) != 2 {
		t.Fatalf("replacement result did not contain a token: %q", env.Data.Created.InstallCommand)
	}
	stillCurrent, err := fixture.registry.PublicKey(context.Background(), "edge-replacement")
	if err != nil || !bytes.Equal(stillCurrent, currentKey) {
		t.Fatalf("current key changed before replacement redemption: %x, %v", stillCurrent, err)
	}
	token, err := base64.RawURLEncoding.DecodeString(match[1])
	if err != nil {
		t.Fatal(err)
	}
	replacementKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.registry.EnrollByToken(
		context.Background(),
		token,
		replacementKey,
		fixture.now,
	); err != nil {
		t.Fatal(err)
	}
}

func TestPerServerConfigurationEndpointIsRetired(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/configuration",
		url.Values{
			"config_json": {`{"inbounds":[]}`},
			"csrf_token":  {fixture.session.CSRFToken},
		}.Encode(),
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("legacy configuration POST status = %d, want 405", response.Code)
	}
	if _, err := fixture.controller.store.LatestForAgent(context.Background(), "edge-online"); !errors.Is(err, deployment.ErrNotFound) {
		t.Fatalf("retired endpoint created a deployment: %v", err)
	}
}

func TestProxyNodePagesUseLinkOwnedRulesAndMembershipCredentials(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-exit")
	enrollAgent(t, fixture.registry, "edge-alt")
	fixture.controller.sessions["edge-exit"] = true
	poolRegistry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.controller.poolRegistry = poolRegistry
	if _, err := poolRegistry.SetReported("edge-online", []string{"203.0.113.42"}, nil); err != nil {
		t.Fatal(err)
	}

	user, err := fixture.proxyNodes.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootName: "Entrance", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto", TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"}},
		Final:    proxynode.Target{Type: proxynode.TargetReject},
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := fixture.proxyNodes.AddMembership(node.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	link, child, err := fixture.proxyNodes.AddLink(node.ID, proxynode.AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-exit",
		Endpoint: proxynode.Endpoint{Protocol: proxynode.ProtocolShadowsocks, Listen: "::", ListenPort: 8443, Family: "auto", Method: "2022-blake3-aes-128-gcm"},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstRule, err := fixture.proxyNodes.AddRule(node.ID, proxynode.AddRuleInput{LinkID: link.ID, Match: proxynode.MatchDomainSuffix, Values: []string{"example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	secondRule, err := fixture.proxyNodes.AddRule(node.ID, proxynode.AddRuleInput{LinkID: link.ID, Match: proxynode.MatchProtocol, Values: []string{"bittorrent"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online", "edge-exit"}); err != nil {
		t.Fatal(err)
	}
	fixture.controller.linkLatencies = make(map[string]control.LinkLatencyState)
	updatedNode, _ := fixture.proxyNodes.ProxyNode(node.ID)
	rootOptions := fixture.handler.(*Handler).proxyDestinationAgentOptions(updatedNode, node.Entrance.HopID, "")
	if slices.ContainsFunc(rootOptions, func(option agentOptionView) bool { return option.ID == "edge-online" }) {
		t.Fatalf("entrance Agent remains selectable as its own child: %#v", rootOptions)
	}
	childOptions := fixture.handler.(*Handler).proxyDestinationAgentOptions(updatedNode, child.ID, "")
	for _, excluded := range []string{"edge-online", "edge-exit"} {
		if slices.ContainsFunc(childOptions, func(option agentOptionView) bool { return option.ID == excluded }) {
			t.Fatalf("ancestor Agent %q remains selectable below child Hop: %#v", excluded, childOptions)
		}
	}
	if !slices.ContainsFunc(childOptions, func(option agentOptionView) bool { return option.ID == "edge-alt" }) {
		t.Fatalf("unrelated Agent is missing from child destination choices: %#v", childOptions)
	}
	for _, candidate := range updatedNode.Links {
		fixture.controller.linkLatencies["edge-online/"+proxynode.LinkOutboundTag(candidate.ID)] = control.LinkLatencyState{
			Responded: true, Connected: true, Duration: 42 * time.Millisecond, ObservedAt: fixture.handler.(*Handler).now(),
		}
	}

	request := fixture.authenticatedRequest(http.MethodGet, proxyHopURL(node.ID, node.Entrance.HopID), "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("GET legacy Hop page = %d %q", response.Code, response.Body.String())
	}
	if got, want := response.Header().Get("Location"), proxyNodeURL(node.ID)+"?dialog=proxy-entrance-dialog"; got != want {
		t.Fatalf("legacy Hop redirect = %q, want %q", got, want)
	}

	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET Proxy Node tree = %d %q", response.Code, response.Body.String())
	}
	env := decodeSPA(t, response)
	if env.View != "proxy-node" || env.Data.ProxyNode == nil {
		t.Fatalf("GET Proxy Node detail view = %q proxyNode = %+v", env.View, env.Data.ProxyNode)
	}
	nodeView := env.Data.ProxyNode
	if nodeView.Tree == nil || nodeView.TerminalCount != 3 || !nodeView.Tree.ShowFallback || nodeView.Tree.Final != "reject" {
		t.Fatalf("Proxy Node tree = %+v terminalCount=%d", nodeView.Tree, nodeView.TerminalCount)
	}
	if len(nodeView.Tree.Branches) != 2 || nodeView.Tree.Branches[0].RuleID != firstRule.ID || nodeView.Tree.Branches[1].RuleID != secondRule.ID {
		t.Fatalf("Proxy Node branches = %+v", nodeView.Tree.Branches)
	}
	if nodeView.Tree.Branches[0].RuleLabel != "Domain suffix" || nodeView.Tree.Branches[0].RuleValues != "example.net" {
		t.Fatalf("first branch = %+v", nodeView.Tree.Branches[0])
	}
	if nodeView.Tree.Branches[1].RuleLabel != "Protocol" || nodeView.Tree.Branches[1].RuleValues != "bittorrent" {
		t.Fatalf("second branch = %+v", nodeView.Tree.Branches[1])
	}
	if nodeView.Tree.Branches[0].Latency.Label != "42 ms" || nodeView.Tree.Branches[0].Latency.ProbeType != "tcp" {
		t.Fatalf("first branch latency = %+v", nodeView.Tree.Branches[0].Latency)
	}
	if len(nodeView.Tree.Children) != 2 {
		t.Fatalf("Proxy Node links = %+v", nodeView.Tree.Children)
	}
	if nodeView.Tree.Children[0].Protocol != "SS2022" || nodeView.Tree.Children[0].Listener != "[::]:8443" {
		t.Fatalf("first link = %+v", nodeView.Tree.Children[0])
	}
	if nodeView.Tree.Children[0].Child == nil || nodeView.Tree.Children[0].Child.ID != child.ID {
		t.Fatalf("first link child = %+v", nodeView.Tree.Children[0].Child)
	}
	body := response.Body.String()
	if strings.Contains(body, `/rule-sets`) {
		t.Error("Proxy Node tree still exposes custom Rule Set management")
	}
	request = fixture.authenticatedRequestWithLocale(
		http.MethodGet,
		proxyNodeURL(node.ID),
		"",
		localeSimplifiedChinese,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	zhEnv := decodeSPA(t, response)
	if response.Code != http.StatusOK || zhEnv.Locale != localeSimplifiedChinese || zhEnv.Data.ProxyNode == nil {
		t.Fatalf("Chinese Proxy Node detail = %d %+v", response.Code, zhEnv)
	}
	request = fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes/"+url.PathEscape(node.ID)+"/rule-sets", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("removed custom Rule Set route = %d, want 404", response.Code)
	}
	request = fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes/"+url.PathEscape(node.ID)+"/latencies", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Body.String(), `"label":"42 ms"`) {
		t.Fatalf("Link latency endpoint = %d %q", response.Code, response.Body.String())
	}

	form := url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "agent_id": {"edge-alt"}, "terminal": {"reject"}, "confirm_replace": {"yes"},
		"protocol": {"shadowsocks"}, "listen": {"::"}, "listen_port": {"8443"}, "family": {"auto"}, "method": {"2022-blake3-aes-128-gcm"},
		"mux_enabled": {"0"}, "mux_padding": {"0"}, "mux_brutal": {"0"}, "mux_brutal_up_mbps": {""}, "mux_brutal_down_mbps": {""},
		"tls_mode": {"self_signed"}, "server_name": {""}, "email": {""}, "certificate_path": {""}, "key_path": {""},
		"up_mbps": {""}, "down_mbps": {""}, "obfs_type": {""},
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, proxyLinkURL(node.ID, link.ID)+"/destination", form.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("POST Link destination = %d %q", response.Code, response.Body.String())
	}
	if got, want := response.Header().Get("Location"), proxyInspectorURL(node.ID, "link-"+link.ID); got != want {
		t.Fatalf("Link destination redirect = %q, want %q", got, want)
	}
	updatedNode, exists := fixture.proxyNodes.ProxyNode(node.ID)
	if !exists {
		t.Fatal("Proxy Node disappeared after Link destination update")
	}
	if _, exists := proxyHop(updatedNode, child.ID); exists {
		t.Fatal("Link destination replacement retained the old child Hop")
	}
	updatedLink, exists := proxyLink(updatedNode, link.ID)
	if !exists || updatedLink.ChildHopID == child.ID || updatedLink.Credential == link.Credential || len(updatedLink.Rules) != 1 || updatedLink.Rules[0].ID != firstRule.ID {
		t.Fatalf("retained Link after destination replacement = %#v, exists %v", updatedLink, exists)
	}
	updatedChild, exists := proxyHop(updatedNode, updatedLink.ChildHopID)
	if !exists || updatedChild.AgentID != "edge-alt" || updatedChild.Final.Type != proxynode.TargetReject {
		t.Fatalf("replacement child = %#v, exists %v", updatedChild, exists)
	}

	request = fixture.authenticatedRequest(http.MethodGet, proxyLinkURL(node.ID, link.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("GET legacy Link settings = %d %q", response.Code, response.Body.String())
	}
	if got, want := response.Header().Get("Location"), proxyInspectorURL(node.ID, "link-"+link.ID); got != want {
		t.Fatalf("legacy Link redirect = %q, want %q", got, want)
	}
	targetLink, _, err := fixture.proxyNodes.AddLink(node.ID, proxynode.AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "Alternate", ChildAgent: "edge-alt",
		Endpoint: proxynode.Endpoint{
			Protocol: proxynode.ProtocolShadowsocks, Listen: "::", ListenPort: 9443, Family: "auto",
			Method: "2022-blake3-aes-128-gcm",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET Proxy Node destinations = %d %q", response.Code, response.Body.String())
	}
	body = response.Body.String()
	if strings.Contains(body, `name="target_link_id"`) || strings.Contains(body, "Private branch credential and auth_user") {
		t.Fatalf("Rule editor still exposes shared Link destinations or internal isolation wording: %q", body)
	}

	form = url.Values{
		"csrf_token": {fixture.session.CSRFToken},
		"match":      {string(proxynode.MatchIPCIDR)},
		"values":     {"203.0.113.0/24"},
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, proxyLinkURL(node.ID, link.ID)+"/rules/"+firstRule.ID, form.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("POST Rule update = %d %q", response.Code, response.Body.String())
	}
	if got, want := response.Header().Get("Location"), proxyNodeURL(node.ID); got != want {
		t.Fatalf("Rule update redirect = %q, want %q", got, want)
	}
	updated, exists := fixture.proxyNodes.ProxyNode(node.ID)
	if !exists || len(updated.Links) != 3 {
		t.Fatalf("updated Proxy Node = %#v, exists %v", updated, exists)
	}
	sourceIndex := slices.IndexFunc(updated.Links, func(candidate proxynode.Link) bool { return candidate.ID == link.ID })
	targetIndex := slices.IndexFunc(updated.Links, func(candidate proxynode.Link) bool { return candidate.ID == targetLink.ID })
	if sourceIndex < 0 || targetIndex < 0 {
		t.Fatalf("updated Links = %#v", updated.Links)
	}
	if updated.Links[sourceIndex].Credential != updatedLink.Credential || updated.Links[targetIndex].Credential != targetLink.Credential {
		t.Fatal("Rule update rotated a branch credential")
	}
	if len(updated.Links[sourceIndex].Rules) != 1 || updated.Links[sourceIndex].Rules[0].ID != firstRule.ID || len(updated.Links[targetIndex].Rules) != 0 {
		t.Fatalf("Rule left its isolated branch: %#v", updated.Links)
	}
	if got := updated.Links[sourceIndex].Rules[0]; got.ID != firstRule.ID || got.Match != proxynode.MatchIPCIDR || !slices.Equal(got.Values, []string{"203.0.113.0/24"}) {
		t.Fatalf("updated Rule = %#v", got)
	}

	form = url.Values{
		"csrf_token": {fixture.session.CSRFToken},
		"rule_ids":   {secondRule.ID + "," + firstRule.ID},
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+node.ID+"/hops/"+node.Entrance.HopID+"/rules/reorder", form.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeURL(node.ID) {
		t.Fatalf("POST Rule reorder = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	firstIndex := slices.IndexFunc(updated.Links, func(candidate proxynode.Link) bool {
		return len(candidate.Rules) == 1 && candidate.Rules[0].ID == firstRule.ID
	})
	secondIndex := slices.IndexFunc(updated.Links, func(candidate proxynode.Link) bool {
		return len(candidate.Rules) == 1 && candidate.Rules[0].ID == secondRule.ID
	})
	if firstIndex < 0 || secondIndex < 0 || updated.Links[secondIndex].Rules[0].Order != 0 || updated.Links[firstIndex].Rules[0].Order != 1 {
		t.Fatalf("dragged Rule priority was not persisted: %#v", updated.Links)
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+node.ID+"/hops/"+node.Entrance.HopID+"/rules/reorder", form.Encode())
	request.Header.Set("Accept", "application/json")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("Location") != "" {
		t.Fatalf("async Rule reorder = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online", "edge-b"}); err != nil {
		t.Fatal(err)
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/users/"+url.PathEscape(user.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET user page = %d %q", response.Code, response.Body.String())
	}
	body = response.Body.String()
	if !strings.Contains(body, proxynode.AuthenticatedUserLabel(membership.ID)) || !strings.Contains(body, "anytls://") || !strings.Contains(body, "203.0.113.42:443") {
		t.Fatalf("user page omitted membership identity or import URI: %q", body)
	}

	beforeDuplicate, _ := fixture.proxyNodes.ProxyNode(node.ID)
	request = fixture.authenticatedMutationRequest(http.MethodPost, proxyLinkURL(node.ID, link.ID)+"/rules", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "match": {string(proxynode.MatchNetwork)}, "values": {"udp"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeURL(node.ID) {
		t.Fatalf("POST duplicated branch = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	afterDuplicate, _ := fixture.proxyNodes.ProxyNode(node.ID)
	if len(afterDuplicate.Hops) <= len(beforeDuplicate.Hops) {
		t.Fatalf("duplicated branch did not create a child subtree: before=%d after=%d", len(beforeDuplicate.Hops), len(afterDuplicate.Hops))
	}
}

func TestProxyLinkLatencyProbeAndHistory(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-exit")
	registry, err := pool.Open(filepath.Join(t.TempDir(), "pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.controller.poolRegistry = registry
	if _, err := registry.SetReported("edge-exit", []string{"203.0.113.50"}, nil); err != nil {
		t.Fatal(err)
	}
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online", Entrance: proxynode.Endpoint{Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto", TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	link, _, err := fixture.proxyNodes.AddLink(node.ID, proxynode.AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildAgent: "edge-exit",
		Endpoint: proxynode.Endpoint{Protocol: proxynode.ProtocolHysteria2, Listen: "::", ListenPort: 8443, Family: "ipv4", TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "exit.example"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online", "edge-exit"}); err != nil {
		t.Fatal(err)
	}
	fixture.controller.linkProbeResult = control.LinkLatencyState{ProbeType: "tcp", Responded: true, Connected: true, Duration: 8 * time.Millisecond, ObservedAt: fixture.handler.(*Handler).now()}
	request := fixture.authenticatedMutationRequest(http.MethodPost, proxyLinkURL(node.ID, link.ID)+"/latency-probe", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "agent_id": {"edge-exit"}, "family": {"ipv4"},
	}.Encode())
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || fixture.controller.linkProbeAgent != "edge-online" ||
		fixture.controller.linkProbeAddress != "203.0.113.50" || fixture.controller.linkProbePort != control.PeerLatencyListenPort || fixture.controller.linkProbeType != "tcp" ||
		!strings.Contains(response.Body.String(), `"status":"reachable"`) {
		t.Fatalf("probe = %d %q, parent=%q address=%q port=%d type=%q", response.Code, response.Body.String(), fixture.controller.linkProbeAgent, fixture.controller.linkProbeAddress, fixture.controller.linkProbePort, fixture.controller.linkProbeType)
	}
	if cached, ok := fixture.controller.PeerLatency("edge-online", "edge-exit"); !ok || cached.Duration != 8*time.Millisecond {
		t.Fatalf("cached peer latency = %+v, %v", cached, ok)
	}
	targetID := "0123456789abcdef0123456789abcdef"
	now := fixture.handler.(*Handler).now()
	fixture.controller.linkLatencies = map[string]control.LinkLatencyState{
		"edge-online/" + proxynode.LinkOutboundTag(link.ID): {TargetID: targetID, ProbeType: "quic", Responded: true, Connected: true, Duration: 12 * time.Millisecond, ObservedAt: now},
	}
	if err := fixture.proxyNodes.RecordLinkLatencySnapshot("edge-online", now, []proxynode.LinkLatencyObservation{{TargetID: targetID, Responded: true, Connected: true, Duration: 12 * time.Millisecond}}); err != nil {
		t.Fatal(err)
	}
	request = fixture.authenticatedRequest(http.MethodGet, proxyLinkURL(node.ID, link.ID)+"/latency-history?range=24h", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"average_ms":12`) || !strings.Contains(response.Body.String(), `"loss_percent":0`) {
		t.Fatalf("history = %d %q", response.Code, response.Body.String())
	}
}

func TestProxyNodePageDistinguishesPendingEntranceAndRelayOutages(t *testing.T) {
	fixture := newWebFixture(t)
	for agentID, displayName := range map[string]string{
		"edge-old-entry": "Old Entrance",
		"edge-switch":    "Switchboard",
		"edge-new-relay": "New Relay",
	} {
		enrollAgent(t, fixture.registry, agentID)
		if err := fixture.registry.RenameDisplayName(agentID, displayName); err != nil {
			t.Fatal(err)
		}
	}
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-old-entry",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, child, _, err := fixture.proxyNodes.AddBranch(node.ID, proxynode.AddBranchInput{
		AddLinkInput: proxynode.AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildAgent: "edge-switch",
			Endpoint: proxynode.Endpoint{
				Protocol: proxynode.ProtocolShadowsocks, Listen: "::", ListenPort: 8443, Family: "auto",
				Method: "2022-blake3-aes-128-gcm",
			},
		},
		Match: proxynode.MatchDomainSuffix, Values: []string{"example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-old-entry", "edge-switch"}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MoveHop(node.ID, child.ID, "edge-new-relay"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MoveHop(node.ID, node.Entrance.HopID, "edge-switch"); err != nil {
		t.Fatal(err)
	}

	render := func(locale string) spaEnvelope {
		request := fixture.authenticatedRequestWithLocale(http.MethodGet, proxyNodeURL(node.ID), "", locale)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET pending Proxy Node = %d %q", response.Code, response.Body.String())
		}
		return decodeSPA(t, response)
	}
	env := render(localeEnglish)
	op := env.Data.ProxyNode.OperationalStatus
	if !op.TopologyPending {
		t.Fatalf("expected TopologyPending = true, got %+v", op)
	}
	if len(op.EntranceOffline) != 2 || len(op.RelayOffline) != 2 {
		t.Fatalf("offline entrance/relay = %+v", op)
	}
	if !env.Data.ProxyNode.Tree.Offline || env.Data.ProxyNode.Tree.Name != "Switchboard" {
		t.Fatalf("entrance tree node = %+v", env.Data.ProxyNode.Tree)
	}
	if len(env.Data.ProxyNode.Tree.Branches) != 1 || env.Data.ProxyNode.Tree.Branches[0].Child == nil ||
		!env.Data.ProxyNode.Tree.Branches[0].Child.Offline || env.Data.ProxyNode.Tree.Branches[0].Child.Name != "New Relay" {
		t.Fatalf("child tree node = %+v", env.Data.ProxyNode.Tree.Branches)
	}

	chinese := render(localeSimplifiedChinese)
	if chinese.Locale != localeSimplifiedChinese || !chinese.Data.ProxyNode.OperationalStatus.TopologyPending {
		t.Fatalf("Chinese pending Proxy Node = %+v", chinese)
	}

	fixture.controller.sessions["edge-switch"] = true
	fixture.controller.sessions["edge-new-relay"] = true
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-switch", "edge-new-relay"}); err != nil {
		t.Fatal(err)
	}
	user, err := fixture.proxyNodes.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	env = render(localeEnglish)
	op = env.Data.ProxyNode.OperationalStatus
	if op.TopologyPending || len(op.EntranceOffline) != 0 || len(op.RelayOffline) != 0 || env.Data.ProxyNode.Tree.Offline {
		t.Fatalf("applied healthy topology retained pending or offline status: %+v", op)
	}
}

func TestProxyNodePendingStatusSurvivesWithoutCurrentDeploymentAndIsNodeScoped(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-offline")
	appliedNode, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Applied", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "applied.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online"}); err != nil {
		t.Fatal(err)
	}
	pendingNode, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Pending", RootAgent: "edge-offline",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 8443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "pending.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	deployer, err := proxynode.NewDeployer(fixture.proxyNodes, fixedProxyResolver{}, fixture.controller)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler.(*Handler).proxyDeployer = deployer
	if _, exists := deployer.Current(); exists {
		t.Fatal("fresh Deployer unexpectedly has an in-memory deployment")
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyDeployment == nil || env.Data.ProxyDeployment.Status != "pending" || env.Data.ProxyDeployment.Active {
		t.Fatalf("durable pending list status = %d %+v", response.Code, env.Data.ProxyDeployment)
	}

	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(appliedNode.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyNode == nil || env.Data.ProxyNode.OperationalStatus.TopologyPending {
		t.Fatalf("clean Node inherited another Node's pending status: %d %+v", response.Code, env.Data.ProxyNode)
	}

	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(pendingNode.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyNode == nil || !env.Data.ProxyNode.OperationalStatus.TopologyPending ||
		len(env.Data.ProxyNode.OperationalStatus.EntranceOffline) != 1 || env.Data.ProxyDeployment == nil ||
		env.Data.ProxyDeployment.Status != "pending" || env.Data.ProxyDeployment.Active {
		t.Fatalf("pending Node status = %d %+v %+v", response.Code, env.Data.ProxyNode, env.Data.ProxyDeployment)
	}
}

func TestTerminalDeploymentJobCannotHideNewerPendingTopology(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.controller.sessions["edge-online"] = true
	fixture.controller.autoApply = true
	_, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Applied", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "applied.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online"}); err != nil {
		t.Fatal(err)
	}
	deployer, err := proxynode.NewDeployer(fixture.proxyNodes, fixedProxyResolver{}, fixture.controller)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler.(*Handler).proxyDeployer = deployer
	if _, err := deployer.StartAppliedRefresh(); err != nil {
		t.Fatal(err)
	}
	waitForProxyDeployment(t, deployer)
	if job, exists := deployer.Current(); !exists || job.Status != proxynode.FleetDeploymentApplied {
		t.Fatalf("applied refresh job = %#v, exists = %t", job, exists)
	}

	if _, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Pending", RootAgent: "edge-offline",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 8443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "pending.example"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyDeployment == nil || env.Data.ProxyDeployment.Status != "pending" {
		t.Fatalf("newer pending topology was hidden by terminal refresh job: %d %+v", response.Code, env.Data.ProxyDeployment)
	}
}

func TestCurrentTopologyFailureIsNotHiddenByGenericPendingState(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.controller.sessions["edge-online"] = true
	if _, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	deployer, err := proxynode.NewDeployer(fixture.proxyNodes, fixedProxyResolver{}, fixture.controller)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler.(*Handler).proxyDeployer = deployer
	fixture.controller.queueErr = errors.New("Agent rejected the candidate")
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	job := waitForFailedProxyDeployment(t, deployer)
	metadata, exists := deployer.DeploymentMetadata(job.ID)
	if !exists || metadata.Kind != proxynode.FleetDeploymentKindTopology ||
		metadata.TopologyRevision != fixture.proxyNodes.Snapshot().Revision {
		t.Fatalf("failed topology metadata = %#v, exists=%t", metadata, exists)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes/deployment-status", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"failed"`) ||
		!strings.Contains(response.Body.String(), "Agent rejected the candidate") {
		t.Fatalf("failed topology status = %d %q", response.Code, response.Body.String())
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyDeployment == nil || env.Data.ProxyDeployment.Status != "failed" ||
		!strings.Contains(env.Data.ProxyDeployment.Error, "Agent rejected the candidate") {
		t.Fatalf("failed topology page = %d %+v", response.Code, env.Data.ProxyDeployment)
	}
}

func TestFailedAppliedRefreshDoesNotMaskNewerPendingTopology(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-offline")
	fixture.controller.sessions["edge-online"] = true
	if _, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Applied", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "applied.example"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online"}); err != nil {
		t.Fatal(err)
	}
	deployer, err := proxynode.NewDeployer(fixture.proxyNodes, fixedProxyResolver{}, fixture.controller)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler.(*Handler).proxyDeployer = deployer
	fixture.controller.queueErr = errors.New("refresh rejected")
	if _, err := deployer.StartAppliedRefresh(); err != nil {
		t.Fatal(err)
	}
	job := waitForFailedProxyDeployment(t, deployer)
	metadata, exists := deployer.DeploymentMetadata(job.ID)
	if !exists || metadata.Kind != proxynode.FleetDeploymentKindAppliedRefresh {
		t.Fatalf("failed refresh metadata = %#v, exists=%t", metadata, exists)
	}
	if _, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Pending", RootAgent: "edge-offline",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 8443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "pending.example"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyDeployment == nil || env.Data.ProxyDeployment.Status != "pending" ||
		strings.Contains(env.Data.ProxyDeployment.Error, "refresh rejected") {
		t.Fatalf("pending topology after failed refresh = %d %+v", response.Code, env.Data.ProxyDeployment)
	}
}

func TestProxyNodeListKeepsAppliedOnlyNodeAsReadOnlyPendingRemoval(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-offline")
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Legacy Runtime", RootAgent: "edge-offline",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "legacy.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-offline"}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.DeleteProxyNode(node.ID); err != nil {
		t.Fatal(err)
	}

	render := func(locale string) spaEnvelope {
		request := fixture.authenticatedRequestWithLocale(http.MethodGet, "/proxy-nodes", "", locale)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET applied-only Proxy Node list = %d %q", response.Code, response.Body.String())
		}
		return decodeSPA(t, response)
	}
	env := render(localeEnglish)
	if len(env.Data.ProxyNodes) != 1 || env.Data.ProxyNodes[0].Name != "Legacy Runtime" ||
		!env.Data.ProxyNodes[0].PendingRemoval || env.Data.ProxyNodes[0].URL != "" {
		t.Fatalf("applied-only Proxy Node list = %+v", env.Data.ProxyNodes)
	}
	request := fixture.authenticatedRequest(http.MethodGet, "/servers/edge-offline/manage", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	serverEnv := decodeSPA(t, response)
	if response.Code != http.StatusOK || serverEnv.Data.Agent == nil ||
		len(serverEnv.Data.Agent.ProxyNodeReferences) != 1 || serverEnv.Data.Agent.ProxyNodeReferences[0].URL == proxyNodeURL(node.ID) {
		t.Fatalf("applied-only server assignment linked to missing editor: %d %+v", response.Code, serverEnv.Data.Agent)
	}

	chinese := render(localeSimplifiedChinese)
	if chinese.Locale != localeSimplifiedChinese || len(chinese.Data.ProxyNodes) != 1 || !chinese.Data.ProxyNodes[0].PendingRemoval {
		t.Fatalf("Chinese applied-only Proxy Node list = %+v", chinese)
	}
}

func TestProxyNodeListShowsHighestSeverityOutageBadge(t *testing.T) {
	fixture := newWebFixture(t)
	for _, agentID := range []string{"entrance-offline", "entrance-online", "relay-offline"} {
		enrollAgent(t, fixture.registry, agentID)
	}
	fixture.controller.sessions["entrance-online"] = true
	if _, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Entrance Fault", RootAgent: "entrance-offline",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "entrance.example"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	relayNode, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Relay Fault", RootAgent: "entrance-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 8443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "relay.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := fixture.proxyNodes.AddBranch(relayNode.ID, proxynode.AddBranchInput{
		AddLinkInput: proxynode.AddLinkInput{
			ParentHopID: relayNode.Entrance.HopID, ChildAgent: "relay-offline",
			Endpoint: proxynode.Endpoint{
				Protocol: proxynode.ProtocolShadowsocks, Listen: "::", ListenPort: 20048,
				Method: "2022-blake3-aes-128-gcm",
			},
		},
		Match: proxynode.MatchDomainSuffix, Values: []string{"example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"entrance-offline", "entrance-online", "relay-offline"}); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	var entranceOffline, relayOffline int
	for _, item := range env.Data.ProxyNodes {
		if item.EntranceOffline {
			entranceOffline++
		}
		if item.RelayOffline {
			relayOffline++
		}
	}
	if response.Code != http.StatusOK || entranceOffline != 1 || relayOffline != 1 {
		t.Fatalf("Proxy Node overview outage badges = %d %+v", response.Code, env.Data.ProxyNodes)
	}

	request = fixture.authenticatedRequestWithLocale(http.MethodGet, "/proxy-nodes", "", localeSimplifiedChinese)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	zhEnv := decodeSPA(t, response)
	if response.Code != http.StatusOK || zhEnv.Locale != localeSimplifiedChinese || len(zhEnv.Data.ProxyNodes) != 2 {
		t.Fatalf("localized Proxy Node overview outage badges = %d %+v", response.Code, zhEnv)
	}
}

func TestProxyNodeDistinguishesDeletedAgentReferencesFromOfflineServers(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.controller.sessions["edge-online"] = true
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Legacy Orphan", RootAgent: "edge-deleted-entrance",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "legacy.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := fixture.proxyNodes.AddBranch(node.ID, proxynode.AddBranchInput{
		AddLinkInput: proxynode.AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildAgent: "edge-deleted-relay",
			Endpoint: proxynode.Endpoint{
				Protocol: proxynode.ProtocolShadowsocks, Listen: "::", ListenPort: 20048,
				Method: "2022-blake3-aes-128-gcm",
			},
		},
		Match: proxynode.MatchDomainSuffix, Values: []string{"example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(
		fixture.proxyNodes.Snapshot().Revision,
		[]string{"edge-deleted-entrance", "edge-deleted-relay"},
	); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	op := env.Data.ProxyNode.OperationalStatus
	if response.Code != http.StatusOK || len(op.EntranceDeleted) != 1 || len(op.RelayDeleted) != 1 ||
		len(op.EntranceOffline) != 0 || len(op.RelayOffline) != 0 {
		t.Fatalf("deleted Agent detail status=%d op=%+v", response.Code, op)
	}
	if !env.Data.ProxyNode.Tree.Deleted || env.Data.ProxyNode.Tree.Offline {
		t.Fatalf("deleted entrance hop = %+v", env.Data.ProxyNode.Tree)
	}
	if len(env.Data.ProxyNode.Tree.Branches) != 1 || env.Data.ProxyNode.Tree.Branches[0].Child == nil ||
		!env.Data.ProxyNode.Tree.Branches[0].Child.Deleted || env.Data.ProxyNode.Tree.Branches[0].Child.Offline {
		t.Fatalf("deleted relay hop = %+v", env.Data.ProxyNode.Tree.Branches)
	}

	request = fixture.authenticatedRequestWithLocale(http.MethodGet, proxyNodeURL(node.ID), "", localeSimplifiedChinese)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	zhEnv := decodeSPA(t, response)
	if response.Code != http.StatusOK || zhEnv.Locale != localeSimplifiedChinese || len(zhEnv.Data.ProxyNode.OperationalStatus.EntranceDeleted) != 1 {
		t.Fatalf("localized deleted Agent detail status=%d %+v", response.Code, zhEnv)
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	listEnv := decodeSPA(t, response)
	if response.Code != http.StatusOK || len(listEnv.Data.ProxyNodes) != 1 ||
		!listEnv.Data.ProxyNodes[0].EntranceDeleted || listEnv.Data.ProxyNodes[0].EntranceOffline {
		t.Fatalf("Proxy Node overview did not prioritize deleted entrance: %d %+v", response.Code, listEnv.Data.ProxyNodes)
	}
}

func TestPendingLinkPathDoesNotReuseAppliedLatencyOrHistory(t *testing.T) {
	fixture := newWebFixture(t)
	for _, agentID := range []string{"edge-online", "edge-exit", "edge-alt"} {
		enrollAgent(t, fixture.registry, agentID)
		fixture.controller.sessions[agentID] = true
	}
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	link, child, _, err := fixture.proxyNodes.AddBranch(node.ID, proxynode.AddBranchInput{
		AddLinkInput: proxynode.AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildAgent: "edge-exit",
			Endpoint: proxynode.Endpoint{
				Protocol: proxynode.ProtocolHysteria2, Listen: "::", ListenPort: 8443, Family: "ipv4",
				TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "exit.example"},
			},
		},
		Match: proxynode.MatchDomainSuffix, Values: []string{"example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online", "edge-exit"}); err != nil {
		t.Fatal(err)
	}
	now := fixture.handler.(*Handler).now()
	targetID := "0123456789abcdef0123456789abcdef"
	fixture.controller.linkLatencies = map[string]control.LinkLatencyState{
		"edge-online/" + proxynode.LinkOutboundTag(link.ID): {
			TargetID: targetID, ProbeType: "quic", Responded: true, Connected: true,
			Duration: 37 * time.Millisecond, ObservedAt: now,
		},
	}
	if err := fixture.proxyNodes.RecordLinkLatencySnapshot("edge-online", now, []proxynode.LinkLatencyObservation{
		{TargetID: targetID, Responded: true, Connected: true, Duration: 37 * time.Millisecond},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MoveHop(node.ID, child.ID, "edge-alt"); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes/"+url.PathEscape(node.ID)+"/latencies", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"label":"Pending Apply"`) || strings.Contains(response.Body.String(), "37 ms") {
		t.Fatalf("pending path latency = %d %q", response.Code, response.Body.String())
	}
	request = fixture.authenticatedRequest(http.MethodGet, proxyLinkURL(node.ID, link.ID)+"/latency-history?range=24h", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"label":"Pending Apply"`) || !strings.Contains(response.Body.String(), `"points":[]`) || strings.Contains(response.Body.String(), `"average_ms":37`) {
		t.Fatalf("pending path history = %d %q", response.Code, response.Body.String())
	}
	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Pending Apply") || strings.Contains(response.Body.String(), "37 ms") {
		t.Fatalf("pending path page = %d %q", response.Code, response.Body.String())
	}
}

func TestProxyTreeHidesDirectOnlyOnLeafHops(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-root")
	enrollAgent(t, fixture.registry, "edge-reject")
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-root", Final: proxynode.Target{Type: proxynode.TargetDirect},
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	render := func() spaEnvelope {
		request := fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET Proxy Node tree = %d %q", response.Code, response.Body.String())
		}
		return decodeSPA(t, response)
	}
	if env := render(); env.Data.ProxyNode.Tree.Final != "direct" || len(env.Data.ProxyNode.Tree.Branches) != 0 {
		t.Fatalf("leaf Hop tree = %+v", env.Data.ProxyNode.Tree)
	}

	link, _, err := fixture.proxyNodes.AddLink(node.ID, proxynode.AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "Blocked", ChildAgent: "edge-reject",
		Final: proxynode.Target{Type: proxynode.TargetReject},
		Endpoint: proxynode.Endpoint{
			Protocol: proxynode.ProtocolShadowsocks, Listen: "::", ListenPort: 20048, Family: "auto",
			Method: "2022-blake3-aes-128-gcm",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.AddRule(node.ID, proxynode.AddRuleInput{
		LinkID: link.ID, Match: proxynode.MatchProtocol, Values: []string{"bittorrent"},
	}); err != nil {
		t.Fatal(err)
	}
	env := render()
	if !env.Data.ProxyNode.Tree.ShowFallback || env.Data.ProxyNode.Tree.Final != "direct" {
		t.Fatalf("branched Hop fallback = %+v", env.Data.ProxyNode.Tree)
	}
	if len(env.Data.ProxyNode.Tree.Branches) != 1 || env.Data.ProxyNode.Tree.Branches[0].Child == nil ||
		!env.Data.ProxyNode.Tree.Branches[0].Child.ShowFallback || env.Data.ProxyNode.Tree.Branches[0].Child.Fallback.TargetKind != "reject" {
		t.Fatalf("Reject leaf fallback = %+v", env.Data.ProxyNode.Tree.Branches[0].Child)
	}
}

func TestProxyNodeMutationsRequireExactForms(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	form := url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "name": {"Cinema"}, "agent_id": {"edge-online"}, "terminal": {"direct"},
		"protocol": {"anytls"}, "listen": {"::"}, "listen_port": {"443"}, "family": {"auto"}, "method": {""},
		"mux_enabled": {"0"}, "mux_padding": {"0"}, "mux_brutal": {"0"}, "mux_brutal_up_mbps": {""}, "mux_brutal_down_mbps": {""},
		"tls_mode": {"self_signed"}, "server_name": {"cinema.example"}, "email": {""}, "certificate_path": {""}, "key_path": {""},
		"up_mbps": {""}, "down_mbps": {""}, "obfs_type": {""}, "unexpected": {"must be rejected"},
	}
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes", form.Encode())
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("Proxy Node create with extra field = %d, want 400", response.Code)
	}
	if len(fixture.proxyNodes.Snapshot().ProxyNodes) != 0 {
		t.Fatal("invalid exact-form request created a Proxy Node")
	}
}

func TestProxyNodeTopologyMutationAppliesImmediately(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := fixture.proxyNodes.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	fixture.controller.autoApply = true
	deployer, err := proxynode.NewDeployer(fixture.proxyNodes, fixedProxyResolver{}, fixture.controller)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler.(*Handler).proxyDeployer = deployer
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForProxyDeployment(t, deployer)

	renameURL := "/proxy-nodes/" + url.PathEscape(node.ID) + "/rename"
	request := fixture.authenticatedMutationRequest(http.MethodPost, renameURL, url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "name": {"Cinema-Live"},
	}.Encode())
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("immediate rename = %d %q", response.Code, response.Body.String())
	}
	// Renaming only changes the display name. Since immutable IDs own every
	// generated auth_user, there is no Agent configuration to deploy. The
	// transaction still commits asynchronously through the topology worker.
	deadline := time.Now().Add(2 * time.Second)
	for {
		state := fixture.proxyNodes.Snapshot()
		if len(state.AppliedProxyNodes) == 1 && state.AppliedProxyNodes[0].Name == "Cinema-Live" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("applied topology after rename = %#v", state.AppliedProxyNodes)
		}
		time.Sleep(10 * time.Millisecond)
	}

	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if env.Data.ProxyNode == nil || env.Data.ProxyNode.Name != "Cinema-Live" {
		t.Fatalf("immediate topology UI = %+v", env.Data.ProxyNode)
	}

	fixture.controller.autoApply = false
	finalURL := proxyHopURL(node.ID, node.Entrance.HopID) + "/final"
	request = fixture.authenticatedMutationRequest(http.MethodPost, finalURL, url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "target": {"reject"}, "return_to": {""},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("queued immediate terminal update = %d %q", response.Code, response.Body.String())
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, finalURL, url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "target": {"direct"}, "return_to": {""},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("overlapping topology mutation = %d, want 409", response.Code)
	}
	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if env.Data.ProxyDeployment == nil || !env.Data.ProxyDeployment.Active {
		t.Fatalf("active topology transaction did not lock topology controls: %+v", env.Data.ProxyDeployment)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		record, latestErr := fixture.controller.store.LatestForAgent(context.Background(), "edge-online")
		if latestErr == nil && record.Status == deployment.StatusDeploying {
			if _, err := fixture.controller.store.Transition(context.Background(), record.ID, deployment.StatusApplied, "", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queued topology deployment did not reach the Agent")
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitForProxyDeployment(t, deployer)
}

func TestHopTerminalRejectsLinkTargets(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.authenticatedMutationRequest(http.MethodPost, proxyHopURL(node.ID, node.Entrance.HopID)+"/final", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "target": {"link:lnk_abcdefghijklmnopqrst"}, "return_to": {""},
	}.Encode())
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "DIRECT to connect directly or REJECT") {
		t.Fatalf("Link terminal target = %d %q, want 400", response.Code, response.Body.String())
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, proxyHopURL(node.ID, node.Entrance.HopID)+"/final", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "target": {"reject"}, "return_to": {"fallback"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyInspectorURL(node.ID, "terminal-"+node.Entrance.HopID+"-fallback") {
		t.Fatalf("fallback terminal update = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
}

func TestUserSettingsOwnProxyNodeAccessAssignments(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	user, err := fixture.proxyNodes.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Archive", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 8443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "archive.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.SetAdministratorProxyAccess(true); err != nil {
		t.Fatal(err)
	}
	deployer, err := proxynode.NewDeployer(fixture.proxyNodes, fixedProxyResolver{}, fixture.controller)
	if err != nil {
		t.Fatal(err)
	}
	fixture.controller.autoApply = true
	fixture.handler.(*Handler).proxyDeployer = deployer
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForProxyDeployment(t, deployer)
	fixture.handler.(*Handler).proxyUserSync = testProxyUserSync{deployer: deployer}

	request := fixture.authenticatedRequest(http.MethodGet, "/users/"+url.PathEscape(user.ID), "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.EndUser == nil || len(env.Data.EndUser.AvailableAccess) != 2 ||
		len(env.Data.EndUser.AssignedAccess) != 0 {
		t.Fatalf("user settings omitted Proxy Node grant options: %d %+v", response.Code, env.Data.EndUser)
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/users/"+url.PathEscape(user.ID)+"/access", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "proxy_id": {node.ID},
		"quota_mode": {"limited"}, "monthly_quota_gib": {"100"},
		"expiration_mode": {"finite"}, "subscription_value": {"2"}, "subscription_unit": {"months"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("grant user access = %d %q", response.Code, response.Body.String())
	}
	updated, _ := fixture.proxyNodes.ProxyNode(node.ID)
	grantedIndex := slices.IndexFunc(updated.Memberships, func(membership proxynode.Membership) bool { return membership.UserID == user.ID })
	if len(updated.Memberships) != 2 || grantedIndex < 0 || updated.Memberships[grantedIndex].Credential.Secret == "" {
		t.Fatalf("granted membership = %#v", updated.Memberships)
	}
	grantedLabel := proxynode.AuthenticatedUserLabel(updated.Memberships[grantedIndex].ID)

	request = fixture.authenticatedRequest(http.MethodGet, "/users/"+url.PathEscape(user.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.EndUser == nil ||
		len(env.Data.EndUser.AssignedAccess) != 1 || env.Data.EndUser.AssignedAccess[0].ProxyID != node.ID ||
		env.Data.EndUser.AssignedAccess[0].AuthUser != grantedLabel ||
		len(env.Data.EndUser.AvailableAccess) != 1 || env.Data.EndUser.AvailableAccess[0].ProxyID != archive.ID {
		t.Fatalf("user settings did not separate assigned tags from available options: %d %+v", response.Code, env.Data.EndUser)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		job, exists := deployer.Current()
		if exists && job.Status == proxynode.FleetDeploymentApplied {
			break
		}
		if exists && job.Status == proxynode.FleetDeploymentFailed {
			t.Fatalf("user access deployment failed: %s", job.Error)
		}
		if time.Now().After(deadline) {
			t.Fatal("user access deployment did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}

	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyNode == nil ||
		len(env.Data.ProxyNode.UserAccess) != 2 || len(env.Data.ProxyNode.AvailableUsers) != 0 ||
		!strings.Contains(response.Body.String(), "100.00 GiB / month") {
		t.Fatalf("Proxy Node map omitted the user roster: %d %+v", response.Code, env.Data.ProxyNode)
	}
	var sawAdmin bool
	for _, access := range env.Data.ProxyNode.UserAccess {
		if access.System {
			sawAdmin = true
		}
	}
	if !sawAdmin {
		t.Fatalf("Proxy Node user roster missing protected Administrator: %+v", env.Data.ProxyNode.UserAccess)
	}
	request = fixture.authenticatedRequestWithLocale(http.MethodGet, proxyNodeURL(node.ID), "", localeSimplifiedChinese)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	zhEnv := decodeSPA(t, response)
	chineseBody := response.Body.String()
	for _, expected := range []string{"管理员", "正常", `"UsageLabel":"0 B"`, "每月 100.00 GiB"} {
		if response.Code != http.StatusOK || zhEnv.Locale != localeSimplifiedChinese || !strings.Contains(chineseBody, expected) {
			t.Errorf("Chinese Proxy Node user roster omitted %q: %d %q", expected, response.Code, chineseBody)
		}
	}
	for _, unwanted := range []string{"0 B used", "GiB / month"} {
		if strings.Contains(chineseBody, unwanted) {
			t.Errorf("Chinese Proxy Node user roster contains stale wording %q", unwanted)
		}
	}
	request = fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes/"+url.PathEscape(node.ID)+"/users", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeUsersURL(node.ID) {
		t.Fatalf("legacy Proxy Node users route = %d location=%q", response.Code, response.Header().Get("Location"))
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/users/"+url.PathEscape(user.ID)+"/access/remove", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "proxy_id": {node.ID},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("revoke user access = %d %q", response.Code, response.Body.String())
	}
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if len(updated.Memberships) != 1 || updated.Memberships[0].UserID != proxynode.SystemAdministratorUserID {
		t.Fatalf("revoked membership remains: %#v", updated.Memberships)
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+url.PathEscape(node.ID)+"/users", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "user_id": {user.ID},
		"quota_mode": {"unlimited"}, "monthly_quota_gib": {""},
		"expiration_mode": {"none"}, "subscription_value": {"1"}, "subscription_unit": {"months"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeUsersURL(node.ID) {
		t.Fatalf("Proxy Node grant user access = %d %q", response.Code, response.Body.String())
	}
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	regrantedIndex := slices.IndexFunc(updated.Memberships, func(membership proxynode.Membership) bool { return membership.UserID == user.ID })
	if len(updated.Memberships) != 2 || regrantedIndex < 0 || updated.Memberships[regrantedIndex].MonthlyQuotaBytes != 0 ||
		!updated.Memberships[regrantedIndex].SubscriptionEndsAfter.IsZero() {
		t.Fatalf("Proxy Node grant membership = %#v", updated.Memberships)
	}

	if _, err := fixture.proxyNodes.AddMembership(archive.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	request = fixture.authenticatedRequest(http.MethodGet, "/users/"+url.PathEscape(user.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.EndUser == nil ||
		len(env.Data.EndUser.AssignedAccess) != 2 || len(env.Data.EndUser.AvailableAccess) != 0 {
		t.Fatalf("fully assigned user detail = %d %+v", response.Code, env.Data.EndUser)
	}
}

func TestUserSubscriptionLinksExportActiveNodesAndOrderedRules(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	registry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.SetOverrides("edge-online", "203.0.113.42", "2001:db8::42"); err != nil {
		t.Fatal(err)
	}
	fixture.controller.poolRegistry = registry
	user, err := fixture.proxyNodes.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	deployer, err := proxynode.NewDeployer(fixture.proxyNodes, fixedProxyResolver{}, fixture.controller)
	if err != nil {
		t.Fatal(err)
	}
	fixture.controller.autoApply = true
	if _, err := deployer.Start(); err != nil {
		t.Fatal(err)
	}
	waitForProxyDeployment(t, deployer)

	request := fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyNode == nil || env.Data.ProxyNode.SubscriptionAddressMode != "ipv4" {
		t.Fatalf("Proxy Node subscription address mode = %d %+v", response.Code, env.Data.ProxyNode)
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/users/"+user.ID+"/subscription/token", url.Values{
		"csrf_token": {fixture.session.CSRFToken},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != userSubscriptionNodesURL(user.ID) {
		t.Fatalf("create subscription = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	updatedUser, _ := fixture.proxyNodes.User(user.ID)
	if updatedUser.Subscription.Token == "" {
		t.Fatal("subscription token was not created")
	}
	request = fixture.authenticatedRequest(http.MethodGet, userSubscriptionNodesURL(user.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.UserSubscription == nil ||
		!strings.HasSuffix(env.Data.UserSubscription.ClashURL, "/subscriptions/"+updatedUser.Subscription.Token+"/clash") ||
		len(env.Data.UserSubscription.Nodes) != 1 || env.Data.UserSubscription.Nodes[0].Name != "Cinema" {
		t.Fatalf("subscription Nodes page = %d %+v", response.Code, env.Data.UserSubscription)
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/subscriptions/rules", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "match": {"domain_suffix"}, "values": {"example.com"},
		"action": {"direct"}, "no_resolve": {"no"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("add subscription rule = %d %q", response.Code, response.Body.String())
	}
	request = fixture.authenticatedRequest(http.MethodGet, "/subscriptions", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.SubscriptionPolicy == nil ||
		len(env.Data.SubscriptionPolicy.Rules) != 1 ||
		env.Data.SubscriptionPolicy.Rules[0].MatchLabel != "Domain suffix" ||
		env.Data.SubscriptionPolicy.Rules[0].Values != "example.com" {
		t.Fatalf("subscription Rules page = %d %+v", response.Code, env.Data.SubscriptionPolicy)
	}

	for format, expected := range map[string]string{"clash": "DOMAIN-SUFFIX,example.com,DIRECT", "surge": "[Proxy Group]", "sing-box": `"tag": "PROXY"`} {
		request = fixture.request(http.MethodGet, "/subscriptions/"+updatedUser.Subscription.Token+"/"+format, "")
		response = httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), expected) ||
			response.Header().Get("Cache-Control") != "no-store" ||
			response.Header().Get("Access-Control-Allow-Origin") != "*" ||
			response.Header().Get("Cross-Origin-Resource-Policy") != "cross-origin" {
			t.Fatalf("%s subscription = %d headers %#v body %q", format, response.Code, response.Header(), response.Body.String())
		}
	}

	request = fixture.request(http.MethodGet, "/subscriptions/"+updatedUser.Subscription.Token+"/clash", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `name: "Cinema"`) ||
		!strings.Contains(response.Body.String(), `server: "203.0.113.42"`) ||
		strings.Contains(response.Body.String(), "Cinema - IPv6") || strings.Contains(response.Body.String(), "2001:db8::42") {
		t.Fatalf("default IPv4-only Clash subscription = %d %q", response.Code, response.Body.String())
	}
	beforeModeChange := fixture.proxyNodes.Snapshot()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+node.ID+"/subscription-addresses", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "mode": {"dual"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeURL(node.ID) {
		t.Fatalf("set subscription address mode = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	afterModeChange := fixture.proxyNodes.Snapshot()
	if afterModeChange.Revision != beforeModeChange.Revision || afterModeChange.UserRevision != beforeModeChange.UserRevision+1 {
		t.Fatalf("address mode revisions = %d/%d, want %d/%d", afterModeChange.Revision, afterModeChange.UserRevision, beforeModeChange.Revision, beforeModeChange.UserRevision+1)
	}
	request = fixture.request(http.MethodGet, "/subscriptions/"+updatedUser.Subscription.Token+"/clash", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `server: "203.0.113.42"`) ||
		!strings.Contains(response.Body.String(), "2001:db8::42") || !strings.Contains(response.Body.String(), "Cinema - IPv6") {
		t.Fatalf("explicit dual-stack Clash subscription = %d %q", response.Code, response.Body.String())
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+node.ID+"/subscription-addresses", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "mode": {"ipv4"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("restore IPv4 subscription address mode = %d %q", response.Code, response.Body.String())
	}
	if err := registry.SetOverrides("edge-online", "", "2001:db8::42"); err != nil {
		t.Fatal(err)
	}
	request = fixture.authenticatedRequest(http.MethodGet, userSubscriptionNodesURL(user.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.UserSubscription == nil ||
		len(env.Data.UserSubscription.Nodes) != 1 || env.Data.UserSubscription.Nodes[0].Status != "Unavailable" {
		t.Fatalf("missing selected family status = %d %+v", response.Code, env.Data.UserSubscription)
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost, "/users/"+user.ID+"/subscription/revoke", url.Values{
		"csrf_token": {fixture.session.CSRFToken},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("revoke subscription = %d %q", response.Code, response.Body.String())
	}
	request = fixture.request(http.MethodGet, "/subscriptions/"+updatedUser.Subscription.Token+"/clash", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("revoked subscription status = %d", response.Code)
	}
}

func TestAdministratorSubscriptionIsAutomaticAndProtected(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	registry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.SetAdministratorProxyAccess(true); err != nil {
		t.Fatal(err)
	}
	if err := registry.SetOverrides("edge-online", "203.0.113.42", ""); err != nil {
		t.Fatal(err)
	}
	fixture.controller.poolRegistry = registry
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online"}); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/subscriptions/admin", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.UserSubscription == nil || !env.Data.UserSubscription.System ||
		!env.Data.UserSubscription.Enabled || len(env.Data.UserSubscription.Nodes) != 1 ||
		env.Data.UserSubscription.Nodes[0].Name != "Cinema" || !strings.Contains(env.Data.UserSubscription.ClashURL, "/subscriptions/") {
		t.Fatalf("administrator subscription page = %d %+v", response.Code, env.Data.UserSubscription)
	}

	administrator, exists := fixture.proxyNodes.User(proxynode.SystemAdministratorUserID)
	if !exists || administrator.Subscription.Token == "" {
		t.Fatalf("administrator = %#v, exists=%v", administrator, exists)
	}
	request = fixture.request(http.MethodGet, "/subscriptions/"+administrator.Subscription.Token+"/clash", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `name: "Cinema"`) {
		t.Fatalf("administrator Clash subscription = %d %q", response.Code, response.Body.String())
	}

	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyNode == nil || len(env.Data.ProxyNode.UserAccess) != 1 ||
		!env.Data.ProxyNode.UserAccess[0].System || env.Data.ProxyNode.UserAccess[0].URL != "/subscriptions/admin" {
		t.Fatalf("protected administrator roster = %d %+v", response.Code, env.Data.ProxyNode)
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/users", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || len(env.Data.EndUsers) != 0 ||
		strings.Contains(response.Body.String(), proxynode.SystemAdministratorUserID) {
		t.Fatalf("global users exposed system administrator = %d %+v", response.Code, env.Data.EndUsers)
	}
	request = fixture.authenticatedRequest(http.MethodGet, "/users/"+proxynode.SystemAdministratorUserID, "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("system administrator user page status = %d", response.Code)
	}
}

func TestServerPageShowsFiniteEntranceUsageAndUnlimitedUserCount(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	finite, _ := fixture.proxyNodes.CreateUser("finite")
	unlimited, _ := fixture.proxyNodes.CreateUser("unlimited")
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.AddMembershipWithPlan(node.ID, finite.ID, proxynode.MembershipPlan{MonthlyQuotaBytes: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.AddMembership(node.ID, unlimited.ID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online"}); err != nil {
		t.Fatal(err)
	}
	request := fixture.authenticatedRequest(http.MethodGet, "/servers/edge-online/manage", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.Agent == nil ||
		env.Data.Agent.EntranceAllocated != "100 B" || env.Data.Agent.EntranceUsed != "0 B" ||
		env.Data.Agent.EntranceUnlimited != 1 {
		t.Fatalf("server entrance usage = %d %+v", response.Code, env.Data.Agent)
	}
}

func TestUserCredentialResetScopes(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	alice, err := fixture.proxyNodes.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := fixture.proxyNodes.CreateUser("Bob")
	if err != nil {
		t.Fatal(err)
	}
	createNode := func(name string, port int) proxynode.ProxyNode {
		t.Helper()
		node, createErr := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
			Name: name, RootAgent: "edge-online",
			Entrance: proxynode.Endpoint{
				Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: port, Family: "auto",
				TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: strings.ToLower(name) + ".example"},
			},
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		return node
	}
	first := createNode("Cinema", 443)
	second := createNode("Archive", 8443)
	if _, err := fixture.proxyNodes.AddMembership(first.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.AddMembership(second.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.proxyNodes.AddMembership(first.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	credential := func(nodeID, userID string) string {
		t.Helper()
		node, exists := fixture.proxyNodes.ProxyNode(nodeID)
		if !exists {
			t.Fatalf("Proxy Node %q is missing", nodeID)
		}
		for _, membership := range node.Memberships {
			if membership.UserID == userID {
				return membership.Credential.Secret
			}
		}
		t.Fatalf("Membership %q/%q is missing", nodeID, userID)
		return ""
	}

	request := fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(first.ID), "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyNode == nil || len(env.Data.ProxyNode.UserAccess) != 2 {
		t.Fatalf("Proxy Node credential reset UI = %d %+v", response.Code, env.Data.ProxyNode)
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/users/"+url.PathEscape(alice.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.EndUser == nil || len(env.Data.EndUser.AssignedAccess) != 2 {
		t.Fatalf("global credential reset UI = %d %+v", response.Code, env.Data.EndUser)
	}

	firstBefore := credential(first.ID, alice.ID)
	secondBefore := credential(second.ID, alice.ID)
	bobBefore := credential(first.ID, bob.ID)
	tokenBefore := alice.Subscription.Token
	request = fixture.authenticatedMutationRequest(http.MethodPost,
		"/proxy-nodes/"+url.PathEscape(first.ID)+"/users/"+url.PathEscape(alice.ID)+"/credential-reset",
		url.Values{"csrf_token": {fixture.session.CSRFToken}, "return_to": {"user"}}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || credential(first.ID, alice.ID) != firstBefore {
		t.Fatalf("unconfirmed per-Node credential reset = %d", response.Code)
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/users/"+url.PathEscape(alice.ID)+"/credentials/reset", url.Values{
		"csrf_token": {fixture.session.CSRFToken},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || credential(first.ID, alice.ID) != firstBefore ||
		credential(second.ID, alice.ID) != secondBefore {
		t.Fatalf("unconfirmed credential reset = %d", response.Code)
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/users/"+url.PathEscape(alice.ID)+"/credentials/reset", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "confirm_reset": {"yes"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	updatedAlice, _ := fixture.proxyNodes.User(alice.ID)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/users/"+url.PathEscape(alice.ID) ||
		credential(first.ID, alice.ID) == firstBefore || credential(second.ID, alice.ID) == secondBefore ||
		credential(first.ID, bob.ID) != bobBefore || updatedAlice.Subscription.Token != tokenBefore {
		t.Fatalf("global credential reset = %d location=%q", response.Code, response.Header().Get("Location"))
	}

	firstBefore = credential(first.ID, alice.ID)
	secondBefore = credential(second.ID, alice.ID)
	request = fixture.authenticatedRequest(http.MethodGet, userSubscriptionNodesURL(alice.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.UserSubscription == nil || !env.Data.UserSubscription.Enabled || env.Data.UserSubscription.System {
		t.Fatalf("subscription reset UI = %d %+v", response.Code, env.Data.UserSubscription)
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/users/"+url.PathEscape(alice.ID)+"/subscription/reset", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "confirm_reset": {"yes"},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	updatedAlice, _ = fixture.proxyNodes.User(alice.ID)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != userSubscriptionNodesURL(alice.ID) ||
		updatedAlice.Subscription.Token == tokenBefore || credential(first.ID, alice.ID) == firstBefore ||
		credential(second.ID, alice.ID) == secondBefore || credential(first.ID, bob.ID) != bobBefore {
		t.Fatalf("subscription reset = %d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func TestMembershipMaintenanceActions(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	user, err := fixture.proxyNodes.CreateUser("Alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Cinema", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(fixture.proxyNodes.Snapshot().Revision, []string{"edge-online"}); err != nil {
		t.Fatal(err)
	}
	membership, err := fixture.proxyNodes.AddMembershipWithPlan(node.ID, user.ID, proxynode.MembershipPlan{
		MonthlyQuotaBytes: 10 << 30, SubscriptionValue: 30, SubscriptionUnit: proxynode.SubscriptionMinutes,
	})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := fixture.proxyNodes.CreateUser("Bob")
	if err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/users/"+url.PathEscape(user.ID), "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.EndUser == nil || len(env.Data.EndUser.AssignedAccess) != 1 ||
		!env.Data.EndUser.AssignedAccess[0].Plan.CanExtend {
		t.Fatalf("user maintenance UI = %d %+v", response.Code, env.Data.EndUser)
	}
	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeUsersURL(node.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env = decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.ProxyNode == nil ||
		env.Data.ProxyNode.FiniteMemberCount != 1 || env.Data.ProxyNode.CompensationStart == "" ||
		len(env.Data.ProxyNode.UserAccess) != 1 || env.Data.ProxyNode.UserAccess[0].MembershipID != membership.ID ||
		env.Data.ProxyNode.UserAccess[0].SubscriptionStartedAt == "" {
		t.Fatalf("Proxy Node compensation UI = %d %+v", response.Code, env.Data.ProxyNode)
	}

	request = fixture.authenticatedMutationRequest(http.MethodPost,
		"/proxy-nodes/"+url.PathEscape(node.ID)+"/users/"+url.PathEscape(user.ID)+"/subscription-extend",
		url.Values{
			"csrf_token": {fixture.session.CSRFToken}, "return_to": {"user"},
			"extension_value": {"2"}, "extension_unit": {"hours"},
		}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/users/"+url.PathEscape(user.ID) {
		t.Fatalf("extend subscription = %d location=%q body=%q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	updated, _ := fixture.proxyNodes.ProxyNode(node.ID)
	if want := membership.SubscriptionEndsAfter.Add(2 * time.Hour); !updated.Memberships[0].SubscriptionEndsAfter.Equal(want) {
		t.Fatalf("extended deadline = %v, want %v", updated.Memberships[0].SubscriptionEndsAfter, want)
	}
	beforeCompensation := updated.Memberships[0].SubscriptionEndsAfter
	request = fixture.authenticatedMutationRequest(http.MethodPost,
		"/proxy-nodes/"+url.PathEscape(node.ID)+"/users/compensate",
		url.Values{
			"csrf_token":         {fixture.session.CSRFToken},
			"outage_started_at":  {fixture.now.In(proxynode.BillingLocation()).Format("2006-01-02T15:04")},
			"outage_ended_at":    {fixture.now.Add(-time.Hour).In(proxynode.BillingLocation()).Format("2006-01-02T15:04")},
			"compensation_value": {"1"}, "compensation_unit": {"days"},
			"membership_ids": {membership.ID},
		}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if response.Code != http.StatusBadRequest ||
		!updated.Memberships[0].SubscriptionEndsAfter.Equal(beforeCompensation) {
		t.Fatalf("invalid outage range = %d membership=%#v", response.Code, updated.Memberships[0])
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost,
		"/proxy-nodes/"+url.PathEscape(node.ID)+"/users/compensate",
		url.Values{
			"csrf_token":         {fixture.session.CSRFToken},
			"outage_started_at":  {fixture.now.Add(-3 * time.Hour).In(proxynode.BillingLocation()).Format("2006-01-02T15:04")},
			"outage_ended_at":    {fixture.now.Add(-2 * time.Hour).In(proxynode.BillingLocation()).Format("2006-01-02T15:04")},
			"compensation_value": {"1"}, "compensation_unit": {"days"},
			"membership_ids": {membership.ID},
		}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeUsersURL(node.ID) ||
		!updated.Memberships[0].SubscriptionEndsAfter.Equal(beforeCompensation.Add(24*time.Hour)) {
		t.Fatalf("bulk compensation = %d membership=%#v", response.Code, updated.Memberships[0])
	}

	bobMembership, err := fixture.proxyNodes.AddMembershipWithPlan(node.ID, bob.ID, proxynode.MembershipPlan{
		MonthlyQuotaBytes: 10 << 30, SubscriptionValue: 30, SubscriptionUnit: proxynode.SubscriptionMinutes,
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeMultiAlice := updated.Memberships[0].SubscriptionEndsAfter
	beforeMultiBob := bobMembership.SubscriptionEndsAfter
	request = fixture.authenticatedMutationRequest(http.MethodPost,
		"/proxy-nodes/"+url.PathEscape(node.ID)+"/users/compensate",
		url.Values{
			"csrf_token":         {fixture.session.CSRFToken},
			"outage_started_at":  {fixture.now.Add(-3 * time.Hour).In(proxynode.BillingLocation()).Format("2006-01-02T15:04")},
			"outage_ended_at":    {fixture.now.Add(-2 * time.Hour).In(proxynode.BillingLocation()).Format("2006-01-02T15:04")},
			"compensation_value": {"2"}, "compensation_unit": {"hours"},
			"membership_ids": {membership.ID, bobMembership.ID},
		}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if response.Code != http.StatusSeeOther ||
		!updated.Memberships[0].SubscriptionEndsAfter.Equal(beforeMultiAlice.Add(2*time.Hour)) ||
		!updated.Memberships[1].SubscriptionEndsAfter.Equal(beforeMultiBob.Add(2*time.Hour)) {
		t.Fatalf("multi-user bulk compensation = %d memberships=%#v", response.Code, updated.Memberships)
	}

	oldSecret := updated.Memberships[0].Credential.Secret
	request = fixture.authenticatedMutationRequest(http.MethodPost,
		"/proxy-nodes/"+url.PathEscape(node.ID)+"/users/"+url.PathEscape(user.ID)+"/credential-reset",
		url.Values{"csrf_token": {fixture.session.CSRFToken}, "return_to": {"node"}, "confirm_reset": {"yes"}}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeUsersURL(node.ID) || updated.Memberships[0].Credential.Secret == oldSecret {
		t.Fatalf("credential reset = %d membership=%#v", response.Code, updated.Memberships[0])
	}

	resetAt := updated.Memberships[0].QuotaResetsAfter
	request = fixture.authenticatedMutationRequest(http.MethodPost,
		"/proxy-nodes/"+url.PathEscape(node.ID)+"/users/"+url.PathEscape(user.ID)+"/traffic-reset",
		url.Values{"csrf_token": {fixture.session.CSRFToken}, "return_to": {"node"}}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeUsersURL(node.ID) || !updated.Memberships[0].QuotaResetsAfter.Equal(resetAt) ||
		len(fixture.controller.trafficRequests) != 1 || fixture.controller.trafficRequests[0] != "edge-online" {
		t.Fatalf("traffic reset = %d membership=%#v", response.Code, updated.Memberships[0])
	}
}

func TestParseEndpointFormIgnoresProtocolForeignFields(t *testing.T) {
	t.Parallel()

	shadowsocks, err := parseEndpointForm(url.Values{
		"protocol": {"shadowsocks"}, "listen": {"::"}, "listen_port": {"443"}, "family": {"auto"},
		"method": {"2022-blake3-aes-256-gcm"}, "tls_mode": {"self_signed"}, "server_name": {"stale.example"},
		"mux_enabled": {"1"}, "mux_padding": {"1"}, "mux_brutal": {"1"}, "mux_brutal_up_mbps": {"100"}, "mux_brutal_down_mbps": {"200"},
		"up_mbps": {"not-a-number"}, "down_mbps": {"not-a-number"}, "obfs_type": {"salamander"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if shadowsocks.Method != "2022-blake3-aes-256-gcm" || shadowsocks.TLS != (proxynode.TLSConfig{}) || shadowsocks.UpMbps != 0 || shadowsocks.DownMbps != 0 || shadowsocks.ObfsType != "" || shadowsocks.Multiplex == nil || !shadowsocks.Multiplex.Enabled || !shadowsocks.Multiplex.Padding || shadowsocks.Multiplex.Brutal == nil || shadowsocks.Multiplex.Brutal.UpMbps != 100 || shadowsocks.Multiplex.Brutal.DownMbps != 200 {
		t.Fatalf("Shadowsocks endpoint retained protocol-foreign fields: %#v", shadowsocks)
	}
	listenerOnlyMux, err := parseEndpointForm(url.Values{
		"protocol": {"shadowsocks"}, "listen": {"::"}, "listen_port": {"443"}, "family": {"auto"},
		"method": {"2022-blake3-aes-256-gcm"}, "mux_enabled": {"0"}, "mux_padding": {"1"}, "mux_brutal": {"0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if listenerOnlyMux.Multiplex == nil || listenerOnlyMux.Multiplex.Enabled || !listenerOnlyMux.Multiplex.Padding {
		t.Fatalf("disabled per-Link mux lost the shared listener policy: %#v", listenerOnlyMux.Multiplex)
	}

	anyTLS, err := parseEndpointForm(url.Values{
		"protocol": {"anytls"}, "listen": {"::"}, "listen_port": {"443"}, "family": {"auto"},
		"method": {"2022-blake3-aes-128-gcm"}, "tls_mode": {"self_signed"}, "server_name": {"relay.example"},
		"mux_enabled": {"1"}, "mux_padding": {"1"}, "mux_brutal": {"1"}, "mux_brutal_up_mbps": {"bad"}, "mux_brutal_down_mbps": {"bad"},
		"up_mbps": {"not-a-number"}, "down_mbps": {"not-a-number"}, "obfs_type": {"gecko"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if anyTLS.Method != "" || anyTLS.Multiplex != nil || anyTLS.TLS.Mode != proxynode.TLSModeSelfSigned || anyTLS.TLS.ServerName != "relay.example" || anyTLS.UpMbps != 0 || anyTLS.DownMbps != 0 || anyTLS.ObfsType != "" {
		t.Fatalf("AnyTLS endpoint retained protocol-foreign fields: %#v", anyTLS)
	}

	hysteria, err := parseEndpointForm(url.Values{
		"protocol": {"hysteria2"}, "listen": {"::"}, "listen_port": {"8443"}, "family": {"ipv6"},
		"method": {"2022-blake3-aes-128-gcm"}, "tls_mode": {"self_signed"}, "server_name": {"hy2.example"},
		"up_mbps": {"100"}, "down_mbps": {"200"}, "obfs_type": {"salamander"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hysteria.Method != "" || hysteria.TLS.Mode != proxynode.TLSModeSelfSigned || hysteria.UpMbps != 100 || hysteria.DownMbps != 200 || hysteria.ObfsType != "salamander" {
		t.Fatalf("Hysteria2 endpoint parsed incorrectly: %#v", hysteria)
	}
}

func TestAddProxyLinkIgnoresHiddenForeignProtocolFields(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-entrance")
	enrollAgent(t, fixture.registry, "edge-exit")
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Gen2-JP-Out", RootAgent: "edge-entrance", Final: proxynode.Target{Type: proxynode.TargetDirect},
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "entrance.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "match": {"domain_suffix"}, "values": {"example.net"},
		"child_agent": {"edge-exit"}, "child_terminal": {"direct"},
		"protocol": {"shadowsocks"}, "listen": {"::"}, "listen_port": {"20048"}, "family": {"auto"},
		"method": {"2022-blake3-aes-256-gcm"}, "tls_mode": {"self_signed"}, "server_name": {"stale.example"},
		"mux_enabled": {"0"}, "mux_padding": {"0"}, "mux_brutal": {"0"}, "mux_brutal_up_mbps": {""}, "mux_brutal_down_mbps": {""},
		"email": {""}, "certificate_path": {""}, "key_path": {""}, "up_mbps": {""}, "down_mbps": {""}, "obfs_type": {""},
	}
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+node.ID+"/hops/"+node.Entrance.HopID+"/links", form.Encode())
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("POST Shadowsocks Link = %d %q", response.Code, response.Body.String())
	}
	if got, want := response.Header().Get("Location"), proxyNodeURL(node.ID); got != want {
		t.Fatalf("POST Shadowsocks Link redirect = %q, want %q", got, want)
	}
	updated, exists := fixture.proxyNodes.ProxyNode(node.ID)
	if !exists || len(updated.Links) != 1 || len(updated.Links[0].Rules) != 1 {
		t.Fatalf("updated Proxy Node = %#v, exists %v", updated, exists)
	}
	endpoint := updated.Links[0].Endpoint
	if endpoint.Protocol != proxynode.ProtocolShadowsocks || endpoint.TLS != (proxynode.TLSConfig{}) || endpoint.ObfsType != "" {
		t.Fatalf("saved Shadowsocks Link retained foreign fields: %#v", endpoint)
	}
}

func TestProxyNodeCanCreateAndManageConditionalBlockRule(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-entrance")
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "filtered", RootAgent: "edge-entrance", Final: proxynode.Target{Type: proxynode.TargetDirect},
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "filtered.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "match": {"domain_suffix"},
		"values": {"ads.example"},
	}
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+node.ID+"/hops/"+node.Entrance.HopID+"/block-rules", form.Encode())
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeURL(node.ID) {
		t.Fatalf("POST BLOCK rule = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	updated, exists := fixture.proxyNodes.ProxyNode(node.ID)
	if !exists || len(updated.Hops) != 1 || len(updated.Links) != 0 || len(updated.BlockBranches) != 1 {
		t.Fatalf("BLOCK rule created a relay artifact: %#v, exists %v", updated, exists)
	}

	request = fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET Proxy Node = %d %q", response.Code, response.Body.String())
	}
	env := decodeSPA(t, response)
	if env.Data.ProxyNode == nil || env.Data.ProxyNode.Tree == nil ||
		len(env.Data.ProxyNode.Tree.BlockRules) != 1 ||
		len(env.Data.ProxyNode.Tree.Branches) != 1 || !env.Data.ProxyNode.Tree.Branches[0].Block ||
		!env.Data.ProxyNode.Tree.ShowFallback {
		t.Fatalf("Proxy Node BLOCK rule view = %+v", env.Data.ProxyNode)
	}

	ruleID := updated.BlockBranches[0].Rule.ID
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+node.ID+"/block-rules/"+ruleID+"/delete", url.Values{
		"csrf_token": {fixture.session.CSRFToken},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("DELETE BLOCK rule = %d %q", response.Code, response.Body.String())
	}
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if len(updated.BlockBranches) != 0 {
		t.Fatalf("BLOCK rule remains after deletion: %#v", updated.BlockBranches)
	}
}

func TestCreateProxyNodeMakesTerminalExitExplicitAndReturnsToRelayMap(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-child")
	fixture.controller.sessions["edge-child"] = true
	deployer, err := proxynode.NewDeployer(fixture.proxyNodes, fixedProxyResolver{}, fixture.controller)
	if err != nil {
		t.Fatal(err)
	}
	fixture.controller.autoApply = true
	fixture.handler.(*Handler).proxyDeployer = deployer
	request := fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes/new", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET new Proxy Node = %d %q", response.Code, response.Body.String())
	}
	env := decodeSPA(t, response)
	if env.View != "proxy-node-new" || len(env.Data.AgentOptions) < 2 {
		t.Fatalf("new Proxy Node view = %q agents = %+v", env.View, env.Data.AgentOptions)
	}

	request = fixture.authenticatedRequestWithLocale(http.MethodGet, "/proxy-nodes/new", "", localeSimplifiedChinese)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET Chinese new Proxy Node = %d %q", response.Code, response.Body.String())
	}
	zhEnv := decodeSPA(t, response)
	if zhEnv.Locale != localeSimplifiedChinese || zhEnv.View != "proxy-node-new" {
		t.Fatalf("Chinese new Proxy Node = %+v", zhEnv)
	}

	form := url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "name": {"东京 出口"}, "agent_id": {"edge-online"}, "terminal": {"reject"},
		"protocol": {"anytls"}, "listen": {"::"}, "listen_port": {"443"}, "family": {"auto"}, "method": {""},
		"mux_enabled": {"0"}, "mux_padding": {"0"}, "mux_brutal": {"0"}, "mux_brutal_up_mbps": {""}, "mux_brutal_down_mbps": {""},
		"tls_mode": {"self_signed"}, "server_name": {"cinema.example"}, "email": {""}, "certificate_path": {""}, "key_path": {""},
		"up_mbps": {""}, "down_mbps": {""}, "obfs_type": {""},
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes", form.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("POST Proxy Node = %d %q", response.Code, response.Body.String())
	}
	state := fixture.proxyNodes.Snapshot()
	if len(state.ProxyNodes) != 1 {
		t.Fatalf("created Proxy Nodes = %d, want 1", len(state.ProxyNodes))
	}
	node := state.ProxyNodes[0]
	if node.Name != "东京 出口" {
		t.Fatalf("created Proxy Node name = %q, want %q", node.Name, "东京 出口")
	}
	entrance, ok := proxyHop(node, node.Entrance.HopID)
	if !ok || entrance.Name != "edge-online" || entrance.Final.Type != proxynode.TargetReject {
		t.Fatalf("created entrance = %#v, exists %v", entrance, ok)
	}
	wantLocation := proxyNodeURL(node.ID)
	if got := response.Header().Get("Location"); got != wantLocation {
		t.Fatalf("create redirect = %q, want %q", got, wantLocation)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		deployment, exists := deployer.Current()
		if exists && deployment.Status == proxynode.FleetDeploymentApplied {
			if len(deployment.Agents) != 1 || deployment.Agents[0].AgentID != "edge-online" {
				t.Fatalf("automatic entrance deployment Agents = %#v", deployment.Agents)
			}
			break
		}
		if exists && deployment.Status == proxynode.FleetDeploymentFailed {
			t.Fatalf("automatic entrance deployment failed: %s", deployment.Error)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for automatic entrance deployment")
		}
		time.Sleep(10 * time.Millisecond)
	}

	request = fixture.authenticatedRequest(http.MethodGet, wantLocation, "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET entrance Hop inspector = %d %q", response.Code, response.Body.String())
	}
	detailEnv := decodeSPA(t, response)
	if detailEnv.Data.ProxyNode == nil || detailEnv.Data.ProxyNode.Tree == nil ||
		!detailEnv.Data.ProxyNode.Tree.IsEntrance || detailEnv.Data.ProxyNode.Tree.Final != "reject" ||
		!detailEnv.Data.ProxyNode.Tree.ShowFallback {
		t.Fatalf("entrance Hop view = %+v", detailEnv.Data.ProxyNode)
	}

	branchForm := url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "match": {string(proxynode.MatchDomainSuffix)}, "values": {"example.net"},
		"child_agent": {"edge-child"}, "child_terminal": {"direct"},
		"protocol": {"shadowsocks"}, "listen": {"::"}, "listen_port": {"20048"}, "family": {"auto"}, "method": {"2022-blake3-aes-128-gcm"},
		"mux_enabled": {"0"}, "mux_padding": {"0"}, "mux_brutal": {"0"}, "mux_brutal_up_mbps": {""}, "mux_brutal_down_mbps": {""},
		"tls_mode": {"self_signed"}, "server_name": {""}, "email": {""}, "certificate_path": {""}, "key_path": {""},
		"up_mbps": {""}, "down_mbps": {""}, "obfs_type": {""},
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+node.ID+"/hops/"+entrance.ID+"/links", branchForm.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeURL(node.ID) {
		t.Fatalf("POST branch = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	waitForProxyDeployment(t, deployer)
	updated, ok := fixture.proxyNodes.ProxyNode(node.ID)
	if !ok || len(updated.Hops) != 2 || len(updated.Links) != 1 || len(updated.Links[0].Rules) != 1 || updated.Links[0].ChildHopID != updated.Hops[1].ID {
		t.Fatalf("atomic branch creation produced %#v, exists %v", updated, ok)
	}

	branchForm.Set("match", string(proxynode.MatchNone))
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+node.ID+"/hops/"+entrance.ID+"/links", branchForm.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("POST invalid branch = %d, want 400", response.Code)
	}
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if len(updated.Hops) != 2 || len(updated.Links) != 1 {
		t.Fatalf("invalid branch left a child Hop or Link behind: %#v", updated)
	}

	createdLink, createdRule := updated.Links[0], updated.Links[0].Rules[0]
	request = fixture.authenticatedMutationRequest(http.MethodPost, proxyLinkURL(node.ID, createdLink.ID)+"/rules/delete", url.Values{
		"csrf_token": {fixture.session.CSRFToken}, "rule_id": {createdRule.ID},
	}.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyInspectorURL(node.ID, "hop-"+entrance.ID) {
		t.Fatalf("DELETE branch = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	waitForProxyDeployment(t, deployer)
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if len(updated.Hops) != 1 || len(updated.Links) != 0 {
		t.Fatalf("deleting branch did not remove its child subtree: %#v", updated)
	}

	branchForm.Set("values", "")
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/"+node.ID+"/hops/"+entrance.ID+"/links", branchForm.Encode())
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != proxyNodeURL(node.ID) {
		t.Fatalf("POST ALL branch = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	waitForProxyDeployment(t, deployer)
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if len(updated.Hops) != 2 || len(updated.Links) != 1 || !updated.Links[0].Fallback || len(updated.Links[0].Rules) != 0 {
		t.Fatalf("ALL branch creation produced %#v", updated)
	}
}

func TestProxyNodeEditorOffersSecretFreePhysicalListenerReuse(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-listener")
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "shared-edge", RootAgent: "edge-listener",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolShadowsocks, Listen: "::", ListenPort: 20048,
			Family: "auto", Method: "2022-blake3-aes-256-gcm",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.Entrance.Endpoint.ServerKey == "" {
		t.Fatal("test listener did not receive its generated server key")
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes/new", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET new Proxy Node = %d %q", response.Code, response.Body.String())
	}
	env := decodeSPA(t, response)
	wantListenerID := proxynode.ListenerPresetID("edge-listener", node.Entrance.Endpoint)
	if len(env.Data.ListenerOptions) != 1 || env.Data.ListenerOptions[0].ID != wantListenerID ||
		env.Data.ListenerOptions[0].AgentID != "edge-listener" ||
		env.Data.ListenerOptions[0].ReferenceCount != 1 ||
		env.Data.ListenerOptions[0].Label != "SS2022 · :::20048 · 1 reference" {
		t.Fatalf("listener reuse options = %+v", env.Data.ListenerOptions)
	}
	if strings.Contains(response.Body.String(), node.Entrance.Endpoint.ServerKey) {
		t.Fatal("physical-listener catalog exposed a generated server key")
	}
}

func TestProxyNodeEditorKeepsLegacyFileTLSValuesHidden(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-legacy-files")
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Legacy TLS", RootAgent: "edge-legacy-files",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{
				Mode:            proxynode.TLSModeFiles,
				CertificatePath: "/etc/theatropolis/certs/server.pem",
				KeyPath:         "/etc/theatropolis/certs/server.key",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET legacy file-TLS Proxy Node = %d %q", response.Code, response.Body.String())
	}
	env := decodeSPA(t, response)
	if env.Data.ProxyNode == nil || env.Data.ProxyNode.Entrance.TLSMode != "files" ||
		env.Data.ProxyNode.Entrance.CertificatePath != "/etc/theatropolis/certs/server.pem" ||
		env.Data.ProxyNode.Entrance.KeyPath != "/etc/theatropolis/certs/server.key" {
		t.Fatalf("legacy file-TLS entrance = %+v", env.Data.ProxyNode)
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
	env := decodeSPA(t, response)
	var manageURLs []string
	for _, agent := range env.Data.Agents {
		manageURLs = append(manageURLs, agent.URL)
	}
	for _, expected := range []string{
		"/servers/new/manage",
		"/servers/enrollment-result/manage",
	} {
		if !slices.Contains(manageURLs, expected) {
			t.Errorf("servers manage URLs %v do not contain %q", manageURLs, expected)
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

func TestAgentUpdateAllQueuesLatestForEligibleAgents(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-second")
	fixture.controller.sessions["edge-second"] = true
	form := url.Values{
		"csrf_token": {fixture.session.CSRFToken},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/agent-update-all",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update-all response = %d %q", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Queued agent update to v1.14.0-beta.7 for 2 server(s).") {
		t.Fatalf("update-all notice missing from %q", response.Body.String())
	}
	for _, agentID := range []string{"edge-online", "edge-second"} {
		state, exists := fixture.controller.updates[agentID]
		if !exists || state.TargetVersion != "v1.14.0-beta.7" {
			t.Fatalf("queued update for %s = %+v, exists=%v", agentID, state, exists)
		}
	}
}

func TestAgentUpdateAllSkipsOfflineAgents(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-offline")
	form := url.Values{
		"csrf_token": {fixture.session.CSRFToken},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/agent-update-all",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update-all response = %d %q", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "for 1 server(s). 1 enrolled server(s) skipped") {
		t.Fatalf("update-all notice missing from %q", response.Body.String())
	}
	if _, exists := fixture.controller.updates["edge-offline"]; exists {
		t.Fatal("offline agent update was queued")
	}
	if _, exists := fixture.controller.updates["edge-online"]; !exists {
		t.Fatal("online agent update was not queued")
	}
}

func TestAgentUpdateAllRejectsBadCSRF(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	form := url.Values{
		"csrf_token": {"bogus"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/agent-update-all",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("update-all response = %d %q", response.Code, response.Body.String())
	}
	if _, exists := fixture.controller.updates["edge-online"]; exists {
		t.Fatal("update was queued despite bad CSRF token")
	}
}

func TestSingBoxUpdateAllQueuesSelectedReleaseForConnectedAgents(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	for _, agentID := range []string{"edge-online", "edge-second", "edge-offline"} {
		enrollAgent(t, fixture.registry, agentID)
	}
	fixture.controller.sessions["edge-second"] = true
	fixture.handler.(*Handler).singBoxReleases = testReleaseCatalog{
		releases: []AgentRelease{
			{Tag: "v1.14.0-theatropolis.1"},
			{Tag: "v1.14.0-rc.1.theatropolis.1", Prerelease: true},
		},
	}
	form := url.Values{
		"csrf_token":     {fixture.session.CSRFToken},
		"target_version": {"v1.14.0-rc.1.theatropolis.1"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/sing-box-update-all",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("sing-box update-all response = %d %q", response.Code, response.Body.String())
	}
	if !strings.Contains(
		response.Body.String(),
		"Queued sing-box v1.14.0-rc.1.theatropolis.1 for 2 connected server(s).",
	) || !strings.Contains(response.Body.String(), "1 enrolled server(s) skipped") {
		t.Fatalf("sing-box update-all notice missing from %q", response.Body.String())
	}
	for _, agentID := range []string{"edge-online", "edge-second"} {
		state, exists := fixture.controller.singBoxUpdates[agentID]
		if !exists || state.TargetVersion != "v1.14.0-rc.1.theatropolis.1" {
			t.Fatalf("queued sing-box update for %s = %+v, exists=%v", agentID, state, exists)
		}
	}
	if _, exists := fixture.controller.singBoxUpdates["edge-offline"]; exists {
		t.Fatal("offline Agent received a sing-box update")
	}
}

func TestSingBoxUpdateAllRejectsUnpublishedReleaseAndBadCSRF(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.handler.(*Handler).singBoxReleases = testReleaseCatalog{
		releases: []AgentRelease{{Tag: "v1.14.0-rc.1.theatropolis.1", Prerelease: true}},
	}
	tests := []struct {
		name   string
		csrf   string
		target string
		status int
	}{
		{
			name: "unpublished release", csrf: fixture.session.CSRFToken,
			target: "v1.14.0-rc.2.theatropolis.1", status: http.StatusBadRequest,
		},
		{
			name: "bad CSRF", csrf: "bogus",
			target: "v1.14.0-rc.1.theatropolis.1", status: http.StatusForbidden,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			form := url.Values{
				"csrf_token":     {test.csrf},
				"target_version": {test.target},
			}.Encode()
			request := fixture.authenticatedMutationRequest(
				http.MethodPost,
				"/servers/sing-box-update-all",
				form,
			)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("response = %d %q, want %d", response.Code, response.Body.String(), test.status)
			}
		})
	}
	if len(fixture.controller.singBoxUpdates) != 0 {
		t.Fatalf("rejected fleet update queued changes: %+v", fixture.controller.singBoxUpdates)
	}
}

func TestSingBoxUpdateQueuesExactReleaseCandidate(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	form := url.Values{
		"csrf_token":     {fixture.session.CSRFToken},
		"target_version": {"v1.14.0-rc.1.theatropolis.1"},
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
	if !exists || state.TargetVersion != "v1.14.0-rc.1.theatropolis.1" {
		t.Fatalf("queued sing-box update = %+v, exists=%v", state, exists)
	}
}

func TestServerPageRendersSingBoxUpdateForm(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.handler.(*Handler).singBoxReleases = testReleaseCatalog{
		releases: []AgentRelease{
			{Tag: "v1.14.0-rc.1.theatropolis.1", Prerelease: true},
			{Tag: "v1.14.0-theatropolis.1", Prerelease: false},
		},
	}
	request := fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/manage",
		"",
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.Agent == nil ||
		!env.Data.Agent.SingBoxUpdateEnabled || env.Data.Agent.SingBoxVersion != "v1.14.0-beta.2" {
		t.Fatalf(
			"sing-box update form response = %d %+v",
			response.Code,
			env.Data.Agent,
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
			{Tag: "v1.14.0-rc.1.theatropolis.1", Prerelease: true},
			{Tag: "v1.14.0-theatropolis.1", Prerelease: false},
		},
	}
	for _, test := range []struct {
		catalog string
		want    []string
		reject  string
	}{
		{catalog: "agent", want: []string{"v1.14.0-beta.7", "v1.13.2"}, reject: "v1.14.0-rc.1.theatropolis.1"},
		{catalog: "sing-box", want: []string{"v1.14.0-rc.1.theatropolis.1", "v1.14.0-theatropolis.1"}, reject: "v1.13.2"},
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

func TestFleetVersionsEndpointReturnsSingBoxCatalogWithoutAgentContext(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	fixture.handler.(*Handler).singBoxReleases = testReleaseCatalog{
		releases: []AgentRelease{
			{Tag: "v1.14.0-theatropolis.1"},
			{Tag: "v1.14.0-rc.1.theatropolis.1", Prerelease: true},
		},
	}
	request := fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/versions?catalog=sing-box",
		"",
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("fleet versions response = %d %q", response.Code, response.Body.String())
	}
	for _, version := range []string{"v1.14.0-theatropolis.1", "v1.14.0-rc.1.theatropolis.1"} {
		if !strings.Contains(response.Body.String(), version) {
			t.Fatalf("fleet versions response missing %q: %q", version, response.Body.String())
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

func TestSubscriptionRuleSetOptionsEndpoint(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	fixture.handler.(*Handler).geositeRuleSets = testRuleSetOptions{
		options: []string{"category-ads-all", "cn", "openai"},
	}
	fixture.handler.(*Handler).geoipRuleSets = testRuleSetOptions{
		options: []string{"cn", "private"},
	}

	request := fixture.request(http.MethodGet, "/subscriptions/rule-set-options?kind=geosite", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated subscription rule-set status = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/subscriptions/rule-set-options?kind=geosite", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("subscription rule-set response = %d headers %#v body %q", response.Code, response.Header(), response.Body.String())
	}
	for _, option := range []string{"category-ads-all", "cn", "openai"} {
		if !strings.Contains(response.Body.String(), option) {
			t.Fatalf("subscription rule-set response missing %q: %q", option, response.Body.String())
		}
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/subscriptions/rule-set-options?kind=geoip", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "private") {
		t.Fatalf("subscription GeoIP rule-set response = %d body %q", response.Code, response.Body.String())
	}
}

func TestSubscriptionRuleReorderEndpoint(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	first, err := fixture.proxyNodes.AddSubscriptionRule(proxynode.SubscriptionRuleInput{
		Match: proxynode.SubscriptionMatchDomainSuffix, Values: []string{"first.example"}, Action: proxynode.SubscriptionProxy,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.proxyNodes.AddSubscriptionRule(proxynode.SubscriptionRuleInput{
		Match: proxynode.SubscriptionMatchDomainSuffix, Values: []string{"second.example"}, Action: proxynode.SubscriptionDirect,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedMutationRequest(http.MethodPost, "/subscriptions/rules/reorder", url.Values{
		"csrf_token": {fixture.session.CSRFToken},
		"rule_ids":   {second.ID + "," + first.ID},
	}.Encode())
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("Location") != "" {
		t.Fatalf("subscription Rule reorder = %d location %q body %q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	policy := fixture.proxyNodes.SubscriptionPolicy()
	if len(policy.Rules) != 2 || policy.Rules[0].ID != second.ID || policy.Rules[0].Order != 0 ||
		policy.Rules[1].ID != first.ID || policy.Rules[1].Order != 1 {
		t.Fatalf("subscription Rule order = %#v", policy.Rules)
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
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.Agent == nil || !env.Data.Agent.UpdateEnabled {
		t.Fatalf("agent update form response = %d %+v", response.Code, env.Data.Agent)
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
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.Agent == nil || env.Data.Agent.AgentVersion != "v0.0.9" ||
		!env.Data.Agent.UpdateEnabled {
		t.Fatalf("agent update form missing current version: %d %+v", response.Code, env.Data.Agent)
	}
}

func TestServerPageShowsACMERelayOnlyForCapableCoLocatedAgent(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.controller.acmeRelay = map[string]bool{"edge-online": true}

	request := fixture.authenticatedRequest(http.MethodGet, "/servers/edge-online/manage", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.Agent == nil || !env.Data.Agent.ACMEHTTP01Relay {
		t.Fatalf("ACME relay status response = %d %+v", response.Code, env.Data.Agent)
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

func TestRevokeServerReportsReferencedProxyNodeConflict(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	fixture.controller.revokeErr = fmt.Errorf("%w: Agent %q is used by Cinema", proxynode.ErrAgentReferenced, "edge-online")
	form := url.Values{
		"agent_id":       {"edge-online"},
		"confirm_revoke": {"yes"},
		"csrf_token":     {fixture.session.CSRFToken},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/revoke",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusConflict ||
		!strings.Contains(body, "Review its assignments and finish the topology change") ||
		strings.Contains(body, `Agent &#34;edge-online&#34; is used by Cinema`) {
		t.Fatalf("referenced revoke response = %d %q", response.Code, response.Body.String())
	}
	if _, err := fixture.registry.PublicKey(context.Background(), "edge-online"); err != nil {
		t.Fatalf("referenced revoke removed identity: %v", err)
	}
}

func TestRevokeServerForceRemovesPermanentlyOfflineAgent(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	// edge-lost is enrolled but has no session in the fixture, modelling a
	// wiped machine that can never reconnect.
	enrollAgent(t, fixture.registry, "edge-lost")
	if _, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name:      "Cinema",
		RootAgent: "edge-lost",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(
		fixture.proxyNodes.Snapshot().Revision,
		[]string{"edge-lost"},
	); err != nil {
		t.Fatal(err)
	}

	// The blocked page exposes the force-removal flag for the offline Server.
	request := fixture.authenticatedRequest(http.MethodGet, "/servers/edge-lost/manage", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.Agent == nil || !env.Data.Agent.RemovalBlocked || !env.Data.Agent.CanForceRemove {
		t.Fatalf("offline referenced server page = %d %+v", response.Code, env.Data.Agent)
	}
	request = fixture.authenticatedRequestWithLocale(
		http.MethodGet, "/servers/edge-lost/manage", "", localeSimplifiedChinese,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	zhEnv := decodeSPA(t, response)
	if zhEnv.Locale != localeSimplifiedChinese || zhEnv.Data.Agent == nil || !zhEnv.Data.Agent.CanForceRemove {
		t.Fatalf("localized server page omitted CanForceRemove: %+v", zhEnv)
	}

	// The ordinary revoke path stays blocked.
	form := url.Values{
		"agent_id":       {"edge-lost"},
		"confirm_revoke": {"yes"},
		"csrf_token":     {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers/edge-lost/revoke", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), "This Server is still used by one or more Proxy Nodes") {
		t.Fatalf("ordinary referenced revoke response = %d %q", response.Code, response.Body.String())
	}

	// Force removal still requires the explicit confirmation.
	unconfirmed := url.Values{
		"agent_id":       {"edge-lost"},
		"confirm_revoke": {"no"},
		"force":          {"yes"},
		"csrf_token":     {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers/edge-lost/revoke", unconfirmed)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unconfirmed force revoke status = %d, want 403", response.Code)
	}

	force := url.Values{
		"agent_id":       {"edge-lost"},
		"confirm_revoke": {"yes"},
		"force":          {"yes"},
		"csrf_token":     {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers/edge-lost/revoke", force)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/servers" {
		t.Fatalf(
			"force revoke response = %d %q",
			response.Code,
			response.Header().Get("Location"),
		)
	}
	if !fixture.controller.revokeForce {
		t.Fatal("force revoke did not reach the controller as a forced removal")
	}
	if _, err := fixture.registry.PublicKey(context.Background(), "edge-lost"); !errors.Is(err, identity.ErrAgentNotFound) {
		t.Fatalf("force-revoked identity remains: %v", err)
	}
}

func TestRevokeServerForceRejectsOnlineAgent(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	// edge-online holds a live session in the fixture.
	enrollAgent(t, fixture.registry, "edge-online")
	if _, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name:      "Cinema",
		RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(
		fixture.proxyNodes.Snapshot().Revision,
		[]string{"edge-online"},
	); err != nil {
		t.Fatal(err)
	}

	// A reachable Server must retire through the ordinary topology path, so
	// the blocked page must not offer force removal.
	request := fixture.authenticatedRequest(http.MethodGet, "/servers/edge-online/manage", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if strings.Contains(response.Body.String(), `name="force"`) {
		t.Fatal("online referenced server page exposed the force-removal form")
	}

	form := url.Values{
		"agent_id":       {"edge-online"},
		"confirm_revoke": {"yes"},
		"force":          {"yes"},
		"csrf_token":     {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers/edge-online/revoke", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), "enrolled and offline") {
		t.Fatalf("online force revoke response = %d %q", response.Code, response.Body.String())
	}
	if _, err := fixture.registry.PublicKey(context.Background(), "edge-online"); err != nil {
		t.Fatalf("rejected force revoke removed identity: %v", err)
	}
	if !fixture.controller.sessions["edge-online"] {
		t.Fatal("rejected force revoke disconnected the online Agent")
	}
}

func TestServerPageListsProxyNodeAssignmentsAndBlocksReferencedRemoval(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	for _, agentID := range []string{"edge-online", "edge-root", "edge-alt"} {
		enrollAgent(t, fixture.registry, agentID)
	}
	retiring, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name:      "Cinema",
		RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "cinema.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name:      "Archive Route",
		RootAgent: "edge-root",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "archive.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, relayHop, err := fixture.proxyNodes.AddLink(relay.ID, proxynode.AddLinkInput{
		ParentHopID: relay.Entrance.HopID,
		ChildAgent:  "edge-online",
		Endpoint: proxynode.Endpoint{
			Protocol: proxynode.ProtocolShadowsocks, Listen: "::", ListenPort: 20048,
			Method: "2022-blake3-aes-128-gcm",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MarkTopologyApplied(
		fixture.proxyNodes.Snapshot().Revision,
		[]string{"edge-online", "edge-root"},
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.MoveHop(retiring.ID, retiring.Entrance.HopID, "edge-alt"); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/servers/edge-online/manage", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if env.Data.Agent == nil || !env.Data.Agent.RemovalBlocked || len(env.Data.Agent.ProxyNodeReferences) != 2 {
		t.Fatalf("referenced server page = %+v", env.Data.Agent)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Cinema",
		"Archive Route",
		"1 Relay Hop",
		proxyNodeURL(retiring.ID),
		proxyNodeURL(relay.ID),
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("referenced server page omitted %q", expected)
		}
	}
	for _, hopID := range []string{retiring.Entrance.HopID, relayHop.ID} {
		if strings.Contains(body, hopID) {
			t.Fatalf("referenced server page exposed internal Hop ID %q", hopID)
		}
	}

	form := url.Values{
		"agent_id":       {"edge-online"},
		"confirm_revoke": {"yes"},
		"csrf_token":     {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers/edge-online/revoke", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), "This Server is still used by one or more Proxy Nodes") {
		t.Fatalf("referenced removal response = %d %q", response.Code, response.Body.String())
	}
	if _, err := fixture.registry.PublicKey(context.Background(), "edge-online"); err != nil {
		t.Fatalf("blocked removal revoked the Agent identity: %v", err)
	}
	if !fixture.controller.sessions["edge-online"] {
		t.Fatal("blocked removal disconnected the Agent")
	}

	request = fixture.authenticatedRequestWithLocale(http.MethodGet, "/servers/edge-online/manage", "", localeSimplifiedChinese)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	zhEnv := decodeSPA(t, response)
	if zhEnv.Locale != localeSimplifiedChinese || !strings.Contains(response.Body.String(), "1 个中继节点") {
		t.Fatalf("localized assignment UI = %+v body=%q", zhEnv, response.Body.String())
	}
}

func TestCreateServerRequiresCSRFAndRevealsCommandOnce(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	request := fixture.authenticatedRequest(http.MethodGet, "/servers/new", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.View != "new-server" || env.Data.TTLSeconds <= 0 {
		t.Fatalf("new server form = %d %+v", response.Code, env)
	}

	form := url.Values{
		"display_name": {"巴黎 边缘"},
		"csrf_token":   {fixture.session.CSRFToken},
		"ttl_seconds":  {"900"},
	}.Encode()

	request = fixture.authenticatedRequest(http.MethodPost, "/servers", form)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("mutation without Origin status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if len(fixture.registry.Snapshot(fixture.now)) != 0 {
		t.Fatal("cross-site request created a server entry")
	}

	badCSRF := url.Values{
		"display_name": {"巴黎 边缘"},
		"csrf_token":   {strings.Repeat("A", encodedCredentialLength)},
		"ttl_seconds":  {"900"},
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
	if !strings.Contains(response.Body.String(), "already in use") {
		t.Fatal("duplicate server display name was not explained")
	}

	request = fixture.authenticatedRequest(http.MethodGet, resultLocation, "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("result GET status = %d, body = %s", response.Code, response.Body.String())
	}
	createdEnv := decodeSPA(t, response)
	if createdEnv.View != "server-created" || createdEnv.Data.Created == nil || createdEnv.Data.Created.DisplayName != "巴黎 边缘" {
		t.Fatalf("created page = %+v", createdEnv)
	}
	installCmd := createdEnv.Data.Created.InstallCommand
	if !strings.Contains(installCmd, "--master 'master.example.com:8443'") {
		t.Errorf("install command missing master flag: %q", installCmd)
	}
	if strings.Contains(installCmd, "--agent-id") {
		t.Fatal("token-only enrollment command redundantly contains an agent ID")
	}
	tokenPattern := regexp.MustCompile(`--token '([A-Za-z0-9_-]{43})'`)
	match := tokenPattern.FindStringSubmatch(installCmd)
	if len(match) != 2 {
		t.Fatalf("created page does not contain one valid enrollment token: %q", installCmd)
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
		!strings.HasPrefix(snapshots[0].ID, "agt_") ||
		snapshots[0].DisplayName != "巴黎 边缘" ||
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

func TestEnhancedEnrollmentDefersOneTimeResultUntilNavigation(t *testing.T) {
	t.Parallel()
	for _, replacement := range []bool{false, true} {
		name := "new server"
		if replacement {
			name = "replacement"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newWebFixture(t)
			form := url.Values{
				"csrf_token": {fixture.session.CSRFToken}, "ttl_seconds": {"900"},
			}
			action := "/servers"
			if replacement {
				enrollAgent(t, fixture.registry, "edge-replacement")
				action = "/servers/edge-replacement/replace"
				form.Set("agent_id", "edge-replacement")
			} else {
				form.Set("display_name", "New Edge")
			}
			request := fixture.authenticatedMutationRequest(http.MethodPost, action, form.Encode())
			request.Header.Set("X-Theatropolis-Form", "1")
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			location := response.Header().Get("X-Theatropolis-Redirect")
			if response.Code != http.StatusNoContent ||
				!strings.HasPrefix(location, "/servers/enrollment-result?id=") ||
				response.Header().Get("Location") != "" || response.Body.Len() != 0 {
				t.Fatalf("enhanced enrollment status=%d, headers=%v, body=%q", response.Code, response.Header(), response.Body.String())
			}

			request = fixture.authenticatedRequest(http.MethodGet, location, "")
			response = httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			createdEnv := decodeSPA(t, response)
			if response.Code != http.StatusOK || createdEnv.Data.Created == nil ||
				!regexp.MustCompile(`--token '[A-Za-z0-9_-]{43}'`).MatchString(createdEnv.Data.Created.InstallCommand) {
				t.Fatalf("first navigation did not show the installation command: %d %+v", response.Code, createdEnv.Data.Created)
			}
			request = fixture.authenticatedRequest(http.MethodGet, location, "")
			response = httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/servers" {
				t.Fatalf("one-time result was not consumed: %d", response.Code)
			}
		})
	}
}

func TestEnrollmentFormRejectsExtraAndDuplicateFields(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	tests := map[string]url.Values{
		"extra": {
			"display_name": {"Edge 1"},
			"csrf_token":   {fixture.session.CSRFToken},
			"ttl_seconds":  {"900"},
			"surprise":     {"true"},
		},
		"duplicate": {
			"display_name": {"Edge 1", "Edge 2"},
			"csrf_token":   {fixture.session.CSRFToken},
			"ttl_seconds":  {"900"},
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

func TestServerDisplayNameRenameKeepsImmutableRecordID(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-rename")
	enrollAgent(t, fixture.registry, "edge-other")
	originalKey, err := fixture.registry.PublicKey(context.Background(), "edge-rename")
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"csrf_token":   {fixture.session.CSRFToken},
		"display_name": {"上海 中继"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/servers/edge-rename/rename", form)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/servers/edge-rename/manage" {
		t.Fatalf("rename response = %d %q", response.Code, response.Header().Get("Location"))
	}
	if got := fixture.registry.DisplayName("edge-rename"); got != "上海 中继" {
		t.Fatalf("display name = %q", got)
	}
	currentKey, err := fixture.registry.PublicKey(context.Background(), "edge-rename")
	if err != nil || !bytes.Equal(currentKey, originalKey) {
		t.Fatalf("rename changed enrolled identity: %v", err)
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/servers/edge-rename/manage", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Data.Agent == nil || env.Data.Agent.Name != "上海 中继" || env.Data.Agent.ID != "edge-rename" {
		t.Fatalf("renamed server page = %d, agent = %+v", response.Code, env.Data.Agent)
	}

	conflict := url.Values{
		"csrf_token":   {fixture.session.CSRFToken},
		"display_name": {"上海 中继"},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers/edge-other/rename", conflict)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "already in use") {
		t.Fatalf("duplicate rename response = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestEnrollmentResultIsBoundToCreatingSession(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	form := url.Values{
		"display_name": {"Session Bound"},
		"csrf_token":   {fixture.session.CSRFToken},
		"ttl_seconds":  {"900"},
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

func TestCreateServerRejectsRemovedDefaultTLSAddress(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	form := url.Values{
		"display_name":        {"No TLS Default"},
		"csrf_token":          {fixture.session.CSRFToken},
		"default_tls_address": {"Proxy.Example.COM."},
		"ttl_seconds":         {"900"},
	}.Encode()
	request := fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("removed field status = %d, body = %s", response.Code, response.Body.String())
	}
	if snapshots := fixture.registry.Snapshot(fixture.now); len(snapshots) != 0 {
		t.Fatalf("removed field created a server: %+v", snapshots)
	}
}

func TestPublicURLValidation(t *testing.T) {
	t.Parallel()

	valid := map[string]string{
		"https://master.example.com:8443": "master.example.com:8443",
		"https://master.example.com:443":  "master.example.com:443",
		"https://[2001:db8::1]:8443":      "[2001:db8::1]:8443",
		"http://localhost:19444":          "localhost:19444",
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
			"display_name": {fmt.Sprintf("Edge %d", index)},
			"csrf_token":   {fixture.session.CSRFToken},
			"ttl_seconds":  {"900"},
		}.Encode()
		request := fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusSeeOther {
			t.Fatalf("enrollment %d status = %d", index, response.Code)
		}
	}

	form := url.Values{
		"display_name": {"Limited Edge"},
		"csrf_token":   {fixture.session.CSRFToken},
		"ttl_seconds":  {"900"},
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
		"display_name": {"Storage Failure"},
		"csrf_token":   {fixture.session.CSRFToken},
		"ttl_seconds":  {"900"},
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
	entries, err := webFiles.ReadDir("dist/assets")
	if err != nil {
		t.Fatalf("read dist/assets: %v", err)
	}
	var jsCount, cssCount int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := "/assets/" + entry.Name()
		request := fixture.request(http.MethodGet, path, "")
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Body.Len() == 0 {
			t.Fatalf("%s response = %d (%d bytes)", path, response.Code, response.Body.Len())
		}
		contentType := response.Header().Get("Content-Type")
		switch {
		case strings.HasSuffix(entry.Name(), ".js"):
			jsCount++
			if !strings.HasPrefix(contentType, "text/javascript") && !strings.HasPrefix(contentType, "application/javascript") {
				t.Fatalf("%s Content-Type = %q", path, contentType)
			}
		case strings.HasSuffix(entry.Name(), ".css"):
			cssCount++
			if !strings.HasPrefix(contentType, "text/css") {
				t.Fatalf("%s Content-Type = %q", path, contentType)
			}
		}
		assertSecurityHeaders(t, response.Header())
	}
	if jsCount == 0 || cssCount == 0 {
		t.Fatalf("expected embedded JS and CSS bundles, got js=%d css=%d", jsCount, cssCount)
	}
	for _, retired := range []string{"/assets/app.js", "/assets/dropdown.js", "/assets/i18n.js", "/assets/subscription-rules.js", "/assets/app.css"} {
		request := fixture.request(http.MethodGet, retired, "")
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("retired asset %s status = %d, want 404", retired, response.Code)
		}
		assertSecurityHeaders(t, response.Header())
	}

	messagesReq := fixture.requestWithLocale(http.MethodGet, "/api/messages", "", localeSimplifiedChinese)
	messagesRes := httptest.NewRecorder()
	fixture.handler.ServeHTTP(messagesRes, messagesReq)
	if messagesRes.Code != http.StatusOK {
		t.Fatalf("GET /api/messages = %d", messagesRes.Code)
	}
	for _, expected := range []string{
		`"Listener conflict":"监听器冲突"`,
		`"TLS certificate domain/IP":"TLS 证书域名/IP"`,
	} {
		if !strings.Contains(messagesRes.Body.String(), expected) {
			t.Errorf("localized message catalog does not contain %q", expected)
		}
	}
	assertSecurityHeaders(t, messagesRes.Header())

	request := fixture.request(http.MethodGet, "/not-found", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want %d", response.Code, http.StatusNotFound)
	}
	assertSecurityHeaders(t, response.Header())
}

func TestProxyTreeFallbackTerminalsShareConnectorStyle(t *testing.T) {
	t.Parallel()

	entries, err := webFiles.ReadDir("dist/assets")
	if err != nil {
		t.Fatalf("read dist/assets: %v", err)
	}
	var css strings.Builder
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".css") {
			data, readErr := webFiles.ReadFile("dist/assets/" + entry.Name())
			if readErr != nil {
				t.Fatal(readErr)
			}
			css.Write(data)
		}
	}
	if !strings.Contains(css.String(), ".proxy-map__link:after,.proxy-map__route-label:after") &&
		!strings.Contains(css.String(), ".proxy-map__link::after,.proxy-map__route-label::after") &&
		!strings.Contains(css.String(), ".proxy-map__link::after,\n.proxy-map__route-label::after") {
		t.Fatal("fallback terminal labels do not share the Link-to-node connector style in built CSS")
	}
}

func TestEndUserInvitationClaimPortalAndLoginReset(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	user, err := fixture.proxyNodes.CreateUser("Alice-Customer")
	if err != nil {
		t.Fatal(err)
	}
	originalSubscriptionToken := user.Subscription.Token

	form := url.Values{
		"csrf_token":    {fixture.session.CSRFToken},
		"confirm_reset": {""},
	}
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/users/"+url.PathEscape(user.ID)+"/login/invitation",
		form.Encode(),
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("issue invitation = %d %q", response.Code, response.Body.String())
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/users/"+url.PathEscape(user.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Invitation ready") {
		t.Fatalf("user page after invitation = %d %q", response.Code, response.Body.String())
	}
	match := regexp.MustCompile(`/claim/([A-Za-z0-9_-]{43})`).FindStringSubmatch(response.Body.String())
	if len(match) != 2 {
		t.Fatalf("user page did not reveal the session-bound invitation URL: %q", response.Body.String())
	}
	invitationToken := match[1]

	form = url.Values{
		"csrf_token":    {fixture.session.CSRFToken},
		"confirm_reset": {""},
	}
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/users/"+url.PathEscape(user.ID)+"/login/invitation",
		form.Encode(),
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !fixture.endUsers.InvitationValid(invitationToken) {
		t.Fatalf("unconfirmed registration reset = %d, invitation valid = %t", response.Code, fixture.endUsers.InvitationValid(invitationToken))
	}

	form.Set("confirm_reset", "yes")
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/users/"+url.PathEscape(user.ID)+"/login/invitation",
		form.Encode(),
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("confirmed registration reset = %d %q", response.Code, response.Body.String())
	}
	if fixture.endUsers.InvitationValid(invitationToken) {
		t.Fatal("registration reset left the previous token valid")
	}
	request = fixture.authenticatedRequest(http.MethodGet, "/users/"+url.PathEscape(user.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	match = regexp.MustCompile(`/claim/([A-Za-z0-9_-]{43})`).FindStringSubmatch(response.Body.String())
	if len(match) != 2 {
		t.Fatalf("registration reset did not reveal the new invitation URL: %q", response.Body.String())
	}
	invitationToken = match[1]

	request = fixture.request(http.MethodGet, "/claim/"+invitationToken, "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/claim" {
		t.Fatalf("claim token exchange = %d %q", response.Code, response.Header().Get("Location"))
	}
	if got := response.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("claim token exchange Referrer-Policy = %q, want no-referrer", got)
	}
	claimCookie := response.Result().Cookies()[0]
	if claimCookie.Name != EndUserClaimCookieName || !claimCookie.HttpOnly || !claimCookie.Secure {
		t.Fatalf("claim cookie = %+v", claimCookie)
	}

	request = fixture.request(http.MethodGet, "/claim", "")
	request.AddCookie(claimCookie)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("claim form = %d %q", response.Code, response.Body.String())
	}
	claimEnv := decodeSPA(t, response)
	if claimEnv.View != "portal-claim" || claimEnv.Data.EndUserLogin == nil || claimEnv.Data.EndUserLogin.Unavailable {
		t.Fatalf("claim form = %+v", claimEnv)
	}
	if got := response.Header().Get("Referrer-Policy"); got != "strict-origin" {
		t.Fatalf("claim form Referrer-Policy = %q, want strict-origin", got)
	}

	form = url.Values{
		"username":              {"alice.portal"},
		"password":              {testEndUserPassword},
		"password_confirmation": {testEndUserPassword},
	}
	request = fixture.mutationRequest(http.MethodPost, "/claim", form.Encode())
	request.AddCookie(claimCookie)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/portal" {
		t.Fatalf("claim invitation = %d %q", response.Code, response.Body.String())
	}
	var portalCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == EndUserSessionCookieName && cookie.MaxAge >= 0 {
			portalCookie = cookie
			break
		}
	}
	if portalCookie == nil || !portalCookie.HttpOnly || !portalCookie.Secure {
		t.Fatalf("portal session cookie was not issued: %+v", response.Result().Cookies())
	}

	request = fixture.request(http.MethodGet, "/portal", "")
	request.AddCookie(portalCookie)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	portalEnv := decodeSPA(t, response)
	if response.Code != http.StatusOK || portalEnv.View != "portal" ||
		portalEnv.Data.EndUserPortal == nil ||
		portalEnv.Data.EndUserPortal.LoginUsername != "alice.portal" ||
		len(portalEnv.Data.EndUserPortal.Nodes) != 0 {
		t.Fatalf("end-user portal = %d %+v", response.Code, portalEnv)
	}

	request = fixture.authenticatedRequest(http.MethodGet, "/users/"+url.PathEscape(user.ID), "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "alice.portal") ||
		!strings.Contains(response.Body.String(), "Registered") {
		t.Fatalf("operator user page after claim = %d %q", response.Code, response.Body.String())
	}

	form = url.Values{
		"csrf_token":    {fixture.session.CSRFToken},
		"confirm_reset": {"yes"},
	}
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/users/"+url.PathEscape(user.ID)+"/login/invitation",
		form.Encode(),
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("reset end-user login = %d %q", response.Code, response.Body.String())
	}
	currentUser, exists := fixture.proxyNodes.User(user.ID)
	if !exists || currentUser.Subscription.Token != originalSubscriptionToken {
		t.Fatalf("login reset changed subscription identity: %+v", currentUser)
	}

	request = fixture.request(http.MethodGet, "/portal", "")
	request.AddCookie(portalCookie)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/portal/login" {
		t.Fatalf("old portal session after reset = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestEndUserClaimHasIndependentRateLimit(t *testing.T) {
	t.Parallel()
	fixture := newWebFixture(t)
	user, err := fixture.proxyNodes.CreateUser("Rate-Limited-Customer")
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := fixture.endUsers.IssueInvitation(user.ID, defaultUserInviteLifetime)
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.request(http.MethodGet, "/claim/"+token, "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("claim token exchange = %d", response.Code)
	}
	claimCookie := response.Result().Cookies()[0]
	claimHandler := fixture.handler.(*Handler)
	claimHandler.claimLimiter = newFixedWindowLimiter(1, time.Minute)
	form := url.Values{
		"username":              {"rate.user"},
		"password":              {testEndUserPassword},
		"password_confirmation": {"different-password-long-enough"},
	}
	request = fixture.mutationRequest(http.MethodPost, "/claim", form.Encode())
	request.AddCookie(claimCookie)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("first claim attempt = %d %q", response.Code, response.Body.String())
	}
	request = fixture.mutationRequest(http.MethodPost, "/claim", form.Encode())
	request.AddCookie(claimCookie)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "60" {
		t.Fatalf("limited claim attempt = %d retry-after=%q", response.Code, response.Header().Get("Retry-After"))
	}
}

func TestEndUserPortalLanguageSwitchReturnsToPortalRealm(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	request := fixture.requestWithLocale(http.MethodGet, "/portal/login", "", localeSimplifiedChinese)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	env := decodeSPA(t, response)
	if response.Code != http.StatusOK || env.Locale != localeSimplifiedChinese ||
		env.View != "portal-login" || env.Data.EndUserLogin == nil ||
		env.Data.EndUserLogin.ReturnTo != "/portal/login" {
		t.Fatalf("localized portal login = %d %+v", response.Code, env)
	}

	request = fixture.request(http.MethodGet, "/language/zh-CN?return_to=/portal/login", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/portal/login" {
		t.Fatalf("portal language redirect = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestMembershipPlanUsesExactTransitionInstantsWithoutFixedZoneLabels(t *testing.T) {
	t.Parallel()

	lastQuotaDate := time.Date(2026, time.September, 26, 0, 0, 0, 0, proxynode.BillingLocation())
	expiresAt := time.Date(2026, time.October, 27, 0, 0, 0, 0, proxynode.BillingLocation())
	plan := membershipPlanViewFor(proxynode.Membership{
		QuotaResetsAfter:      lastQuotaDate,
		SubscriptionEndsAfter: expiresAt,
		SubscriptionValue:     1,
		SubscriptionUnit:      proxynode.SubscriptionMonths,
	})
	localizeMembershipPlan(localeSimplifiedChinese, &plan)

	if plan.ResetLabel != "2026年9月27日 00:00" || plan.ResetAt != "2026-09-27T00:00:00+08:00" {
		t.Fatalf("localized reset date = %q", plan.ResetLabel)
	}
	if plan.ExpirationLabel != "2026年10月27日 00:00" || plan.ExpirationAt != "2026-10-27T00:00:00+08:00" {
		t.Fatalf("localized expiration date = %q", plan.ExpirationLabel)
	}
	if strings.Contains(plan.ResetLabel+plan.ExpirationLabel, "UTC+8") {
		t.Fatalf("membership transition labels expose the billing timezone: reset=%q expiration=%q", plan.ResetLabel, plan.ExpirationLabel)
	}
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
	proxyNodes, err := proxynode.Open(
		filepath.Join(t.TempDir(), "proxy-node-state.json"),
		proxynode.BuildInfo{Component: "master", Version: "test", Commit: "test"},
	)
	if err != nil {
		t.Fatal(err)
	}
	endUserDirectory := t.TempDir()
	endUsers, err := openEndUserAccessWithPasswordDeriver(
		filepath.Join(endUserDirectory, "end-user-auth.json"),
		filepath.Join(endUserDirectory, "end-user-sessions.json"),
		fastTestPasswordDeriver,
		nilSafeRandomReader{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := endUsers.Close(); err != nil {
			t.Errorf("close end-user access: %v", err)
		}
	})
	endUsers.now = func() time.Time { return now }
	endUsers.passwordKDFLimiter = newPasswordKDFLimiter(1, 8, time.Second)
	migration := &testMasterMigrationService{}
	restarts := make(chan struct{}, 1)
	handler, err := New(Options{
		Registry:   registry,
		Sessions:   sessions,
		Controller: controller,
		Access:     access,
		Releases: testReleaseCatalog{releases: []AgentRelease{
			{Tag: "v1.14.0-beta.7", Prerelease: true},
		}},
		PublicURL:       testPublicURL,
		Version:         "test",
		Now:             func() time.Time { return now },
		ProxyNodes:      proxyNodes,
		EndUserAccess:   endUsers,
		MasterMigration: migration,
		RequestRestart: func() {
			select {
			case restarts <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return webFixture{
		handler:    handler,
		registry:   registry,
		controller: controller,
		proxyNodes: proxyNodes,
		access:     access,
		endUsers:   endUsers,
		username:   username,
		password:   password,
		session:    session,
		now:        now,
		migration:  migration,
		restarts:   restarts,
	}
}

func (f webFixture) request(method, path, body string) *http.Request {
	return f.requestWithLocale(method, path, body, localeEnglish)
}

func (f webFixture) requestWithoutLocale(method, path, body string) *http.Request {
	return f.requestWithLocale(method, path, body, "")
}

func (f webFixture) requestWithLocale(method, path, body, locale string) *http.Request {
	request := httptest.NewRequest(method, testPublicURL+path, strings.NewReader(body))
	request.Host = "master.example.com:8443"
	if body != "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if locale != "" {
		request.AddCookie(&http.Cookie{Name: languageCookieName, Value: locale})
	}
	return request
}

func (f webFixture) mutationRequest(method, path, body string) *http.Request {
	request := f.request(method, path, body)
	request.Header.Set("Origin", testPublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	return request
}

func (f webFixture) mutationRequestWithoutLocale(method, path, body string) *http.Request {
	request := f.requestWithoutLocale(method, path, body)
	request.Header.Set("Origin", testPublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	return request
}

func (f webFixture) authenticatedRequest(method, path, body string) *http.Request {
	request := f.request(method, path, body)
	request.AddCookie(NewSessionCookie(f.session.Token, f.session.ExpiresAt))
	return request
}

func (f webFixture) authenticatedRequestWithLocale(method, path, body, locale string) *http.Request {
	request := f.requestWithLocale(method, path, body, locale)
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
	if enrolledAgentID, err := registry.EnrollByToken(
		context.Background(),
		token,
		publicKey,
		time.Now(),
	); err != nil {
		t.Fatal(err)
	} else if enrolledAgentID != agentID {
		t.Fatalf("enrolled Agent ID = %q, want %q", enrolledAgentID, agentID)
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

func TestLoginClientIdentityUsesProxyAppendedAddress(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPost, testPublicURL+"/login", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set(
		"X-Forwarded-For",
		"192.0.2.99, 198.51.100.24",
	)
	if got := loginClientIdentity(request); got != "198.51.100.24" {
		t.Fatalf("loginClientIdentity() = %q", got)
	}
}

func TestLoginClientIdentityFallsBackToRemoteAddress(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPost, testPublicURL+"/login", nil)
	request.RemoteAddr = "[2001:db8::24]:12345"
	request.Header.Set("X-Forwarded-For", "invalid")
	if got := loginClientIdentity(request); got != "2001:db8::24" {
		t.Fatalf("loginClientIdentity() = %q", got)
	}
}

func netJoinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
