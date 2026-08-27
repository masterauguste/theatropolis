package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/pool"
)

const poolTestConfig = `{"inbounds":[{"type":"hysteria2","tag":"hy2-in","listen_port":8443,"users":[{"name":"alice","password":"secret"}]}],"outbounds":[]}`

func openTestPoolRegistry(t *testing.T) *pool.Registry {
	t.Helper()
	registry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func newPoolFixture(t *testing.T) webFixture {
	t.Helper()
	fixture := newWebFixture(t)
	fixture.controller.poolRegistry = openTestPoolRegistry(t)
	return fixture
}

func seedPoolDeployment(t *testing.T, fixture webFixture, agentID, config string) {
	t.Helper()
	record, err := deployment.New(
		"dep_"+agentID,
		agentID,
		"rev_"+agentID,
		[]byte(config),
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.controller.store.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
}

func TestServerPoolOptionsEndpoint(t *testing.T) {
	t.Parallel()

	fixture := newPoolFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-source")
	enrollAgent(t, fixture.registry, "edge-quiet")
	seedPoolDeployment(t, fixture, "edge-source", poolTestConfig)
	seedPoolDeployment(t, fixture, "edge-quiet", poolTestConfig)
	registry := fixture.controller.poolRegistry
	if _, err := registry.SetReported(
		"edge-source",
		[]string{"203.0.113.7"},
		[]string{"2001:db8::7"},
	); err != nil {
		t.Fatal(err)
	}
	if err := registry.UpsertManual("backup", json.RawMessage(`{"type":"direct"}`)); err != nil {
		t.Fatal(err)
	}
	if err := registry.SetDefaultTLSAddress("edge-source", "tls-source.example.com"); err != nil {
		t.Fatal(err)
	}

	request := fixture.request(
		http.MethodGet,
		"/servers/edge-online/pool-options",
		"",
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated pool options status = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/unknown/pool-options",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown agent pool options status = %d, want %d", response.Code, http.StatusNotFound)
	}

	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/pool-options",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("pool options status = %d, body = %s", response.Code, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("pool options Content-Type = %q", contentType)
	}
	for _, expected := range []string{
		`"ipv4":"203.0.113.7"`,
		`"ipv6":"2001:db8::7"`,
		`"available":true`,
		`"available":false`,
	} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("pool options JSON does not contain %q", expected)
		}
	}
	var result poolOptionsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode pool options: %v", err)
	}
	byRef := make(map[string]poolOption, len(result.Options))
	for _, option := range result.Options {
		byRef[option.Ref] = option
	}
	source, exists := byRef["agent/edge-source/hy2-in/alice"]
	if !exists {
		t.Fatalf("pool options missing edge-source entry: %+v", result.Options)
	}
	if !source.Available || source.IPv4 != "203.0.113.7" || source.IPv6 != "2001:db8::7" ||
		source.Type != "hysteria2" || source.Port != 8443 ||
		source.AgentID != "edge-source" || source.InboundTag != "hy2-in" ||
		source.User != "alice" || source.DefaultTLSAddress != "tls-source.example.com" ||
		source.Manual {
		t.Fatalf("unexpected edge-source option: %+v", source)
	}
	quiet, exists := byRef["agent/edge-quiet/hy2-in/alice"]
	if !exists || quiet.Available || quiet.IPv4 != "" || quiet.IPv6 != "" {
		t.Fatalf("edge-quiet option should be present and unavailable: %+v", quiet)
	}
	manual, exists := byRef["manual/backup"]
	if !exists || !manual.Manual || !manual.Available || manual.Type != "direct" {
		t.Fatalf("unexpected manual option: %+v", manual)
	}

	// The requesting agent never imports its own inbounds.
	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-source/pool-options",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("self pool options status = %d, body = %s", response.Code, response.Body.String())
	}
	result = poolOptionsResponse{}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode self pool options: %v", err)
	}
	for _, option := range result.Options {
		if option.AgentID == "edge-source" {
			t.Fatalf("pool options offered the agent its own entry: %+v", option)
		}
	}
	if len(result.Options) != 2 {
		t.Fatalf("self pool options count = %d, want 2 (edge-quiet + manual)", len(result.Options))
	}
}

func TestServerDefaultTLSAddressSettings(t *testing.T) {
	t.Parallel()

	fixture := newPoolFixture(t)
	enrollAgent(t, fixture.registry, "edge-settings")
	form := url.Values{
		"csrf_token":          {fixture.session.CSRFToken},
		"default_tls_address": {"Tls.Edge.Example."},
	}.Encode()
	request := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-settings/tls-address",
		form,
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/servers/edge-settings/manage" {
		t.Fatalf(
			"save TLS address response = %d %q, body = %s",
			response.Code,
			response.Header().Get("Location"),
			response.Body.String(),
		)
	}
	if got := fixture.controller.poolRegistry.DefaultTLSAddress("edge-settings"); got != "tls.edge.example" {
		t.Fatalf("DefaultTLSAddress() = %q, want tls.edge.example", got)
	}

	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-settings/manage",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `value="tls.edge.example"`) {
		t.Fatalf("server settings page = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestPoolPageCRUD(t *testing.T) {
	t.Parallel()

	fixture := newPoolFixture(t)

	request := fixture.authenticatedRequest(http.MethodGet, "/pool", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /pool status = %d, body = %s", response.Code, response.Body.String())
	}
	for _, expected := range []string{
		"Fleet outbound pool",
		`data-async-url="/pool/content"`,
		"Loading fleet outbounds…",
		`action="/pool"`,
		`name="outbound_json"`,
		`name="remark"`,
		"No manual entries yet.",
	} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("pool page does not contain %q", expected)
		}
	}
	if strings.Contains(response.Body.String(), `href="/pool" class="is-active"`) {
		t.Fatal("legacy pool page is still present in primary navigation")
	}
	if fixture.controller.deploymentListCalls != 0 {
		t.Fatalf(
			"GET /pool loaded deployment records before rendering: %d calls",
			fixture.controller.deploymentListCalls,
		)
	}

	// The old settings-page pool routes are gone.
	oldForm := url.Values{
		"csrf_token":    {fixture.session.CSRFToken},
		"name":          {"backup"},
		"remark":        {""},
		"outbound_json": {`{"type":"direct"}`},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/settings/pool", oldForm)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound && response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("removed /settings/pool route status = %d, want 404 or 405", response.Code)
	}

	validForm := url.Values{
		"csrf_token":    {fixture.session.CSRFToken},
		"name":          {"backup"},
		"remark":        {"Backup route"},
		"outbound_json": {`socks://operator:secret@proxy.example:1080#URI%20remark`},
	}.Encode()

	// Origin enforcement.
	request = fixture.authenticatedRequest(http.MethodPost, "/pool", validForm)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("pool upsert without Origin status = %d, want 403", response.Code)
	}

	// CSRF enforcement.
	badCSRF := url.Values{
		"csrf_token":    {"wrong"},
		"name":          {"backup"},
		"remark":        {""},
		"outbound_json": {`{"type":"direct"}`},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/pool", badCSRF)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("pool upsert with bad CSRF status = %d, want 403", response.Code)
	}

	// Valid upsert.
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/pool", validForm)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/pool" {
		t.Fatalf("pool upsert response = %d %q", response.Code, response.Header().Get("Location"))
	}
	entry, exists := fixture.controller.poolRegistry.ManualByName("backup")
	if !exists || entry.Remark != "Backup route" ||
		!strings.Contains(string(entry.Outbound), `"type":"socks"`) ||
		!strings.Contains(string(entry.Outbound), `"server":"proxy.example"`) {
		t.Fatalf("pool upsert stored %+v (exists=%v)", entry, exists)
	}
	if fixture.controller.propagateCalls != 1 {
		t.Fatalf("propagation calls = %d, want 1", fixture.controller.propagateCalls)
	}

	// Validation errors re-render the pool page with the submitted values.
	badName := url.Values{
		"csrf_token":    {fixture.session.CSRFToken},
		"name":          {"bad name!"},
		"remark":        {""},
		"outbound_json": {`{"type":"direct"}`},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/pool", badName)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("bad-name pool upsert status = %d, want 400", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "Use a valid entry name") ||
		!strings.Contains(body, `value="bad name!"`) {
		t.Fatalf("bad-name pool upsert did not re-render the error: %s", body)
	}

	badJSON := url.Values{
		"csrf_token":    {fixture.session.CSRFToken},
		"name":          {"relay"},
		"remark":        {""},
		"outbound_json": {`{"tag":"x"}`},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/pool", badJSON)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("bad-JSON pool upsert status = %d, want 400", response.Code)
	}
	if !strings.Contains(response.Body.String(), "Enter one complete outbound JSON object") {
		// The validation copy also calls out the new URI import path.
		if !strings.Contains(response.Body.String(), "supported proxy URI") {
			t.Fatalf("bad-JSON pool upsert did not re-render the error: %s", response.Body.String())
		}
	}
	if fixture.controller.propagateCalls != 1 {
		t.Fatalf("failed upserts triggered propagation: %d calls", fixture.controller.propagateCalls)
	}

	// The saved entry is listed with a delete form.
	request = fixture.authenticatedRequest(http.MethodGet, "/pool", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	for _, expected := range []string{"manual/backup", `action="/pool/delete"`, `name="confirm_delete"`} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("pool page list does not contain %q", expected)
		}
	}

	// Delete requires the explicit confirmation.
	deleteForm := url.Values{
		"confirm_delete": {"no"},
		"csrf_token":     {fixture.session.CSRFToken},
		"name":           {"backup"},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/pool/delete", deleteForm)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unconfirmed pool delete status = %d, want 403", response.Code)
	}
	if _, exists := fixture.controller.poolRegistry.ManualByName("backup"); !exists {
		t.Fatal("unconfirmed pool delete removed the entry")
	}

	deleteForm = url.Values{
		"confirm_delete": {"yes"},
		"csrf_token":     {fixture.session.CSRFToken},
		"name":           {"backup"},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/pool/delete", deleteForm)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/pool" {
		t.Fatalf("pool delete response = %d %q", response.Code, response.Header().Get("Location"))
	}
	if _, exists := fixture.controller.poolRegistry.ManualByName("backup"); exists {
		t.Fatal("pool delete kept the entry")
	}
	if fixture.controller.propagateCalls != 2 {
		t.Fatalf("propagation calls = %d, want 2", fixture.controller.propagateCalls)
	}

	// Deleting a missing entry re-renders with a 404.
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/pool/delete", deleteForm)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound ||
		!strings.Contains(response.Body.String(), "no longer exists") {
		t.Fatalf("missing pool delete = %d %s", response.Code, response.Body.String())
	}
}

func TestServerAddressOverride(t *testing.T) {
	t.Parallel()

	fixture := newPoolFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-offline")
	seedPoolDeployment(t, fixture, "edge-online", poolTestConfig)
	seedPoolDeployment(t, fixture, "edge-offline", poolTestConfig)
	if _, err := fixture.controller.poolRegistry.SetReported(
		"edge-offline",
		[]string{"192.0.2.9"},
		[]string{"2001:db8::9"},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.registry.CreateEnrollment(
		context.Background(),
		"edge-pending",
		time.Now().Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}

	// The servers page shows connection establishment plus independently
	// resolved IPv4 and IPv6 addresses, with no override form.
	request := fixture.authenticatedRequest(http.MethodGet, "/servers/content", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /servers/content status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{
		`<code class="pool-address-line">192.0.2.9</code>`,
		`<code class="pool-address-line">2001:db8::9</code>`,
		`Established`,
		`Not established`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("servers page does not contain %q", expected)
		}
	}
	for _, unexpected := range []string{
		`name="override_ipv4"`,
		`name="override_ipv6"`,
		"Connected from:",
		"Last known address:",
		"IPv4 <code>",
		"IPv6 <code>",
		"(reported)",
	} {
		if strings.Contains(body, unexpected) {
			t.Errorf("servers page still contains %q", unexpected)
		}
	}

	// The override form lives in each pool summary dialog, and the displayed
	// addresses deliberately omit their internal source attribution.
	request = fixture.authenticatedRequest(http.MethodGet, "/pool/content", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /pool/content status = %d, body = %s", response.Code, response.Body.String())
	}
	for _, expected := range []string{
		`action="/servers/edge-online/address"`,
		`action="/servers/edge-offline/address"`,
		`name="override_ipv4"`,
		`name="override_ipv6"`,
		`<code>192.0.2.9</code>`,
		`<code>2001:db8::9</code>`,
	} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("pool page does not contain %q", expected)
		}
	}

	if strings.Contains(response.Body.String(), "(reported)") {
		t.Error("pool page exposes address source attribution")
	}

	form := url.Values{
		"override_ipv4": {"198.51.100.9"},
		"override_ipv6": {"2001:db8::99"},
		"csrf_token":    {fixture.session.CSRFToken},
	}.Encode()

	// Origin and CSRF enforcement.
	request = fixture.authenticatedRequest(
		http.MethodPost,
		"/servers/edge-online/address",
		form,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("address override without Origin status = %d, want 403", response.Code)
	}
	badCSRF := url.Values{
		"override_ipv4": {"198.51.100.9"},
		"override_ipv6": {""},
		"csrf_token":    {"wrong"},
	}.Encode()
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/address",
		badCSRF,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("address override with bad CSRF status = %d, want 403", response.Code)
	}

	// Each address must parse as its declared family or be empty.
	invalid := url.Values{
		"override_ipv4": {"2001:db8::1"},
		"override_ipv6": {""},
		"csrf_token":    {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/address",
		invalid,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid address status = %d, want 400", response.Code)
	}

	// Private/ULA overrides are rejected by the registry as non-routable.
	for _, testCase := range []struct {
		v4 string
		v6 string
	}{
		{v4: "10.0.0.8"},
		{v4: "192.168.1.2"},
		{v4: "100.64.0.9"},
		{v6: "fd12:3456::1"},
	} {
		private := url.Values{
			"override_ipv4": {testCase.v4},
			"override_ipv6": {testCase.v6},
			"csrf_token":    {fixture.session.CSRFToken},
		}.Encode()
		request = fixture.authenticatedMutationRequest(
			http.MethodPost,
			"/servers/edge-online/address",
			private,
		)
		response = httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("private overrides %q/%q status = %d, want 400", testCase.v4, testCase.v6, response.Code)
		}
	}

	// Valid independent family overrides.
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/address",
		form,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/pool" {
		t.Fatalf("address override response = %d %q", response.Code, response.Header().Get("Location"))
	}
	ipv4, ok := fixture.controller.poolRegistry.AgentAddressForFamily("edge-online", pool.FamilyIPv4)
	if !ok || ipv4 != "198.51.100.9" {
		t.Fatalf("resolved IPv4 = %q (ok=%v), want 198.51.100.9", ipv4, ok)
	}
	ipv6, ok := fixture.controller.poolRegistry.AgentAddressForFamily("edge-online", pool.FamilyIPv6)
	if !ok || ipv6 != "2001:db8::99" {
		t.Fatalf("resolved IPv6 = %q (ok=%v), want 2001:db8::99", ipv6, ok)
	}
	if fixture.controller.propagateCalls != 1 {
		t.Fatalf("propagation calls = %d, want 1", fixture.controller.propagateCalls)
	}

	// Both pages reflect both overrides without exposing source labels.
	request = fixture.authenticatedRequest(http.MethodGet, "/servers/content", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), `<code class="pool-address-line">198.51.100.9</code>`) ||
		!strings.Contains(response.Body.String(), `<code class="pool-address-line">2001:db8::99</code>`) {
		t.Errorf("servers page does not reflect the override: %s", response.Body.String())
	}
	request = fixture.authenticatedRequest(http.MethodGet, "/pool/content", "")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), `value="198.51.100.9"`) ||
		!strings.Contains(response.Body.String(), `value="2001:db8::99"`) ||
		strings.Contains(response.Body.String(), "(override)") {
		t.Errorf("pool page does not reflect the override: %s", response.Body.String())
	}

	// An empty submission clears both overrides.
	clearForm := url.Values{
		"override_ipv4": {""},
		"override_ipv6": {""},
		"csrf_token":    {fixture.session.CSRFToken},
	}.Encode()
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/address",
		clearForm,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("clear override status = %d, want 303", response.Code)
	}
	overrideV4, overrideV6 := fixture.controller.poolRegistry.Overrides("edge-online")
	if overrideV4 != "" || overrideV6 != "" {
		t.Fatalf("clearing overrides left %q/%q", overrideV4, overrideV6)
	}

	// Pending and unknown agents cannot take an override.
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-pending/address",
		form,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("pending agent override status = %d, want 409", response.Code)
	}
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/unknown/address",
		form,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown agent override status = %d, want 404", response.Code)
	}
}

func TestServerPageRoutesThroughProxyNodeManager(t *testing.T) {
	t.Parallel()

	fixture := newPoolFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")

	request := fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-online/manage",
		"",
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET server management status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Proxy Node roles",
		`href="/proxy-nodes"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("server management page does not contain %q", expected)
		}
	}
	for _, removed := range []string{
		`id="outbound-manager-dialog"`,
		`data-outbound-card`,
		`data-add-outbound`,
		`data-route-field="scope_type"`,
		`action="/servers/edge-online/configuration"`,
	} {
		if strings.Contains(body, removed) {
			t.Errorf("server management page still contains %q", removed)
		}
	}
}

func TestServerPageDoesNotExposeLegacyURIExport(t *testing.T) {
	t.Parallel()

	fixture := newPoolFixture(t)
	enrollAgent(t, fixture.registry, "edge-export")
	if _, err := fixture.controller.poolRegistry.SetReported(
		"edge-export",
		[]string{"203.0.113.12"},
		[]string{"2001:db8::12"},
	); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-export/manage",
		"",
	)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET server management status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, removed := range []string{`data-share-family`, "Copy import URI for this user"} {
		if strings.Contains(body, removed) {
			t.Errorf("server page still contains legacy URI export %q", removed)
		}
	}
}

func TestPoolPageAddressFamilies(t *testing.T) {
	t.Parallel()

	fixture := newPoolFixture(t)
	enrollAgent(t, fixture.registry, "edge-source")
	enrollAgent(t, fixture.registry, "edge-quiet")
	seedPoolDeployment(t, fixture, "edge-source", poolTestConfig)
	seedPoolDeployment(t, fixture, "edge-quiet", poolTestConfig)
	registry := fixture.controller.poolRegistry
	if _, err := registry.SetReported("edge-source", []string{"203.0.113.7"}, nil); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/pool/content", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /pool/content status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{
		"<small>IPv4</small><code>203.0.113.7</code>",
		"<small>IPv6</small><span class=\"muted\">—</span>",
		"<small>IPv4</small><span class=\"muted\">—</span>",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("pool page table does not contain %q", expected)
		}
	}
	if strings.Contains(body, "(reported)") || strings.Contains(body, "(probed)") ||
		strings.Contains(body, "(observed)") || strings.Contains(body, "(override)") {
		t.Error("pool page exposes internal address source labels")
	}
}

func TestPoolPageCollapsesUsersButRoutingOptionsRetainThem(t *testing.T) {
	t.Parallel()

	fixture := newPoolFixture(t)
	enrollAgent(t, fixture.registry, "edge-source")
	enrollAgent(t, fixture.registry, "edge-consumer")
	const config = `{"inbounds":[{"type":"anytls","tag":"shared-in","listen_port":443,"users":[{"name":"alice","password":"one"},{"name":"bob","password":"two"}]}],"outbounds":[]}`
	seedPoolDeployment(t, fixture, "edge-source", config)
	if _, err := fixture.controller.poolRegistry.SetReported(
		"edge-source",
		[]string{"203.0.113.8"},
		[]string{"2001:db8::8"},
	); err != nil {
		t.Fatal(err)
	}

	request := fixture.authenticatedRequest(http.MethodGet, "/pool/content", "")
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /pool/content status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if got := strings.Count(body, `class="pool-summary-card"`); got != 1 {
		t.Fatalf("pool summary count = %d, want one inbound summary", got)
	}
	for _, expected := range []string{
		"edge-source",
		"shared-in",
		"alice",
		"bob",
		"agent/edge-source/shared-in/alice",
		"agent/edge-source/shared-in/bob",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("pool page does not contain %q", expected)
		}
	}

	request = fixture.authenticatedRequest(
		http.MethodGet,
		"/servers/edge-consumer/pool-options",
		"",
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("pool options status = %d, body = %s", response.Code, response.Body.String())
	}
	var result poolOptionsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode pool options: %v", err)
	}
	if len(result.Options) != 2 {
		t.Fatalf("routing option count = %d, want one per user", len(result.Options))
	}
	if result.Options[0].User != "alice" || result.Options[1].User != "bob" {
		t.Fatalf("routing users = %q/%q, want alice/bob", result.Options[0].User, result.Options[1].User)
	}
}

func TestServerProbeAddressEndpoint(t *testing.T) {
	t.Parallel()

	fixture := newPoolFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	if _, err := fixture.registry.CreateEnrollment(
		context.Background(),
		"edge-pending",
		time.Now().Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	validForm := url.Values{
		"family":     {"ipv6"},
		"csrf_token": {fixture.session.CSRFToken},
	}.Encode()

	// Session, Origin, and CSRF enforcement.
	request := fixture.request(http.MethodPost, "/servers/edge-online/probe-address", validForm)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated probe status = %d, want 401", response.Code)
	}

	request = fixture.authenticatedRequest(http.MethodPost, "/servers/edge-online/probe-address", validForm)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("probe without Origin status = %d, want 403", response.Code)
	}

	badCSRF := url.Values{
		"family":     {"ipv6"},
		"csrf_token": {"wrong"},
	}.Encode()
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers/edge-online/probe-address", badCSRF)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("probe with bad CSRF status = %d, want 403", response.Code)
	}

	// The family must pin one explicit IP family.
	for _, family := range []string{"", "auto", "ipv7"} {
		form := url.Values{
			"family":     {family},
			"csrf_token": {fixture.session.CSRFToken},
		}.Encode()
		request = fixture.authenticatedMutationRequest(
			http.MethodPost,
			"/servers/edge-online/probe-address",
			form,
		)
		response = httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("probe with family %q status = %d, want 400", family, response.Code)
		}
	}

	// Unknown and not-yet-enrolled agents cannot be probed.
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers/unknown/probe-address", validForm)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown agent probe status = %d, want 404", response.Code)
	}
	request = fixture.authenticatedMutationRequest(http.MethodPost, "/servers/edge-pending/probe-address", validForm)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("pending agent probe status = %d, want 409", response.Code)
	}

	// Controller failures map to conflict/bad-request statuses.
	for _, test := range []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{"offline", control.ErrAgentOffline, http.StatusConflict, "agent is offline"},
		{
			"unsupported",
			control.ErrAgentProbeUnsupported,
			http.StatusConflict,
			"does not support address probes",
		},
		{"family rejected", control.ErrProbeFamilyInvalid, http.StatusBadRequest, "ipv4 or ipv6"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture.controller.probeErr = test.err
			defer func() { fixture.controller.probeErr = nil }()
			request := fixture.authenticatedMutationRequest(
				http.MethodPost,
				"/servers/edge-online/probe-address",
				validForm,
			)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.wantCode ||
				!strings.Contains(response.Body.String(), test.wantBody) {
				t.Fatalf(
					"%s probe response = %d %q, want %d containing %q",
					test.name,
					response.Code,
					response.Body.String(),
					test.wantCode,
					test.wantBody,
				)
			}
			if len(fixture.controller.probeRequests) != 0 {
				t.Fatalf("%s probe reached the controller: %+v", test.name, fixture.controller.probeRequests)
			}
		})
	}

	// Happy path: 202 JSON, and the family reaches the controller unchanged.
	request = fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/servers/edge-online/probe-address",
		validForm,
	)
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted ||
		response.Header().Get("Content-Type") != "application/json" ||
		!strings.Contains(response.Body.String(), `{"status":"probe requested"}`) {
		t.Fatalf(
			"probe response = %d %q %q",
			response.Code,
			response.Header().Get("Content-Type"),
			response.Body.String(),
		)
	}
	if len(fixture.controller.probeRequests) != 1 ||
		fixture.controller.probeRequests[0] != (probeRequest{agentID: "edge-online", family: "ipv6"}) {
		t.Fatalf("probe requests = %+v, want one ipv6 probe for edge-online", fixture.controller.probeRequests)
	}
}
