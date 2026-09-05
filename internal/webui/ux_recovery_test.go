package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

func TestDuplicateUserErrorIsActionableInBothLocales(t *testing.T) {
	f := newWebFixture(t)
	if _, err := f.proxyNodes.CreateUser("Alice"); err != nil {
		t.Fatal(err)
	}
	for locale, want := range map[string]string{"en": "Choose a different name", "zh-CN": "请换一个名称"} {
		r := f.authenticatedMutationRequest(http.MethodPost, "/users", url.Values{"csrf_token": {f.session.CSRFToken}, "name": {"alice"}}.Encode())
		r.Header.Del("Cookie")
		r.AddCookie(&http.Cookie{Name: languageCookieName, Value: locale})
		// Retain the authenticated session cookie without a duplicate locale cookie.
		for _, cookie := range f.authenticatedRequest(http.MethodGet, "/users", "").Cookies() {
			if cookie.Name != languageCookieName {
				r.AddCookie(cookie)
			}
		}
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), want) {
			t.Fatalf("%s: %d %s", locale, w.Code, w.Body.String())
		}
	}
}

func TestUserSearchPaginationAndOutOfRangePages(t *testing.T) {
	f := newWebFixture(t)
	for i := 0; i < 53; i++ {
		if _, err := f.proxyNodes.CreateUser(fmt.Sprintf("User %02d", i)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		path  string
		count int
		want  string
	}{
		{"/users", 50, "User 00"}, {"/users?page=2", 3, "User 50"}, {"/users?page=9999", 3, "User 50"},
		{"/users?q=user+52", 1, "User 52"}, {"/users?q=missing", 0, "No users match your search."},
	} {
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, f.authenticatedRequest(http.MethodGet, tc.path, ""))
		if w.Code != 200 || strings.Count(w.Body.String(), `href="/users/usr_`) != tc.count || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}

func TestPendingTopologyDetectedAfterReopeningPreUpdateState(t *testing.T) {
	f := newWebFixture(t)
	path := filepath.Join(t.TempDir(), "proxy-nodes.json")
	store, err := proxynode.Open(path, proxynode.BuildInfo{})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(proxynode.CreateProxyNodeInput{Name: "Before update", RootAgent: "offline", Entrance: proxynode.Endpoint{
		Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto", TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "edge.example"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTopologyApplied(store.Snapshot().Revision, []string{"offline"}); err != nil {
		t.Fatal(err)
	}
	endpoint := node.Entrance.Endpoint
	endpoint.ListenPort = 8443
	if err := store.UpdateEntrance(node.ID, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// No deployment job or browser state survives this simulated Master upgrade.
	reopened, err := proxynode.Open(path, proxynode.BuildInfo{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	deployer, err := proxynode.NewDeployer(reopened, fixedProxyResolver{}, f.controller)
	if err != nil {
		t.Fatal(err)
	}
	h := f.handler.(*Handler)
	h.proxyNodes = reopened
	h.proxyDeployer = deployer
	w := httptest.NewRecorder()
	h.ServeHTTP(w, f.authenticatedRequest(http.MethodGet, "/proxy-nodes/deployment-status", ""))
	var status proxyDeploymentView
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Status != "pending" || status.Active || !strings.Contains(status.Error, "across Master restarts") {
		t.Fatalf("recovered status = %+v", status)
	}
	if reopened.Snapshot().Revision == reopened.Snapshot().AppliedRevision {
		t.Fatal("pending revision was incorrectly marked applied")
	}
	state := reopened.Snapshot()
	if state.ProxyNodes[0].Entrance.Endpoint.ListenPort != 8443 || state.AppliedProxyNodes[0].Entrance.Endpoint.ListenPort != 443 {
		t.Fatal("upgrade did not preserve the distinct desired and applied listeners")
	}
}

func TestExplicitMessagesNeverTranslateUserDataOrIdentifiers(t *testing.T) {
	set := template.Must(template.New("explicit").Funcs(template.FuncMap{"t": func(key string) string { return messageText("zh-CN", key) }}).Parse(`<a class="user-link" href="/users/user-1" aria-label="{{t "Open user"}}">{{t "Users"}}</a><p>{{.}}</p>`))
	var out bytes.Buffer
	if err := set.Execute(&out, "No Users Direct"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`class="user-link"`, `href="/users/user-1"`, `aria-label="打开用户"`, `>用户</a>`, `>No Users Direct</p>`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s: %s", want, out.String())
		}
	}
	for key, message := range messages {
		if message.English == "" || message.Chinese == "" {
			t.Errorf("incomplete message: %s", key)
		}
	}
}

func TestRetiredEditorAndCustomRuleWritesAreUnavailable(t *testing.T) {
	f := newWebFixture(t)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, f.request(http.MethodGet, "/assets/config-editor.js", ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("retired asset: %d", w.Code)
	}
	r := f.authenticatedMutationRequest(http.MethodPost, "/proxy-nodes/missing/links/missing/rules", url.Values{"csrf_token": {f.session.CSRFToken}, "match": {"rule_set"}, "values": {"custom"}}.Encode())
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Choose Geosite, GeoIP") {
		t.Fatalf("custom rule: %d %s", w.Code, w.Body.String())
	}
}

func TestRetainedDraftCanRefreshOnlyItsAuthenticatedSessionCSRF(t *testing.T) {
	f := newWebFixture(t)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, f.authenticatedRequest(http.MethodGet, "/session/csrf", ""))
	var data map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || data["csrf_token"] != f.session.CSRFToken || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("session CSRF response: %d %#v", w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, f.request(http.MethodGet, "/session/csrf", ""))
	if strings.Contains(w.Body.String(), f.session.CSRFToken) || w.Code == http.StatusOK {
		t.Fatal("anonymous request exposed a CSRF token")
	}
}
