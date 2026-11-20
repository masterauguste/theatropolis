package webui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
)

func TestPublicSubscriptionsProjectGroupMembersPerUser(t *testing.T) {
	f := newWebFixture(t)
	registry, err := pool.Open(filepath.Join(t.TempDir(), "pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.SetOverrides("edge-online", "203.0.113.8", "2001:db8::8"); err != nil {
		t.Fatal(err)
	}
	f.controller.poolRegistry = registry
	allowed, err := f.proxyNodes.CreateUser("allowed")
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.proxyNodes.CreateUser("other")
	if err != nil {
		t.Fatal(err)
	}
	var refs []proxynode.SubscriptionAction
	var forbiddenSecret string
	for i, name := range []string{"Visible", "Forbidden"} {
		node, err := f.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{Name: name, RootAgent: "edge-online", Entrance: proxynode.Endpoint{Protocol: proxynode.ProtocolAnyTLS, ListenPort: 4000 + i, TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "proxy.example"}}})
		if err != nil {
			t.Fatal(err)
		}
		userID := allowed.ID
		if i == 1 {
			userID = other.ID
		}
		member, err := f.proxyNodes.AddMembership(node.ID, userID)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			forbiddenSecret = member.Credential.Secret
		}
		refs = append(refs, proxynode.SubscriptionAction("node:"+node.ID+":ipv4"))
	}
	if err := f.proxyNodes.MarkTopologyApplied(f.proxyNodes.Snapshot().Revision, []string{"edge-online"}); err != nil {
		t.Fatal(err)
	}
	group, err := f.proxyNodes.SaveSubscriptionGroup(proxynode.SubscriptionGroup{Name: "Choices", Type: "select", Members: refs})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.proxyNodes.SetSubscriptionDefault(proxynode.SubscriptionAction("group:" + group.ID)); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"clash", "surge", "sing-box"} {
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, f.request(http.MethodGet, "/subscriptions/"+allowed.Subscription.Token+"/"+format, ""))
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, "Choices") || !strings.Contains(body, "Visible") {
			t.Fatalf("%s group projection failed: %d %s", format, w.Code, body)
		}
		if strings.Contains(body, "Forbidden") || strings.Contains(body, forbiddenSecret) {
			t.Fatalf("%s leaked another user's Node", format)
		}
	}
}

func TestSubscriptionGroupFormsAndTargetChanges(t *testing.T) {
	f := newWebFixture(t)
	post := func(path string, values url.Values, status int) {
		t.Helper()
		values.Set("csrf_token", f.session.CSRFToken)
		r := f.authenticatedMutationRequest(http.MethodPost, path, values.Encode())
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s = %d: %s", path, w.Code, w.Body.String())
		}
	}
	form := url.Values{"name": {"Streaming"}, "type": {"url-test"}, "all_nodes": {"yes"}, "members": {""}, "interval": {"300"}, "tolerance": {"50"}}
	post("/subscriptions/groups", form, http.StatusSeeOther)
	group := f.proxyNodes.SubscriptionPolicy().Groups[0]
	target := "group:" + group.ID
	rule, err := f.proxyNodes.AddSubscriptionRule(proxynode.SubscriptionRuleInput{Match: proxynode.SubscriptionMatchDomain, Values: []string{"example.com"}, Action: proxynode.SubscriptionDirect})
	if err != nil {
		t.Fatal(err)
	}
	post("/subscriptions/rules/"+rule.ID+"/action", url.Values{"action": {target}}, http.StatusSeeOther)
	post("/subscriptions/default", url.Values{"action": {target}}, http.StatusSeeOther)
	for _, locale := range []string{"en", "zh-CN"} {
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, f.authenticatedRequestWithLocale(http.MethodGet, "/subscriptions", "", locale))
		if w.Code != http.StatusOK {
			t.Fatalf("page = %d: %s", w.Code, w.Body.String())
		}
		for _, expected := range []string{"Streaming", "data-subscription-group-form", "data-subscription-member-picker", "data-subscription-rule-search", "value=\"" + target + "\""} {
			if !strings.Contains(w.Body.String(), expected) {
				t.Errorf("page missing %q", expected)
			}
		}
	}
	form.Set("name", "Renamed")
	post("/subscriptions/groups/"+group.ID, form, http.StatusSeeOther)
	post("/subscriptions/groups/"+group.ID+"/delete", url.Values{"replacement": {"reject"}}, http.StatusSeeOther)
	policy := f.proxyNodes.SubscriptionPolicy()
	if len(policy.Groups) != 0 || policy.Rules[0].Action != proxynode.SubscriptionReject || policy.DefaultAction != proxynode.SubscriptionReject {
		t.Fatalf("delete failed to retarget: %+v", policy)
	}
	post("/subscriptions/default", url.Values{"action": {target}}, http.StatusBadRequest)
	// Authentication, origin and CSRF must also protect the new endpoints.
	r := f.mutationRequest(http.MethodPost, "/subscriptions/groups", form.Encode())
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "/login") {
		t.Fatalf("unauthenticated write = %d", w.Code)
	}
	form.Set("csrf_token", "wrong")
	r = f.authenticatedMutationRequest(http.MethodPost, "/subscriptions/groups", form.Encode())
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF = %d", w.Code)
	}
}

func TestSubscriptionTargetPickerPreservesDeletedNodes(t *testing.T) {
	ref := proxynode.SubscriptionAction("node:pn_012345678901234567890123:ipv6")
	v := subscriptionPolicyViewFor(proxynode.SubscriptionPolicy{DefaultAction: ref})
	found := false
	for _, option := range v.DefaultTargets.Options {
		if option.Value == string(ref) {
			found = true
			if option.Kind != "Unavailable" {
				t.Fatal("missing availability hint")
			}
		}
	}
	if !found || v.DefaultTargets.Action != string(ref) {
		t.Fatal("deleted target would be silently replaced")
	}
}
