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
	form := url.Values{"name": {"Streaming"}, "type": {"select"}, "members": {"proxy\nall_nodes\ndirect\nreject"}}
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
		env := decodeSPA(t, w)
		if env.View != "subscription-policy" || env.Data.SubscriptionPolicy == nil || len(env.Data.SubscriptionPolicy.Groups) != 1 || env.Data.SubscriptionPolicy.Groups[0].Name != "Streaming" || env.Data.SubscriptionPolicy.DefaultAction != target {
			t.Errorf("unexpected subscription policy (%s): %+v", locale, env.Data.SubscriptionPolicy)
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

func TestAddAndEditSubscriptionRuleCanCreateCopyOfProxyGroup(t *testing.T) {
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
	post("/subscriptions/rules", url.Values{
		"match":          {"domain_suffix"},
		"values":         {"netflix.com"},
		"action":         {"new_group"},
		"new_group_name": {"Netflix"},
	}, http.StatusSeeOther)

	policy := f.proxyNodes.SubscriptionPolicy()
	if len(policy.Groups) != 1 || len(policy.Rules) != 1 {
		t.Fatalf("expected 1 group and 1 rule, got %+v", policy)
	}
	group := policy.Groups[0]
	rule := policy.Rules[0]
	if group.Name != "Netflix" || group.Type != "select" || !group.AllNodes {
		t.Fatalf("unexpected created group: %+v", group)
	}
	if rule.Action != proxynode.SubscriptionAction("group:"+group.ID) {
		t.Fatalf("rule action = %q, want group:%s", rule.Action, group.ID)
	}
	// Duplicate or empty group names fail cleanly without adding a rule.
	post("/subscriptions/rules", url.Values{
		"match":          {"domain"},
		"values":         {"example.com"},
		"action":         {"new_group"},
		"new_group_name": {"Netflix"},
	}, http.StatusBadRequest)
	post("/subscriptions/rules", url.Values{
		"match":          {"domain"},
		"values":         {"example.com"},
		"action":         {"new_group"},
		"new_group_name": {""},
	}, http.StatusBadRequest)
	if got := len(f.proxyNodes.SubscriptionPolicy().Rules); got != 1 {
		t.Fatalf("failed creates added unexpected rules: %d", got)
	}
	// Editing an existing rule can also spin off a fresh copy-of-PROXY group.
	post("/subscriptions/rules/"+rule.ID, url.Values{
		"match":          {"domain_suffix"},
		"values":         {"openai.com"},
		"action":         {"new_group"},
		"new_group_name": {"OpenAI"},
	}, http.StatusSeeOther)
	policy = f.proxyNodes.SubscriptionPolicy()
	if len(policy.Groups) != 2 || policy.Rules[0].Action != proxynode.SubscriptionAction("group:"+policy.Groups[1].ID) {
		t.Fatalf("rule edit did not create and assign new group: %+v", policy)
	}
	// Verify JSON policy view includes both created groups in both locales.
	for _, locale := range []string{"en", "zh-CN"} {
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, f.authenticatedRequestWithLocale(http.MethodGet, "/subscriptions", "", locale))
		if w.Code != http.StatusOK {
			t.Fatalf("GET /subscriptions (%s) = %d", locale, w.Code)
		}
		env := decodeSPA(t, w)
		if env.Data.SubscriptionPolicy == nil || len(env.Data.SubscriptionPolicy.Groups) != 2 {
			t.Fatalf("GET /subscriptions (%s) groups = %+v", locale, env.Data.SubscriptionPolicy)
		}
		for _, want := range []string{"Netflix", "OpenAI"} {
			if !strings.Contains(w.Body.String(), want) {
				t.Errorf("GET /subscriptions (%s) missing %q", locale, want)
			}
		}
	}
}

func TestGlobalSubscriptionEditorOmitsIndividualNodesAndRejectsNodeTargets(t *testing.T) {
	f := newWebFixture(t)
	node, err := f.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Tokyo", RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{Protocol: proxynode.ProtocolAnyTLS, ListenPort: 4443, TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "proxy.example"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, f.authenticatedRequest(http.MethodGet, "/subscriptions", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /subscriptions = %d", w.Code)
	}
	env := decodeSPA(t, w)
	policy := env.Data.SubscriptionPolicy
	if policy == nil {
		t.Fatal("missing SubscriptionPolicy")
	}
	foundProxy := false
	for _, opt := range policy.NewRuleTargets.Options {
		if strings.HasPrefix(opt.Value, "node:") || opt.Value == "all_nodes" {
			t.Fatalf("global rule targets exposed non-policy target: %+v", opt)
		}
		if opt.Value == "proxy" {
			foundProxy = true
			if opt.Label != "PROXY" || opt.Kind != "Follow PROXY selection" {
				t.Fatalf("unexpected proxy target label/kind: %+v", opt)
			}
		}
	}
	if !foundProxy {
		t.Fatal("missing proxy target option")
	}
	foundAllNodes := false
	for _, choice := range policy.NewGroup.Choices {
		if strings.HasPrefix(choice.Value, "node:") {
			t.Fatalf("global group choices exposed individual node: %+v", choice)
		}
		if choice.Value == "all_nodes" && choice.Selected {
			foundAllNodes = true
		}
	}
	if !foundAllNodes {
		t.Fatal("missing selected All available nodes choice in NewGroup")
	}

	post := func(path string, values url.Values, status int) {
		t.Helper()
		values.Set("csrf_token", f.session.CSRFToken)
		r := f.authenticatedMutationRequest(http.MethodPost, path, values.Encode())
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, r)
		if rec.Code != status {
			t.Fatalf("%s = %d (want %d): %s", path, rec.Code, status, rec.Body.String())
		}
	}
	nodeRef := "node:" + node.ID
	// url-test groups are disabled; empty members and individual node targets are rejected.
	post("/subscriptions/groups", url.Values{"name": {"Auto"}, "type": {"url-test"}, "members": {"all_nodes"}}, http.StatusBadRequest)
	post("/subscriptions/groups", url.Values{"name": {"Empty"}, "type": {"select"}, "members": {""}}, http.StatusBadRequest)
	post("/subscriptions/groups", url.Values{"name": {"Custom"}, "type": {"select"}, "members": {nodeRef}}, http.StatusBadRequest)
	post("/subscriptions/rules", url.Values{"match": {"domain"}, "values": {"example.com"}, "action": {nodeRef}}, http.StatusBadRequest)
	post("/subscriptions/default", url.Values{"action": {nodeRef}}, http.StatusBadRequest)

	// Reordering / omitting All available nodes works cleanly (e.g., AdBlock with Reject -> Direct).
	post("/subscriptions/groups", url.Values{"name": {"AdBlock"}, "type": {"select"}, "members": {"reject\ndirect"}}, http.StatusSeeOther)
	saved := f.proxyNodes.SubscriptionPolicy().Groups
	if len(saved) != 1 || saved[0].Name != "AdBlock" || saved[0].AllNodes || len(saved[0].Members) != 2 || saved[0].Members[0] != proxynode.SubscriptionReject {
		t.Fatalf("unexpected saved AdBlock group: %+v", saved)
	}

	// One-click Private / LAN rule saves cleanly even with empty values input.
	post("/subscriptions/rules", url.Values{"match": {"ip_is_private"}, "values": {""}, "no_resolve": {"yes"}, "action": {"direct"}}, http.StatusSeeOther)
	rules := f.proxyNodes.SubscriptionPolicy().Rules
	if len(rules) != 1 || rules[0].Match != proxynode.SubscriptionMatchIPPrivate || !rules[0].NoResolve || rules[0].Action != proxynode.SubscriptionDirect {
		t.Fatalf("unexpected saved Private / LAN rule: %+v", rules)
	}
}
