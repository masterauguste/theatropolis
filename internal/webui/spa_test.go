package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func decodeSPA(t *testing.T, response *httptest.ResponseRecorder) spaEnvelope {
	t.Helper()
	var env spaEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode SPA JSON (status=%d): %v\nbody=%s", response.Code, err, response.Body.String())
	}
	return env
}

func TestSPAShellAssetsAndSessionAPI(t *testing.T) {
	f := newWebFixture(t)

	// Unauthenticated HTML browser navigation to admin page redirects to /login.
	req := f.request(http.MethodGet, "/servers", "")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated HTML /servers = %d loc=%q", w.Code, w.Header().Get("Location"))
	}

	// Unauthenticated SPA JSON request returns 401 JSON instead of 303.
	req = f.request(http.MethodGet, "/servers", "")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Theatropolis-SPA", "1")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated SPA JSON /servers = %d %s", w.Code, w.Body.String())
	}

	// Authenticated HTML browser navigation returns Vite SPA index.html.
	req = f.authenticatedRequest(http.MethodGet, "/servers", "")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), `<div id="root"></div>`) {
		t.Fatalf("authenticated HTML /servers = %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}

	// /api/session returns authenticated admin session and CSRF token.
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, f.authenticatedRequest(http.MethodGet, "/api/session", ""))
	var sess spaSessionInfo
	if err := json.Unmarshal(w.Body.Bytes(), &sess); err != nil {
		t.Fatal(err)
	}
	if !sess.Authenticated || sess.Role != "admin" || sess.CSRFToken != f.session.CSRFToken {
		t.Fatalf("unexpected /api/session: %+v", sess)
	}

	// /api/messages returns localized message catalog.
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, f.authenticatedRequestWithLocale(http.MethodGet, "/api/messages", "", "zh-CN"))
	var msgResp struct {
		Locale   string            `json:"locale"`
		Messages map[string]string `json:"messages"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &msgResp); err != nil {
		t.Fatal(err)
	}
	if msgResp.Locale != "zh-CN" || msgResp.Messages["Users"] != "用户" {
		t.Fatalf("unexpected /api/messages: %+v", msgResp.Locale)
	}

	// SPA mutation converts 303 redirect to JSON { ok: true, redirect }.
	mutReq := f.authenticatedMutationRequest(http.MethodPost, "/users", url.Values{
		"csrf_token": {f.session.CSRFToken},
		"name":       {"spa-user"},
	}.Encode())
	mutReq.Header.Set("X-Theatropolis-SPA", "1")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, mutReq)
	var mutResp struct {
		OK       bool   `json:"ok"`
		Redirect string `json:"redirect"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &mutResp) != nil || !mutResp.OK || !strings.HasPrefix(mutResp.Redirect, "/users/usr_") {
		t.Fatalf("SPA mutation redirect = %d %s", w.Code, w.Body.String())
	}

	// One-time enrollment result is NOT consumed by HTML shell load, only by JSON load.
	enrollReq := f.authenticatedMutationRequest(http.MethodPost, "/servers", url.Values{
		"csrf_token":   {f.session.CSRFToken},
		"display_name": {"spa-edge"},
		"ttl_seconds":  {"900"},
	}.Encode())
	enrollReq.Header.Set("X-Theatropolis-Form", "1")
	enrollReq.Header.Set("X-Theatropolis-SPA", "1")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, enrollReq)
	resultURL := w.Header().Get("X-Theatropolis-Redirect")
	if w.Code != http.StatusNoContent || !strings.HasPrefix(resultURL, "/servers/enrollment-result?id=") {
		t.Fatalf("enrollment response = %d redirect=%q", w.Code, resultURL)
	}
	htmlReq := f.authenticatedRequest(http.MethodGet, resultURL, "")
	htmlReq.Header.Set("Accept", "text/html")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, htmlReq)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<div id="root"></div>`) {
		t.Fatalf("HTML enrollment-result shell = %d", w.Code)
	}
	jsonReq := f.authenticatedRequest(http.MethodGet, resultURL, "")
	jsonReq.Header.Set("X-Theatropolis-SPA", "1")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, jsonReq)
	env := decodeSPA(t, w)
	if w.Code != http.StatusOK || env.Data.Created == nil || env.Data.Created.DisplayName != "spa-edge" {
		t.Fatalf("first JSON consumption failed: %d %+v", w.Code, env.Data.Created)
	}
	// Second consumption redirects back to /servers.
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, jsonReq)
	var second struct {
		Redirect string `json:"redirect"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &second) != nil || second.Redirect != "/servers" {
		t.Fatalf("second JSON consumption = %d %s", w.Code, w.Body.String())
	}

	// Browser navigation to an invalid/expired claim link serves the SPA shell with 410 Gone (never raw JSON).
	claimHTMLReq := f.request(http.MethodGet, "/claim/expired-or-invalid-token", "")
	claimHTMLReq.Header.Set("Accept", "text/html,application/xhtml+xml")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, claimHTMLReq)
	if w.Code != http.StatusGone || !strings.Contains(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), `<div id="root"></div>`) {
		t.Fatalf("invalid claim HTML shell = %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}
