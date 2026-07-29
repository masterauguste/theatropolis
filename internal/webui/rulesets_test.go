package webui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGeositeRuleSetCatalogExtractsSortsAndDedupesNames(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		fmt.Fprint(response, `{"tree":[`+
			`{"path":"geosite-openai.srs","type":"blob"},`+
			`{"path":"geosite-cn.srs","type":"blob"},`+
			`{"path":"geosite-openai.srs","type":"blob"},`+
			`{"path":"geosite-category-ads-all.srs","type":"blob"},`+
			`{"path":"README.md","type":"blob"},`+
			`{"path":"geoip-cn.srs","type":"blob"}`+
			`],"truncated":false}`)
	}))
	defer server.Close()

	catalog := NewGeositeRuleSetCatalog(server.Client())
	catalog.treeURL = server.URL
	options, err := catalog.Options(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"category-ads-all", "cn", "openai"}
	if len(options) != len(want) {
		t.Fatalf("options = %v, want %v", options, want)
	}
	for index, name := range want {
		if options[index] != name {
			t.Fatalf("option %d = %q, want %q", index, options[index], name)
		}
	}
}

func TestGeoipRuleSetCatalogUsesGeoipPattern(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(response, `{"tree":[`+
			`{"path":"geoip-cn.srs"},`+
			`{"path":"geosite-cn.srs"}`+
			`],"truncated":false}`)
	}))
	defer server.Close()

	catalog := NewGeoipRuleSetCatalog(server.Client())
	catalog.treeURL = server.URL
	options, err := catalog.Options(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(options) != 1 || options[0] != "cn" {
		t.Fatalf("options = %v, want [cn]", options)
	}
}

func TestRuleSetCatalogCachesSingleFlight(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(response, `{"tree":[{"path":"geosite-openai.srs"}],"truncated":false}`)
	}))
	defer server.Close()

	catalog := NewGeositeRuleSetCatalog(server.Client())
	catalog.treeURL = server.URL
	catalog.now = func() time.Time {
		return time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	}
	if _, err := catalog.Options(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Options(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("catalog requests = %d, want cached single request", requests.Load())
	}
}

func TestRuleSetCatalogFallsBackToStaleCacheOnError(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			fmt.Fprint(response, `{"tree":[{"path":"geosite-cn.srs"}],"truncated":false}`)
			return
		}
		http.Error(response, "upstream request failed", http.StatusBadGateway)
	}))
	defer server.Close()

	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	catalog := NewGeositeRuleSetCatalog(server.Client())
	catalog.treeURL = server.URL
	catalog.now = func() time.Time { return now }

	options, err := catalog.Options(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(options) != 1 || options[0] != "cn" {
		t.Fatalf("options = %v, want [cn]", options)
	}

	now = now.Add(ruleSetCatalogTTL + time.Minute)
	options, err = catalog.Options(context.Background())
	if err != nil {
		t.Fatalf("stale fallback error = %v", err)
	}
	if len(options) != 1 || options[0] != "cn" {
		t.Fatalf("stale options = %v, want [cn]", options)
	}
	deadline := time.Now().Add(time.Second)
	for requests.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if requests.Load() != 2 {
		t.Fatalf("catalog requests = %d, want asynchronous refresh", requests.Load())
	}
}

func TestRuleSetCatalogPersistsAndReloadsLastGoodOptions(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(response, `{"tree":[{"path":"geosite-cn.srs"},{"path":"geosite-openai.srs"}],"truncated":false}`)
	}))
	defer server.Close()

	cachePath := filepath.Join(t.TempDir(), "catalog", "geosite.json")
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	catalog := NewGeositeRuleSetCatalog(server.Client(), cachePath)
	catalog.treeURL = server.URL
	catalog.now = func() time.Time { return now }
	if _, err := catalog.Options(context.Background()); err != nil {
		t.Fatal(err)
	}

	reloaded := NewGeositeRuleSetCatalog(server.Client(), cachePath)
	reloaded.treeURL = server.URL
	reloaded.now = func() time.Time { return now.Add(time.Hour) }
	options, err := reloaded.Options(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(options, ",") != "cn,openai" {
		t.Fatalf("reloaded options = %v", options)
	}
	if requests.Load() != 1 {
		t.Fatalf("upstream requests = %d, want disk cache without a refetch", requests.Load())
	}
}

func TestRuleSetCatalogReportsUpstreamStatus(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "upstream request failed", http.StatusBadGateway)
	}))
	defer server.Close()
	catalog := NewGeositeRuleSetCatalog(server.Client())
	catalog.treeURL = server.URL
	_, err := catalog.Options(context.Background())
	if err == nil || !strings.Contains(ruleSetDiagnostic(err), "status 502") {
		t.Fatalf("catalog error = %v", err)
	}
	if !strings.HasPrefix(ruleSetDiagnostic(err), "Rule-set lookup failed: ") {
		t.Fatalf("diagnostic = %q", ruleSetDiagnostic(err))
	}
}

func TestRuleSetCatalogRejectsOversizeResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		fmt.Fprint(response, `{"tree":[{"path":"`)
		for written := 0; written < maxRuleSetResponseSize; written += 1024 {
			fmt.Fprint(response, strings.Repeat("a", 1024))
		}
	}))
	defer server.Close()
	catalog := NewGeositeRuleSetCatalog(server.Client())
	catalog.treeURL = server.URL
	_, err := catalog.Options(context.Background())
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("catalog error = %v", err)
	}
}

func TestRuleSetCatalogRejectsTruncatedTree(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(response, `{"tree":[{"path":"geosite-cn.srs"}],"truncated":true}`)
	}))
	defer server.Close()
	catalog := NewGeositeRuleSetCatalog(server.Client())
	catalog.treeURL = server.URL
	_, err := catalog.Options(context.Background())
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("catalog error = %v", err)
	}
}
