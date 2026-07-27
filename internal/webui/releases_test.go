package webui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitHubReleaseCatalogDiscoversAndSortsTags(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		fmt.Fprint(response, strings.Join([]string{
			"001e# service=git-upload-pack\n0000",
			"0040deadbeef refs/tags/v0.0.9\n",
			"0041deadbeef refs/tags/v0.0.16\n",
			"0049deadbeef refs/tags/v0.0.16^{}\n",
			"0048deadbeef refs/tags/not-a-version\n",
		}, ""))
	}))
	defer server.Close()

	catalog := NewGitHubReleaseCatalog(server.Client())
	catalog.refsURL = server.URL
	catalog.now = func() time.Time {
		return time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	}
	releases, err := catalog.Versions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 2 || releases[0].Tag != "v0.0.16" || releases[1].Tag != "v0.0.9" {
		t.Fatalf("unexpected releases: %+v", releases)
	}
	if _, err := catalog.Versions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("catalog requests = %d, want cached single request", requests.Load())
	}
}

func TestSingBoxCatalogIncludesStableBetaAlphaAndRC(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(response, strings.Join([]string{
			"001e# service=git-upload-pack\n0000",
			"0041deadbeef refs/tags/v1.14.0-alpha.50\n",
			"0040deadbeef refs/tags/v1.14.0-beta.2\n",
			"0040deadbeef refs/tags/v1.14.0-rc.1\n",
			"003cdeadbeef refs/tags/v1.14.0\n",
			"003ddeadbeef refs/tags/v1.13.12\n",
		}, ""))
	}))
	defer server.Close()
	catalog := NewSingBoxReleaseCatalog(server.Client())
	catalog.refsURL = server.URL
	releases, err := catalog.Versions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"v1.14.0", "v1.14.0-rc.1", "v1.14.0-beta.2", "v1.14.0-alpha.50"}
	if len(releases) != len(want) {
		t.Fatalf("releases = %+v, want %v", releases, want)
	}
	for index, tag := range want {
		if releases[index].Tag != tag {
			t.Fatalf("release %d = %q, want %q", index, releases[index].Tag, tag)
		}
	}
}

func TestGitHubReleaseCatalogReportsUpstreamStatus(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "upstream request failed", http.StatusBadGateway)
	}))
	defer server.Close()
	catalog := NewGitHubReleaseCatalog(server.Client())
	catalog.refsURL = server.URL
	_, err := catalog.Versions(context.Background())
	if err == nil || !strings.Contains(catalogDiagnostic(err), "status 502") {
		t.Fatalf("catalog error = %v", err)
	}
}
