package webui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitHubReleaseCatalogIncludesStableAndPrerelease(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		response.Header().Set("Content-Type", "application/json")
		fmt.Fprint(response, `[
			{"tag_name":"v1.2.3-beta.1","draft":false,"prerelease":true,"published_at":"2026-07-02T00:00:00Z","extra":"ignored"},
			{"tag_name":"v1.2.2","draft":false,"prerelease":false,"published_at":"2026-07-01T00:00:00Z"},
			{"tag_name":"v1.2.1","draft":true,"prerelease":false,"published_at":"2026-06-01T00:00:00Z"},
			{"tag_name":"not-a-version","draft":false,"prerelease":false,"published_at":"2026-05-01T00:00:00Z"}
		]`)
	}))
	defer server.Close()

	catalog := NewGitHubReleaseCatalog(server.Client())
	catalog.apiURL = server.URL
	catalog.now = func() time.Time {
		return time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)
	}
	releases, err := catalog.Versions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 2 ||
		releases[0].Tag != "v1.2.3-beta.1" ||
		!releases[0].Prerelease ||
		releases[1].Tag != "v1.2.2" ||
		releases[1].Prerelease {
		t.Fatalf("unexpected releases: %+v", releases)
	}
	if _, err := catalog.Versions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("catalog requests = %d, want cached single request", requests.Load())
	}
}

func TestGitHubReleaseCatalogRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Length", fmt.Sprint(maxReleaseResponseSize+1))
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	catalog := NewGitHubReleaseCatalog(server.Client())
	catalog.apiURL = server.URL
	if _, err := catalog.Versions(context.Background()); err == nil {
		t.Fatal("oversized release response was accepted")
	}
}

func TestSingBoxReleaseCatalogIncludesStableAndTestingFrom114(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(
		func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			fmt.Fprint(response, `[
				{"tag_name":"v1.14.0-alpha.27","draft":false,"prerelease":true,"published_at":"2026-07-27T00:00:00Z"},
				{"tag_name":"v1.14.0","draft":false,"prerelease":false,"published_at":"2026-07-26T00:00:00Z"},
				{"tag_name":"v1.13.12","draft":false,"prerelease":false,"published_at":"2026-07-25T00:00:00Z"}
			]`)
		},
	))
	defer server.Close()
	catalog := NewSingBoxReleaseCatalog(server.Client())
	catalog.apiURL = server.URL
	releases, err := catalog.Versions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 2 ||
		releases[0].Tag != "v1.14.0-alpha.27" ||
		releases[1].Tag != "v1.14.0" {
		t.Fatalf("unexpected sing-box releases: %+v", releases)
	}
}
