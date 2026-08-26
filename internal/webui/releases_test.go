package webui

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGitHubReleaseCatalogDiscoversAndSortsTags(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.Header().Set("Content-Type", "application/json")
		fmt.Fprint(response, `[
			{"tag_name":"v0.0.9","assets":[
				{"name":"checksums.txt"},
				{"name":"checksums.txt.sig"},
				{"name":"theatropolis_linux_amd64.tar.gz"},
				{"name":"theatropolis_linux_arm64.tar.gz"}]},
			{"tag_name":"v0.0.16","assets":[
				{"name":"checksums.txt"},
				{"name":"checksums.txt.sig"},
				{"name":"theatropolis_linux_amd64.tar.gz"},
				{"name":"theatropolis_linux_arm64.tar.gz"}]},
			{"tag_name":"not-a-version","assets":[]}
		]`)
	}))
	defer server.Close()

	catalog := NewGitHubReleaseCatalog(server.Client())
	catalog.releasesURL = server.URL
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
	if requests.Load() != 2 {
		t.Fatalf("catalog requests = %d, want a fresh request for every check", requests.Load())
	}
}

func TestGitHubReleaseCatalogOmitsTagsWithoutCompleteBinaryAssets(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		fmt.Fprint(response, `[
			{"tag_name":"v0.0.18","assets":[{"name":"checksums.txt"}]},
			{"tag_name":"v0.0.17","assets":[
				{"name":"checksums.txt"},
				{"name":"checksums.txt.sig"},
				{"name":"theatropolis_linux_amd64.tar.gz"},
				{"name":"theatropolis_linux_arm64.tar.gz"}]}
		]`)
	}))
	defer server.Close()
	catalog := NewGitHubReleaseCatalog(server.Client())
	catalog.releasesURL = server.URL
	releases, err := catalog.Versions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 1 || releases[0].Tag != "v0.0.17" {
		t.Fatalf("releases = %+v, want only v0.0.17", releases)
	}
}

func TestSingBoxCatalogIncludesOnlyCompleteManagedUserBuilds(t *testing.T) {
	t.Parallel()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/manifest-rc":
			fmt.Fprint(response, `{"schema_version":2,"release":{"tag":"v1.14.0-rc.1.theatropolis.1","version":"1.14.0-rc.1.theatropolis.1"},"patchset":{"capabilities":["managed-users-v1","anytls-live-users","hysteria2-live-users","session-revocation-v1"]},"build":{"tags":["with_v2ray_api","with_theatropolis_managed_users"]}}`)
			return
		case "/manifest-stable":
			fmt.Fprint(response, `{"schema_version":2,"release":{"tag":"v1.14.0-theatropolis.2","version":"1.14.0-theatropolis.2"},"patchset":{"capabilities":["managed-users-v1","anytls-live-users","hysteria2-live-users","session-revocation-v1","traffic-reset-v1"]},"build":{"tags":["with_v2ray_api","with_theatropolis_managed_users"]}}`)
			return
		}
		fmt.Fprintf(response, `[
			{"tag_name":"v1.14.0-alpha.50","prerelease":true,"assets":[]},
			{"tag_name":"v1.14.0-beta.2","prerelease":true,"assets":[]},
			{"tag_name":"v1.14.0-rc.2.theatropolis.1","prerelease":true,"assets":[
				{"name":"checksums.txt"}]},
			{"tag_name":"v1.14.0-rc.1.theatropolis.1","prerelease":true,"assets":[
				{"name":"build-manifest.json","browser_download_url":%q},
				{"name":"checksums.txt"},
				{"name":"checksums.txt.sig"},
				{"name":"sing-box-1.14.0-rc.1.theatropolis.1-linux-amd64.tar.gz"},
				{"name":"sing-box-1.14.0-rc.1.theatropolis.1-linux-arm64.tar.gz"}]},
			{"tag_name":"v1.14.0-theatropolis.2","assets":[
				{"name":"build-manifest.json","browser_download_url":%q},
				{"name":"checksums.txt"},
				{"name":"checksums.txt.sig"},
				{"name":"sing-box-1.14.0-theatropolis.2-linux-amd64.tar.gz"},
				{"name":"sing-box-1.14.0-theatropolis.2-linux-arm64.tar.gz"}]},
			{"tag_name":"v1.14.0","assets":[
				{"name":"checksums.txt"},
				{"name":"checksums.txt.sig"},
				{"name":"sing-box-1.14.0-linux-amd64.tar.gz"},
				{"name":"sing-box-1.14.0-linux-arm64.tar.gz"}]},
			{"tag_name":"v1.13.12","assets":[]}
		]`, server.URL+"/manifest-rc", server.URL+"/manifest-stable")
	}))
	defer server.Close()
	catalog := NewSingBoxReleaseCatalog(server.Client())
	catalog.releasesURL = server.URL
	releases, err := catalog.Versions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"v1.14.0-theatropolis.2"}
	if len(releases) != len(want) {
		t.Fatalf("releases = %+v, want %v", releases, want)
	}
	for index, tag := range want {
		if releases[index].Tag != tag {
			t.Fatalf("release %d = %q, want %q", index, releases[index].Tag, tag)
		}
	}
}

func TestManagedSingBoxVersionsSortByUpstreamThenPatchRevision(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		left  string
		right string
	}{
		{"v1.14.0-rc.1.theatropolis.10", "v1.14.0-rc.1.theatropolis.2"},
		{"v1.14.0-theatropolis.1", "v1.14.0-rc.9.theatropolis.99"},
		{"v1.14.1-rc.1.theatropolis.1", "v1.14.0-theatropolis.99"},
	} {
		if compareVersionTags(test.left, test.right) <= 0 {
			t.Errorf("compareVersionTags(%q, %q) did not rank left newer", test.left, test.right)
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
	catalog.releasesURL = server.URL
	_, err := catalog.Versions(context.Background())
	if err == nil || !strings.Contains(catalogDiagnostic(err), "status 502") {
		t.Fatalf("catalog error = %v", err)
	}
}

func TestGitHubReleaseCatalogRetriesAfterFailure(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			http.Error(response, "temporary failure", http.StatusBadGateway)
			return
		}
		fmt.Fprint(response, `[{"tag_name":"v0.0.17","assets":[
			{"name":"checksums.txt"},
			{"name":"checksums.txt.sig"},
			{"name":"theatropolis_linux_amd64.tar.gz"},
			{"name":"theatropolis_linux_arm64.tar.gz"}]}]`)
	}))
	defer server.Close()
	catalog := NewGitHubReleaseCatalog(server.Client())
	catalog.releasesURL = server.URL
	if _, err := catalog.Versions(context.Background()); err == nil {
		t.Fatal("first version lookup unexpectedly succeeded")
	}
	releases, err := catalog.Versions(context.Background())
	if err != nil {
		t.Fatalf("retry version lookup: %v", err)
	}
	if len(releases) != 1 || releases[0].Tag != "v0.0.17" || requests.Load() != 2 {
		t.Fatalf("retry releases = %+v, requests = %d", releases, requests.Load())
	}
}

func TestTheatropolisReleaseCatalogNeverCachesCompletedReleaseList(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	var newest atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		tag := "v0.0.29"
		if newest.Load() {
			tag = "v0.0.30"
		}
		fmt.Fprintf(response, `[{"tag_name":%q,"assets":[
			{"name":"checksums.txt"},
			{"name":"checksums.txt.sig"},
			{"name":"theatropolis_linux_amd64.tar.gz"},
			{"name":"theatropolis_linux_arm64.tar.gz"}]}]`, tag)
	}))
	defer server.Close()

	catalog := NewGitHubReleaseCatalog(server.Client())
	catalog.releasesURL = server.URL
	releases, err := catalog.Versions(context.Background())
	if err != nil || releases[0].Tag != "v0.0.29" {
		t.Fatalf("initial releases = %+v, err = %v", releases, err)
	}

	newest.Store(true)
	releases, err = catalog.Versions(context.Background())
	if err != nil || releases[0].Tag != "v0.0.30" || requests.Load() != 2 {
		t.Fatalf("fresh releases = %+v, requests = %d, err = %v", releases, requests.Load(), err)
	}
}
