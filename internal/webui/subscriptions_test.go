package webui

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
)

type geositeRoundTripper func(*http.Request) (*http.Response, error)

func TestQuotaReachedMembershipRemainsVisibleInSubscription(t *testing.T) {
	for status, want := range map[proxynode.MembershipStatus]bool{
		proxynode.MembershipEnabled:      true,
		proxynode.MembershipQuotaReached: true,
		proxynode.MembershipExpired:      false,
	} {
		if got := membershipVisibleInSubscription(status); got != want {
			t.Errorf("membershipVisibleInSubscription(%q) = %t, want %t", status, got, want)
		}
	}
}

func TestSubscriptionAddressesPreferPerFamilyDomainsWithIPFallback(t *testing.T) {
	registry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.SetReported("edge-1", []string{"203.0.113.9"}, []string{"2001:db8::9"}); err != nil {
		t.Fatal(err)
	}
	if err := registry.SetSubscriptionDomains("edge-1", "v4.edge.example", ""); err != nil {
		t.Fatal(err)
	}
	addresses := subscriptionAddresses(registry, "edge-1", proxynode.SubscriptionAddressDual)
	want := []subscriptionAddress{{family: "IPv4", address: "v4.edge.example"}, {family: "IPv6", address: "2001:db8::9"}}
	if len(addresses) != len(want) {
		t.Fatalf("subscriptionAddresses() = %+v", addresses)
	}
	for index := range want {
		if addresses[index] != want[index] {
			t.Fatalf("subscriptionAddresses()[%d] = %+v, want %+v", index, addresses[index], want[index])
		}
	}
}

func TestSubscriptionDomainsPublishWithoutDiscoveredIPs(t *testing.T) {
	registry, err := pool.Open(filepath.Join(t.TempDir(), "outbound-pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.SetSubscriptionDomains("edge-1", "v4.edge.example", "v6.edge.example"); err != nil {
		t.Fatal(err)
	}
	addresses := subscriptionAddresses(registry, "edge-1", proxynode.SubscriptionAddressIPv6)
	if len(addresses) != 1 || addresses[0].family != "IPv6" || addresses[0].address != "v6.edge.example" {
		t.Fatalf("subscriptionAddresses() = %+v", addresses)
	}
}

func (roundTrip geositeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestPublicSurgeGeositeRuleSetConvertsSuffixSyntax(t *testing.T) {
	handler := &Handler{
		logger: slog.Default(),
		geositeContent: &http.Client{Transport: geositeRoundTripper(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.list" {
				t.Fatalf("upstream URL = %q", request.URL.String())
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("+.openai.com\napi.openai.com\nregexp:ignored\n")), Header: make(http.Header)}, nil
		})},
	}
	request := httptest.NewRequest(http.MethodGet, "/subscription-rule-sets/geosite/openai", nil)
	request.SetPathValue("kind", "geosite")
	request.SetPathValue("name", "openai")
	response := httptest.NewRecorder()
	handler.publicSurgeRuleSet(response, request)
	if response.Code != http.StatusOK || response.Body.String() != ".openai.com\napi.openai.com\n" ||
		response.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("Geosite response = %d headers %#v body %q", response.Code, response.Header(), response.Body.String())
	}
}

func TestPublicSurgeGeositeRuleSetRejectsInvalidName(t *testing.T) {
	handler := &Handler{logger: slog.Default(), geositeContent: http.DefaultClient}
	request := httptest.NewRequest(http.MethodGet, "/subscription-rule-sets/geosite/invalid", nil)
	request.SetPathValue("kind", "geosite")
	request.SetPathValue("name", "../private")
	response := httptest.NewRecorder()
	handler.publicSurgeRuleSet(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("invalid Geosite status = %d", response.Code)
	}
}

func TestPublicSurgeGeoIPRuleSetConvertsCIDRs(t *testing.T) {
	handler := &Handler{
		logger: slog.Default(),
		geositeContent: &http.Client{Transport: geositeRoundTripper(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/private.list" {
				t.Fatalf("upstream URL = %q", request.URL.String())
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("10.0.0.0/8\nfd00::/8\ninvalid\n")), Header: make(http.Header)}, nil
		})},
	}
	request := httptest.NewRequest(http.MethodGet, "/subscription-rule-sets/geoip/private", nil)
	request.SetPathValue("kind", "geoip")
	request.SetPathValue("name", "private")
	response := httptest.NewRecorder()
	handler.publicSurgeRuleSet(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "IP-CIDR,10.0.0.0/8,no-resolve\nIP-CIDR6,fd00::/8,no-resolve\n" {
		t.Fatalf("GeoIP response = %d body %q", response.Code, response.Body.String())
	}
}

func TestPublicSurgeRuleSetCachesConvertedResponse(t *testing.T) {
	var requests atomic.Int32
	handler := &Handler{
		logger: slog.Default(),
		geositeContent: &http.Client{Transport: geositeRoundTripper(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("+.example.com\n")), Header: make(http.Header)}, nil
		})},
	}
	for range 2 {
		request := httptest.NewRequest(http.MethodGet, "/subscription-rule-sets/geosite/example", nil)
		request.SetPathValue("kind", "geosite")
		request.SetPathValue("name", "example")
		response := httptest.NewRecorder()
		handler.publicSurgeRuleSet(response, request)
		if response.Code != http.StatusOK || response.Body.String() != ".example.com\n" {
			t.Fatalf("cached response = %d %q", response.Code, response.Body.String())
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("upstream request count = %d, want 1", requests.Load())
	}
}

func TestPublicSurgeRuleSetRateLimit(t *testing.T) {
	handler := &Handler{
		logger: slog.Default(),
		geositeContent: &http.Client{Transport: geositeRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("example.com\n")), Header: make(http.Header)}, nil
		})},
	}
	for index := 0; index <= publicRuleSetRequestsPerMinute; index++ {
		request := httptest.NewRequest(http.MethodGet, "/subscription-rule-sets/geosite/example", nil)
		request.RemoteAddr = "192.0.2.9:1234"
		request.SetPathValue("kind", "geosite")
		request.SetPathValue("name", "example")
		response := httptest.NewRecorder()
		handler.publicSurgeRuleSet(response, request)
		if index < publicRuleSetRequestsPerMinute && response.Code != http.StatusOK {
			t.Fatalf("request %d status = %d", index+1, response.Code)
		}
		if index == publicRuleSetRequestsPerMinute && (response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "60") {
			t.Fatalf("limited response = %d headers %#v", response.Code, response.Header())
		}
	}
}

func TestPublicClientIdentityUsesCloudflareAddress(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/subscription-rule-sets/geosite/example", nil)
	request.Header.Set("CF-Connecting-IP", "2001:db8::42")
	request.Header.Set("X-Forwarded-For", "198.51.100.10, 127.0.0.1")
	if got := publicClientIdentity(request); got != "2001:db8::42" {
		t.Fatalf("public client identity = %q", got)
	}
}
