package subscription

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

func TestRenderProfilesKeepNodesAndRulesSeparate(t *testing.T) {
	profile := Profile{
		Name: "alice", Default: proxynode.SubscriptionProxy, RuleSetBaseURL: "https://master.example/subscription-rule-sets",
		Nodes: []Node{
			{Name: "Cinema", Protocol: proxynode.ProtocolShadowsocks, Server: "203.0.113.8", Port: 20048, Method: "2022-blake3-aes-256-gcm", ServerKey: "server-key", Password: "user-key"},
			{Name: "Stage", Protocol: proxynode.ProtocolAnyTLS, Server: "2001:db8::8", Port: 443, Password: "secret", ServerName: "proxy.example.com", Insecure: true},
		},
		Rules: []proxynode.SubscriptionRule{
			{ID: "sru_012345678901234567890123", Order: 0, Match: proxynode.SubscriptionMatchDomainSuffix, Values: []string{"example.com"}, Action: proxynode.SubscriptionDirect},
			{ID: "sru_112345678901234567890123", Order: 1, Match: proxynode.SubscriptionMatchGeosite, Values: []string{"openai"}, Action: proxynode.SubscriptionReject},
			{ID: "sru_212345678901234567890123", Order: 2, Match: proxynode.SubscriptionMatchGeoIP, Values: []string{"CN"}, Action: proxynode.SubscriptionDirect},
			{ID: "sru_312345678901234567890123", Order: 3, Match: proxynode.SubscriptionMatchDomainRegex, Values: []string{"^api\\.example\\.com$"}, Action: proxynode.SubscriptionReject},
			{ID: "sru_412345678901234567890123", Order: 4, Match: proxynode.SubscriptionMatchNetwork, Values: []string{"tcp", "udp"}, Action: proxynode.SubscriptionProxy},
		},
	}
	clash, _, err := Render(FormatClash, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`password: "server-key:user-key"`, `"DOMAIN-SUFFIX,example.com,Direct"`, `"GEOSITE,openai,Reject"`, "geodata-mode: true", "MetaCubeX/meta-rules-dat@release/geoip.dat"} {
		if !strings.Contains(string(clash), want) {
			t.Fatalf("Clash profile missing %q:\n%s", want, clash)
		}
	}
	surge, _, err := Render(FormatSurge, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Proxy Group]", "Proxy = select", "DOMAIN-SUFFIX,example.com,Direct", "DOMAIN-SET,https://master.example/subscription-rule-sets/geosite/openai,Reject,update-interval=86400", "RULE-SET,https://master.example/subscription-rule-sets/geoip/cn,Direct,update-interval=86400"} {
		if !strings.Contains(string(surge), want) {
			t.Fatalf("Surge profile missing %q:\n%s", want, surge)
		}
	}
	if strings.Contains(string(surge), "URL-REGEX") || strings.Contains(string(surge), `^api\\.example`) {
		t.Fatalf("Surge profile exported incompatible domain regex:\n%s", surge)
	}
	for _, want := range []string{"PROTOCOL,TCP,Proxy", "PROTOCOL,UDP,Proxy"} {
		if !strings.Contains(string(surge), want) {
			t.Fatalf("Surge profile missing uppercase network rule %q:\n%s", want, surge)
		}
	}
	singBox, _, err := Render(FormatSingBox, profile)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(singBox, &decoded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(singBox), `"tag": "Proxy"`) ||
		!strings.Contains(string(singBox), `"type": "mixed"`) ||
		!strings.Contains(string(singBox), `"type": "tun"`) ||
		!strings.Contains(string(singBox), `"auto_route": true`) ||
		!strings.Contains(string(singBox), `"type": "local"`) ||
		!strings.Contains(string(singBox), `"default_domain_resolver": "local-dns"`) ||
		!strings.Contains(string(singBox), `"external_controller": "127.0.0.1:9090"`) ||
		!strings.Contains(string(singBox), `"cache_file"`) ||
		!strings.Contains(string(singBox), `"action": "sniff"`) ||
		!strings.Contains(string(singBox), `"action": "resolve"`) ||
		!strings.Contains(string(singBox), `"url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-openai.srs"`) ||
		!strings.Contains(string(singBox), `"url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"`) {
		t.Fatalf("sing-box profile is incomplete:\n%s", singBox)
	}
}

func TestEmptyProxyGroupFailsClosed(t *testing.T) {
	for _, format := range []Format{FormatClash, FormatSurge, FormatSingBox} {
		content, _, err := Render(format, Profile{Default: proxynode.SubscriptionProxy})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), "REJECT") && !strings.Contains(string(content), "Reject") {
			t.Fatalf("%s empty profile does not fail closed:\n%s", format, content)
		}
		if format == FormatClash && !strings.Contains(string(content), "proxies: []") {
			t.Fatalf("empty Clash profile has an invalid proxy list:\n%s", content)
		}
	}
}
