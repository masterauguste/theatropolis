package subscription

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

func TestValidateNodeAcceptsDNSHostnamesAndRejectsURLs(t *testing.T) {
	base := Node{Name: "Cinema", Protocol: proxynode.ProtocolAnyTLS, Port: 443, Password: "secret"}
	for _, server := range []string{"203.0.113.8", "2001:db8::8", "v4.edge.example"} {
		node := base
		node.Server = server
		if err := ValidateNode(node); err != nil {
			t.Errorf("ValidateNode(%q) error = %v", server, err)
		}
	}
	for _, server := range []string{"", "localhost", "https://edge.example", "edge.example:443", "*.edge.example"} {
		node := base
		node.Server = server
		if err := ValidateNode(node); err == nil {
			t.Errorf("ValidateNode(%q) error = nil", server)
		}
	}
}

func TestRenderProfilesKeepNodesAndRulesSeparate(t *testing.T) {
	profile := Profile{
		Name: "alice", Default: proxynode.SubscriptionProxy, RuleSetBaseURL: "https://master.example/subscription-rule-sets",
		Nodes: []Node{
			{Name: "Cinema", Protocol: proxynode.ProtocolShadowsocks, Server: "203.0.113.8", Port: 20048, Method: "2022-blake3-aes-256-gcm", ServerKey: "server-key", Password: "user-key"},
			{Name: "Stage", Protocol: proxynode.ProtocolAnyTLS, Server: "v6.edge.example", Port: 443, Password: "secret", ServerName: "proxy.example.com", Insecure: true},
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
	for _, want := range []string{`password: "server-key:user-key"`, `server: "v6.edge.example"`, `"DOMAIN-SUFFIX,example.com,Direct"`, `"GEOSITE,openai,Reject"`, "geodata-mode: true", "MetaCubeX/meta-rules-dat@release/geoip.dat"} {
		if !strings.Contains(string(clash), want) {
			t.Fatalf("Clash profile missing %q:\n%s", want, clash)
		}
	}
	if !strings.Contains(string(clash), "      - DIRECT\n      - REJECT\n") {
		t.Fatalf("Clash Proxy group does not offer Direct and Reject in order:\n%s", clash)
	}
	surge, _, err := Render(FormatSurge, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Proxy Group]", "Proxy = select", "v6.edge.example", "DOMAIN-SUFFIX,example.com,Direct", "DOMAIN-SET,https://master.example/subscription-rule-sets/geosite/openai,Reject,update-interval=86400", "RULE-SET,https://master.example/subscription-rule-sets/geoip/cn,Direct,update-interval=86400"} {
		if !strings.Contains(string(surge), want) {
			t.Fatalf("Surge profile missing %q:\n%s", want, surge)
		}
	}
	if !strings.Contains(string(surge), "Proxy = select, Cinema, Stage, DIRECT, REJECT") {
		t.Fatalf("Surge Proxy group does not offer Direct and Reject after its Nodes:\n%s", surge)
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
		!strings.Contains(string(singBox), `"server": "v6.edge.example"`) ||
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
	if !singBoxSelectorHasMembers(decoded, "Proxy", []string{"Cinema", "Stage", "Direct", "Reject"}) {
		t.Fatalf("sing-box Proxy selector does not offer Direct and Reject after its Nodes:\n%s", singBox)
	}
}

func singBoxSelectorHasMembers(root map[string]any, tag string, want []string) bool {
	outbounds, ok := root["outbounds"].([]any)
	if !ok {
		return false
	}
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if !ok || outbound["type"] != "selector" || outbound["tag"] != tag {
			continue
		}
		members, ok := outbound["outbounds"].([]any)
		if !ok || len(members) != len(want) {
			return false
		}
		for index := range want {
			if members[index] != want[index] {
				return false
			}
		}
		return true
	}
	return false
}

func TestEmptyProxyGroupUsesDirect(t *testing.T) {
	for _, format := range []Format{FormatClash, FormatSurge, FormatSingBox} {
		content, _, err := Render(format, Profile{Default: proxynode.SubscriptionProxy})
		if err != nil {
			t.Fatal(err)
		}
		if format == FormatClash && !strings.Contains(string(content), "proxies: []") {
			t.Fatalf("empty Clash profile has an invalid proxy list:\n%s", content)
		}
		if format == FormatClash && !strings.Contains(string(content), "      - DIRECT\n      - REJECT\n") {
			t.Fatalf("empty Clash Proxy group does not offer Direct then Reject:\n%s", content)
		}
		if format == FormatSurge && !strings.Contains(string(content), "Proxy = select, DIRECT, REJECT") {
			t.Fatalf("empty Surge Proxy group does not offer Direct then Reject:\n%s", content)
		}
		if format == FormatSingBox {
			var decoded map[string]any
			if err := json.Unmarshal(content, &decoded); err != nil {
				t.Fatal(err)
			}
			if !singBoxSelectorHasMembers(decoded, "Proxy", []string{"Direct", "Reject"}) {
				t.Fatalf("empty sing-box Proxy selector does not offer Direct then Reject:\n%s", content)
			}
		}
	}
}
