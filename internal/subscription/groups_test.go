package subscription

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

func TestGroupsAndSpecificTargetsAcrossExports(t *testing.T) {
	profile := Profile{
		Nodes: []Node{
			{ID: "one", Family: "IPv4", Name: "Streaming", Protocol: proxynode.ProtocolAnyTLS, Server: "203.0.113.1", Port: 443, Password: "secret"},
			{ID: "one", Family: "IPv6", Name: "Streaming v6", Protocol: proxynode.ProtocolAnyTLS, Server: "2001:db8::1", Port: 443, Password: "secret"},
		},
		Groups: []proxynode.SubscriptionGroup{
			{ID: "manual", Name: "Streaming", Type: "select", Members: []proxynode.SubscriptionAction{"group:auto", "node:one:ipv6", "direct"}},
			{ID: "auto", Name: "Fastest", Type: "url-test", Members: []proxynode.SubscriptionAction{"node:one", "node:unassigned"}, Interval: 300, Tolerance: 50},
			{ID: "empty", Name: "Private", Type: "url-test", Members: []proxynode.SubscriptionAction{"node:unassigned"}, Interval: 300, Tolerance: 50},
		},
		Default: "group:manual",
		Rules: []proxynode.SubscriptionRule{
			{Match: proxynode.SubscriptionMatchDomain, Values: []string{"example.com"}, Action: "node:one:ipv6"},
			{Match: proxynode.SubscriptionMatchDomain, Values: []string{"denied.example"}, Action: "node:unassigned"},
		},
	}
	normalized := normalizeProfile(profile)
	groups := profileGroups(normalized)
	if !reflect.DeepEqual(groups[1].Members, []string{"Streaming 2", "Streaming v6"}) {
		t.Fatalf("wrong access/family projection: %+v", groups)
	}
	if groups[3].Type != "select" || !reflect.DeepEqual(groups[3].Members, []string{"REJECT"}) {
		t.Fatalf("empty group did not fail closed: %+v", groups[3])
	}
	if profile.Nodes[0].Name != "Streaming" {
		t.Fatal("render normalization mutated caller")
	}
	for _, format := range []Format{FormatClash, FormatSurge, FormatSingBox} {
		content, _, err := Render(format, profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{"node:one", "node:unassigned", "group:manual", "resolved:"} {
			if strings.Contains(string(content), raw) {
				t.Errorf("%s leaked internal reference %q", format, raw)
			}
		}
		if format == FormatSingBox {
			if binary := os.Getenv("THEATROPOLIS_TEST_SUBSCRIPTION_SING_BOX"); binary != "" {
				path := filepath.Join(t.TempDir(), "subscription.json")
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
				if output, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
					t.Fatalf("real sing-box rejected subscription: %v\n%s", err, output)
				}
			}
			var decoded struct {
				Outbounds []map[string]any
				Route     struct {
					Final string
					Rules []map[string]any
				}
				DNS struct {
					Servers []map[string]any
					Rules   []map[string]any
				}
			}
			if err := json.Unmarshal(content, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Route.Final != "Streaming" || decoded.Route.Rules[2]["outbound"] != "Streaming v6" || decoded.Route.Rules[3]["outbound"] != "REJECT" {
				t.Fatalf("wrong resolved policies: %s", content)
			}
			found := false
			for _, server := range decoded.DNS.Servers {
				if server["detour"] == "Streaming v6" {
					found = true
				}
			}
			if !found {
				t.Fatal("specific proxy DNS does not follow selected policy")
			}
		} else {
			if !strings.Contains(string(content), "denied.example,REJECT") || !strings.Contains(string(content), "Fastest") {
				t.Fatalf("%s targets missing: %s", format, content)
			}
		}
	}
}

func TestAllNodesGroupPlacesUserProxiesBetweenProxyAndDirectReject(t *testing.T) {
	profile := normalizeProfile(Profile{
		Nodes: []Node{
			{ID: "n1", Family: "IPv4", Name: "Tokyo", Protocol: proxynode.ProtocolAnyTLS, Server: "203.0.113.1", Port: 443, Password: "secret"},
			{ID: "n2", Family: "IPv4", Name: "Frankfurt", Protocol: proxynode.ProtocolAnyTLS, Server: "203.0.113.2", Port: 443, Password: "secret"},
		},
		Groups: []proxynode.SubscriptionGroup{
			{
				ID:       "sgp_netflix",
				Name:     "Netflix",
				Type:     "select",
				AllNodes: true,
				Members:  []proxynode.SubscriptionAction{proxynode.SubscriptionProxy, proxynode.SubscriptionAllNodes, proxynode.SubscriptionDirect, proxynode.SubscriptionReject},
			},
			{
				ID:       "sgp_nodesfirst",
				Name:     "NodesFirst",
				Type:     "select",
				AllNodes: true,
				Members:  []proxynode.SubscriptionAction{proxynode.SubscriptionAllNodes, proxynode.SubscriptionProxy, proxynode.SubscriptionDirect, proxynode.SubscriptionReject},
			},
			{
				ID:       "sgp_adblock",
				Name:     "AdBlock",
				Type:     "select",
				AllNodes: false,
				Members:  []proxynode.SubscriptionAction{proxynode.SubscriptionReject, proxynode.SubscriptionDirect},
			},
			{
				ID:       "sgp_apple",
				Name:     "Apple",
				Type:     "select",
				AllNodes: true,
				Members:  []proxynode.SubscriptionAction{proxynode.SubscriptionDirect, proxynode.SubscriptionReject},
			},
			{
				ID:       "sgp_auto",
				Name:     "Auto",
				Type:     "url-test",
				AllNodes: true,
				Interval: 300, Tolerance: 50,
			},
		},
	})
	groups := profileGroups(profile)
	want := map[string][]string{
		"PROXY":      {"Tokyo", "Frankfurt", "DIRECT", "REJECT"},
		"Netflix":    {"PROXY", "Tokyo", "Frankfurt", "DIRECT", "REJECT"},
		"NodesFirst": {"Tokyo", "Frankfurt", "PROXY", "DIRECT", "REJECT"},
		"AdBlock":    {"REJECT", "DIRECT"},
		"Apple":      {"DIRECT", "Tokyo", "Frankfurt", "REJECT"},
		"Auto":       {"Tokyo", "Frankfurt"},
	}
	for _, group := range groups {
		if expected, ok := want[group.Name]; ok && !reflect.DeepEqual(group.Members, expected) {
			t.Errorf("group %q members = %v, want %v", group.Name, group.Members, expected)
		}
	}
}
