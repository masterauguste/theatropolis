package subscription

import (
	"strings"
	"testing"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

func TestPolicyNamesAreReservedAndGeneratedNamesCannotCollide(t *testing.T) {
	input := Profile{Nodes: []Node{{Name: "Direct"}, {Name: "DIRECT 2"}, {Name: "Direct"}, {Name: "PROXY"}, {Name: "Reject"}, {Name: "Node"}, {Name: "Node"}, {Name: "Node 2"}}}
	output := normalizeProfile(input)
	seen := map[string]bool{"direct": true, "reject": true, "proxy": true}
	for _, node := range output.Nodes {
		key := strings.ToLower(node.Name)
		if seen[key] {
			t.Fatalf("duplicate or reserved name %s", node.Name)
		}
		seen[key] = true
	}
	if input.Nodes[0].Name != "Direct" {
		t.Fatal("normalization mutated the caller's Nodes")
	}
}

func TestAllPolicyActionsUseResolvableTargets(t *testing.T) {
	for _, action := range []proxynode.SubscriptionAction{proxynode.SubscriptionDirect, proxynode.SubscriptionReject, proxynode.SubscriptionProxy} {
		for _, format := range []Format{FormatClash, FormatSurge, FormatSingBox} {
			profile := Profile{Default: action, Rules: []proxynode.SubscriptionRule{{Match: proxynode.SubscriptionMatchDomain, Values: []string{"example.com"}, Action: action}}}
			content, _, err := Render(format, profile)
			if err != nil {
				t.Fatal(err)
			}
			target := actionName(action)
			if format == FormatSingBox {
				if !strings.Contains(string(content), `"tag": "`+target+`"`) {
					t.Fatalf("undefined target %s: %s", target, content)
				}
			} else if !strings.Contains(string(content), "DOMAIN,example.com,"+target) {
				t.Fatalf("wrong policy target: %s", content)
			}
		}
	}
}
