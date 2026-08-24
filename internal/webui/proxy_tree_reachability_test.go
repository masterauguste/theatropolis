package webui

import (
	"testing"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

func TestProxyTreeConstraintPrunesOnlyProvenImpossiblePaths(t *testing.T) {
	httpRule := proxynode.Rule{Match: proxynode.MatchProtocol, Values: []string{"http"}}
	bittorrentRule := proxynode.Rule{Match: proxynode.MatchProtocol, Values: []string{"bittorrent"}}
	selectedHTTP := proxyTreeConstraint{}.selectRule(httpRule, nil)
	if !selectedHTTP.selectRule(httpRule, nil).feasible() {
		t.Fatal("matching protocol constraints were pruned")
	}
	if selectedHTTP.selectRule(bittorrentRule, nil).feasible() {
		t.Fatal("contradictory protocol constraints remained reachable")
	}

	parentCIDR := proxynode.Rule{Match: proxynode.MatchIPCIDR, Values: []string{"203.0.113.0/24"}}
	insideCIDR := proxynode.Rule{Match: proxynode.MatchIPCIDR, Values: []string{"203.0.113.128/25"}}
	outsideCIDR := proxynode.Rule{Match: proxynode.MatchIPCIDR, Values: []string{"198.51.100.0/24"}}
	selectedCIDR := proxyTreeConstraint{}.selectRule(parentCIDR, nil)
	if !selectedCIDR.selectRule(insideCIDR, nil).feasible() {
		t.Fatal("overlapping CIDRs were pruned")
	}
	if selectedCIDR.selectRule(outsideCIDR, nil).feasible() {
		t.Fatal("disjoint CIDRs remained reachable")
	}

	domainRule := proxynode.Rule{Match: proxynode.MatchDomain, Values: []string{"cdn.example.com"}}
	domainToIP := proxyTreeConstraint{}.selectRule(domainRule, nil).selectRule(parentCIDR, nil)
	if !domainToIP.feasible() {
		t.Fatal("runtime-dependent domain-to-IP path was pruned")
	}
	if !domainToIP.runtimeDependent() {
		t.Fatal("domain-to-IP path was not marked runtime-dependent")
	}
}

func TestProxyTreeConstraintTracksFirstMatchExclusions(t *testing.T) {
	parent := proxynode.Rule{Match: proxynode.MatchDomain, Values: []string{"api.example.com"}}
	earlier := proxynode.Rule{Match: proxynode.MatchDomainSuffix, Values: []string{"example.com"}}
	constraint := proxyTreeConstraint{}.selectRule(parent, nil)
	if constraint.selectFallback([]proxynode.Rule{earlier}).feasible() {
		t.Fatal("fallback remained reachable after an earlier rule covered the complete parent path")
	}
	if constraint.selectRule(parent, []proxynode.Rule{earlier}).feasible() {
		t.Fatal("a later rule remained reachable after a covering first-match rule")
	}
}

func TestBuildProxyTreePropagatesRuleConstraints(t *testing.T) {
	httpRule := proxynode.Rule{ID: "rule-http", Match: proxynode.MatchProtocol, Values: []string{"http"}}
	bittorrentRule := proxynode.Rule{ID: "rule-bt", Match: proxynode.MatchProtocol, Values: []string{"bittorrent"}}
	node := proxyReachabilityNode(httpRule, []proxynode.Rule{bittorrentRule, httpRule})

	tree, exits, _ := buildProxyTree(node)
	if tree == nil || len(tree.Branches) != 1 || tree.Branches[0].Child == nil {
		t.Fatalf("unexpected root tree: %#v", tree)
	}
	child := tree.Branches[0].Child
	if len(child.Branches) != 1 {
		t.Fatalf("B displayed %d B-to-C branches behind the HTTP A-to-B path, want 1", len(child.Branches))
	}
	if got := child.Branches[0].RuleValues; got != "http" {
		t.Fatalf("reachable B-to-C rule = %q, want http", got)
	}
	if child.ShowFallback {
		t.Fatal("B terminal remained visible even though its HTTP path is fully routed to C")
	}
	if exits != 2 { // C's Direct exit plus A's unmatched Direct exit.
		t.Fatalf("visible exits = %d, want 2", exits)
	}
}

func TestBuildProxyTreeKeepsDomainToIPPathsAsRuntimeDependent(t *testing.T) {
	domainRule := proxynode.Rule{ID: "rule-domain", Match: proxynode.MatchDomain, Values: []string{"cdn.example.com"}}
	ipRule := proxynode.Rule{ID: "rule-ip", Match: proxynode.MatchIPCIDR, Values: []string{"203.0.113.0/24"}}
	node := proxyReachabilityNode(domainRule, []proxynode.Rule{ipRule})

	tree, _, _ := buildProxyTree(node)
	child := tree.Branches[0].Child
	if len(child.Branches) != 1 || !child.Branches[0].Uncertain {
		t.Fatalf("domain-to-IP branch = %#v, want one runtime-dependent branch", child.Branches)
	}
	if !child.ShowFallback || !child.Fallback.Uncertain {
		t.Fatal("runtime-dependent IP outcome did not preserve an uncertain terminal alternative")
	}
	if tree.RuntimeBranches != 2 {
		t.Fatalf("runtime-dependent path count = %d, want 2", tree.RuntimeBranches)
	}
}

func proxyReachabilityNode(parentRule proxynode.Rule, childRules []proxynode.Rule) proxynode.ProxyNode {
	endpoint := proxynode.Endpoint{Protocol: proxynode.ProtocolShadowsocks, Listen: "::", ListenPort: 20048}
	return proxynode.ProxyNode{
		ID: "proxy-test", Name: "Test", Entrance: proxynode.Entrance{HopID: "hop-a", Endpoint: endpoint},
		Hops: []proxynode.Hop{
			{ID: "hop-a", Name: "A", AgentID: "agent-a", Final: proxynode.Target{Type: proxynode.TargetDirect}},
			{ID: "hop-b", Name: "B", AgentID: "agent-b", Final: proxynode.Target{Type: proxynode.TargetDirect}},
			{ID: "hop-c", Name: "C", AgentID: "agent-c", Final: proxynode.Target{Type: proxynode.TargetDirect}},
		},
		Links: []proxynode.Link{
			{ID: "link-ab", ParentHopID: "hop-a", ChildHopID: "hop-b", Order: 0, Rules: []proxynode.Rule{parentRule}, Endpoint: endpoint},
			{ID: "link-bc", ParentHopID: "hop-b", ChildHopID: "hop-c", Order: 0, Rules: childRules, Endpoint: endpoint},
		},
	}
}
