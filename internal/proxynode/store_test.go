package proxynode

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

func testBuild() BuildInfo {
	return BuildInfo{Component: "master", Version: "v1.0.0", Commit: "test-commit"}
}

func testTLSEndpoint(protocol Protocol, port int) Endpoint {
	return Endpoint{
		Protocol: protocol, Listen: "::", ListenPort: port, Family: "ipv4",
		TLS: TLSConfig{Mode: TLSModeSelfSigned, ServerName: "proxy.example.com"},
	}
}

func TestStorePersistsUsersTopologyAndGeneratedCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	alice, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootName: "Entrance", RootAgent: "edge-a",
		Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := store.AddMembership(node.ID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	link, child, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-b",
		Endpoint: testTLSEndpoint(ProtocolHysteria2, 8443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if membership.Credential.Secret == "" || link.Credential.Secret == "" || membership.Credential.Secret == link.Credential.Secret {
		t.Fatal("membership and Link did not receive distinct generated credentials")
	}
	if _, err := store.AddRule(node.ID, AddRuleInput{
		LinkID: link.ID, Match: MatchDomainSuffix,
		Values: []string{"example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFinal(node.ID, child.ID, Target{Type: TargetReject}); err != nil {
		t.Fatal(err)
	}
	if err := store.RenameProxyNode(node.ID, "archive"); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Open(path, BuildInfo{Component: "master", Version: "v1.1.0", Commit: "new-commit"})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.ProxyNode(node.ID)
	if !ok || got.Name != "archive" || len(got.Links) != 1 || len(got.Links[0].Rules) != 1 {
		t.Fatalf("reloaded Proxy Node = %#v, exists %v", got, ok)
	}
	if got.Memberships[0].Credential.Secret != membership.Credential.Secret || got.Links[0].Credential.Secret != link.Credential.Secret {
		t.Fatal("rename or reload rotated credentials")
	}
	if err := reloaded.MarkReady(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), `"version": "v1.1.0"`) || !strings.Contains(string(contents), `"commit": "new-commit"`) {
		t.Fatalf("ready state did not stamp new build: %s", contents)
	}
}

func TestSchemaSixteenMigrationOnlyAdvancesUserAuthorityRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("用户 一")
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "上海 节点", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID,
		ChildAgent:  "edge-b",
		Endpoint:    testTLSEndpoint(ProtocolHysteria2, 8443),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy envelope
	if err := json.Unmarshal(contents, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy.SchemaVersion = 16
	before := cloneState(legacy.Data)
	encoded, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migrated.Close() })
	want := cloneState(before)
	want.UserRevision++
	normalizeTimes := func(state *State) {
		for index := range state.Users {
			state.Users[index].CreatedAt = state.Users[index].CreatedAt.UTC()
			state.Users[index].UpdatedAt = state.Users[index].UpdatedAt.UTC()
			state.Users[index].Subscription.UpdatedAt = state.Users[index].Subscription.UpdatedAt.UTC()
		}
		for nodeIndex := range state.ProxyNodes {
			node := &state.ProxyNodes[nodeIndex]
			node.CreatedAt = node.CreatedAt.UTC()
			node.UpdatedAt = node.UpdatedAt.UTC()
			for hopIndex := range node.Hops {
				node.Hops[hopIndex].CreatedAt = node.Hops[hopIndex].CreatedAt.UTC()
				node.Hops[hopIndex].UpdatedAt = node.Hops[hopIndex].UpdatedAt.UTC()
			}
			for linkIndex := range node.Links {
				node.Links[linkIndex].CreatedAt = node.Links[linkIndex].CreatedAt.UTC()
				node.Links[linkIndex].UpdatedAt = node.Links[linkIndex].UpdatedAt.UTC()
			}
			for membershipIndex := range node.Memberships {
				membership := &node.Memberships[membershipIndex]
				membership.QuotaPeriodStartedOn = membership.QuotaPeriodStartedOn.UTC()
				membership.QuotaResetsAfter = membership.QuotaResetsAfter.UTC()
				membership.SubscriptionStartedAt = membership.SubscriptionStartedAt.UTC()
				membership.SubscriptionEndsAfter = membership.SubscriptionEndsAfter.UTC()
				membership.CreatedAt = membership.CreatedAt.UTC()
			}
		}
	}
	got := migrated.Snapshot()
	normalizeTimes(&got)
	normalizeTimes(&want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schema v16 migration changed data besides UserRevision:\n got: %#v\nwant: %#v", got, want)
	}
	if err := migrated.MarkReady(); err != nil {
		t.Fatal(err)
	}
	contents, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted envelope
	if err := json.Unmarshal(contents, &persisted); err != nil {
		t.Fatal(err)
	}
	if SchemaVersion != 17 {
		t.Fatalf("test requires current schema v17, got v%d", SchemaVersion)
	}
	if persisted.SchemaVersion != SchemaVersion {
		t.Fatalf("persisted schema version = %d, want %d", persisted.SchemaVersion, SchemaVersion)
	}
	normalizeTimes(&persisted.Data)
	if !reflect.DeepEqual(persisted.Data, want) {
		t.Fatal("MarkReady changed migrated state while persisting schema v17")
	}
}

func TestAddBranchAtomicallyCreatesRuleLinkAndChildBeforeFallback(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	fallback, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "Fallback", ChildAgent: "edge-c",
		Endpoint: testTLSEndpoint(ProtocolAnyTLS, 9443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetLinkFallback(node.ID, fallback.ID, true); err != nil {
		t.Fatal(err)
	}

	link, child, rule, err := store.AddBranch(node.ID, AddBranchInput{
		AddLinkInput: AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-b",
			Endpoint: testTLSEndpoint(ProtocolHysteria2, 8443), Final: Target{Type: TargetReject},
		},
		Match: MatchDomainSuffix, Values: []string{"example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := store.ProxyNode(node.ID)
	linkIndex := slices.IndexFunc(got.Links, func(candidate Link) bool { return candidate.ID == link.ID })
	fallbackIndex := slices.IndexFunc(got.Links, func(candidate Link) bool { return candidate.ID == fallback.ID })
	if linkIndex < 0 || fallbackIndex < 0 || got.Links[linkIndex].Order != 0 || got.Links[fallbackIndex].Order != 1 {
		t.Fatalf("branch was not inserted before fallback: %#v", got.Links)
	}
	if got.Links[linkIndex].ChildHopID != child.ID || len(got.Links[linkIndex].Rules) != 1 || got.Links[linkIndex].Rules[0].ID != rule.ID || rule.Order != 0 {
		t.Fatalf("branch components were not created together: link=%#v child=%#v rule=%#v", got.Links[linkIndex], child, rule)
	}

	beforeHops, beforeLinks := len(got.Hops), len(got.Links)
	if _, _, _, err := store.AddBranch(node.ID, AddBranchInput{
		AddLinkInput: AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildName: "Invalid", ChildAgent: "edge-d",
			Endpoint: testTLSEndpoint(ProtocolAnyTLS, 10443),
		},
		Match: MatchNone, Values: []string{"fallbacks-have-no-values"},
	}); err == nil {
		t.Fatal("ALL branch with match values was accepted")
	}
	got, _ = store.ProxyNode(node.ID)
	if len(got.Hops) != beforeHops || len(got.Links) != beforeLinks {
		t.Fatalf("failed branch left topology artifacts: %#v", got)
	}
}

func TestBlockBranchRejectsMatchingTrafficWithoutCreatingRelayTopology(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	block, err := store.AddBlockBranch(node.ID, AddBlockBranchInput{
		ParentHopID: node.Entrance.HopID, Match: MatchDomainSuffix, Values: []string{"ads.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := store.ProxyNode(node.ID)
	if len(got.Hops) != 1 || len(got.Links) != 0 || len(got.BlockBranches) != 1 || block.Rule.Order != 0 {
		t.Fatalf("BLOCK branch created relay topology: %#v", got)
	}
	if _, err := store.AddBlockBranch(node.ID, AddBlockBranchInput{ParentHopID: node.Entrance.HopID, Match: MatchNone}); err == nil {
		t.Fatal("ALL was accepted as a conditional BLOCK branch")
	}

	link, _, rule, err := store.AddBranch(node.ID, AddBranchInput{
		AddLinkInput: AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-b",
			Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443),
		},
		Match: MatchDomain, Values: []string{"allowed.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReorderRules(node.ID, node.Entrance.HopID, []string{rule.ID, block.Rule.ID}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateBlockBranch(node.ID, block.Rule.ID, UpdateRuleInput{Match: MatchDomain, Values: []string{"blocked.example"}}); err != nil {
		t.Fatal(err)
	}

	compiled, err := Compile(store.Snapshot(), testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(compiled.Configs["edge-a"], &config); err != nil {
		t.Fatal(err)
	}
	routes := make([]map[string]any, 0, len(config.Route.Rules))
	for _, candidate := range config.Route.Rules {
		if candidate["action"] != "sniff" && candidate["action"] != "resolve" {
			routes = append(routes, candidate)
		}
	}
	if len(routes) < 3 || routes[0]["outbound"] != linkOutboundTag(link.ID) || routes[1]["action"] != "reject" {
		t.Fatalf("compiled BLOCK priority/action = %#v", config.Route.Rules)
	}
	if domains, ok := routes[1]["domain"].([]any); !ok || len(domains) != 1 || domains[0] != "blocked.example" {
		t.Fatalf("compiled BLOCK match = %#v", routes[1])
	}
	if _, exists := routes[1]["outbound"]; exists {
		t.Fatalf("BLOCK unexpectedly has an outbound: %#v", routes[1])
	}
	if err := store.DeleteBlockBranch(node.ID, block.Rule.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = store.ProxyNode(node.ID)
	if len(got.BlockBranches) != 0 || got.Links[0].Rules[0].Order != 0 {
		t.Fatalf("deleting BLOCK did not normalize remaining priorities: %#v", got)
	}
}

func TestAllMatchCreatesAndConvertsFallbackBranches(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	conditional, _, conditionalRule, err := store.AddBranch(node.ID, AddBranchInput{
		AddLinkInput: AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildName: "Conditional", ChildAgent: "edge-b",
			Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443),
		},
		Match: MatchDomainSuffix, Values: []string{"example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	fallback, child, fallbackRule, err := store.AddBranch(node.ID, AddBranchInput{
		AddLinkInput: AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildName: "Fallback", ChildAgent: "edge-c",
			Endpoint: testTLSEndpoint(ProtocolHysteria2, 9443), Final: Target{Type: TargetReject},
		},
		Match: MatchNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fallbackRule.ID != "" || !fallback.Fallback || len(fallback.Rules) != 0 || fallback.ChildHopID != child.ID {
		t.Fatalf("ALL branch = link %#v child %#v rule %#v", fallback, child, fallbackRule)
	}
	got, _ := store.ProxyNode(node.ID)
	conditionalIndex := slices.IndexFunc(got.Links, func(link Link) bool { return link.ID == conditional.ID })
	fallbackIndex := slices.IndexFunc(got.Links, func(link Link) bool { return link.ID == fallback.ID })
	if conditionalIndex < 0 || fallbackIndex < 0 || got.Links[conditionalIndex].Order != 0 || got.Links[fallbackIndex].Order != 1 {
		t.Fatalf("ALL branch was not last: %#v", got.Links)
	}
	beforeHops, beforeLinks := len(got.Hops), len(got.Links)
	if _, _, _, err := store.AddBranch(node.ID, AddBranchInput{
		AddLinkInput: AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildName: "Duplicate", ChildAgent: "edge-d",
			Endpoint: testTLSEndpoint(ProtocolAnyTLS, 10443),
		},
		Match: MatchNone,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second ALL branch error = %v, want conflict", err)
	}
	got, _ = store.ProxyNode(node.ID)
	if len(got.Hops) != beforeHops || len(got.Links) != beforeLinks {
		t.Fatalf("rejected ALL branch left topology artifacts: %#v", got)
	}
	if err := store.DeleteLink(node.ID, fallback.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateRule(node.ID, conditionalRule.ID, UpdateRuleInput{LinkID: conditional.ID, Match: MatchNone}); err != nil {
		t.Fatal(err)
	}
	got, _ = store.ProxyNode(node.ID)
	if len(got.Links) != 1 || !got.Links[0].Fallback || len(got.Links[0].Rules) != 0 {
		t.Fatalf("Rule-to-ALL conversion = %#v", got.Links)
	}
}

func TestUpdateRuleEditsOnlyItsBranchWithoutRotatingCredential(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	link, child, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-b",
		Endpoint: testTLSEndpoint(ProtocolHysteria2, 8443),
	})
	if err != nil {
		t.Fatal(err)
	}
	target, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "Alternate", ChildAgent: "edge-c",
		Endpoint: testTLSEndpoint(ProtocolAnyTLS, 9443),
	})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := store.AddRule(node.ID, AddRuleInput{LinkID: link.ID, Match: MatchDomain, Values: []string{"old.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateRule(node.ID, rule.ID, UpdateRuleInput{
		LinkID: link.ID,
		Match:  MatchIPCIDR, Values: []string{"203.0.113.0/24"},
	}); err != nil {
		t.Fatal(err)
	}

	updated, ok := store.ProxyNode(node.ID)
	if !ok || len(updated.Links) != 2 {
		t.Fatalf("updated Proxy Node = %#v, exists %v", updated, ok)
	}
	sourceIndex := slices.IndexFunc(updated.Links, func(candidate Link) bool { return candidate.ID == link.ID })
	targetIndex := slices.IndexFunc(updated.Links, func(candidate Link) bool { return candidate.ID == target.ID })
	if sourceIndex < 0 || targetIndex < 0 {
		t.Fatalf("updated Links = %#v", updated.Links)
	}
	if updated.Links[sourceIndex].Credential != link.Credential || updated.Links[targetIndex].Credential != target.Credential {
		t.Fatal("editing a Rule rotated a Link credential")
	}
	if len(updated.Links[sourceIndex].Rules) != 1 || len(updated.Links[targetIndex].Rules) != 0 {
		t.Fatalf("Rule left its isolated branch: %#v", updated.Links)
	}
	got := updated.Links[sourceIndex].Rules[0]
	if got.ID != rule.ID || got.Match != MatchIPCIDR || !slices.Equal(got.Values, []string{"203.0.113.0/24"}) {
		t.Fatalf("updated Rule = %#v", got)
	}
	_, _, err = store.AddLink(node.ID, AddLinkInput{
		ParentHopID: child.ID, ChildName: "Nested", ChildAgent: "edge-d",
		Endpoint: testTLSEndpoint(ProtocolHysteria2, 10443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateRule(node.ID, rule.ID, UpdateRuleInput{
		LinkID: target.ID, Match: MatchProtocol, Values: []string{"http"},
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("edit Rule through another Link error = %v, want ErrNotFound", err)
	}
}

func TestSecondRuleCreatesIndependentBranchAndClonesDownstreamContext(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	rootLink, child, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "Transit", ChildAgent: "edge-b",
		Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443),
	})
	if err != nil {
		t.Fatal(err)
	}
	downstream, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: child.ID, ChildName: "Exit", ChildAgent: "edge-c",
		Endpoint: testTLSEndpoint(ProtocolHysteria2, 9443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddRule(node.ID, AddRuleInput{LinkID: downstream.ID, Match: MatchDomain, Values: []string{"inside.example"}}); err != nil {
		t.Fatal(err)
	}
	first, err := store.AddRule(node.ID, AddRuleInput{LinkID: rootLink.ID, Match: MatchDomainSuffix, Values: []string{"net.coffee"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddRule(node.ID, AddRuleInput{LinkID: rootLink.ID, Match: MatchDomainSuffix, Values: []string{"bgp.he.net"}})
	if err != nil {
		t.Fatal(err)
	}

	got, _ := store.ProxyNode(node.ID)
	rootBranches := make([]Link, 0, 2)
	for _, link := range got.Links {
		if link.ParentHopID == node.Entrance.HopID {
			rootBranches = append(rootBranches, link)
		}
		if len(link.Rules) > 1 {
			t.Fatalf("Link retained multiple routing Rules: %#v", link)
		}
	}
	if len(rootBranches) != 2 {
		t.Fatalf("root branch count = %d, want 2: %#v", len(rootBranches), rootBranches)
	}
	if rootBranches[0].ChildHopID == rootBranches[1].ChildHopID || rootBranches[0].Credential == rootBranches[1].Credential {
		t.Fatalf("branches share logical context or credential: %#v", rootBranches)
	}
	if rootBranches[0].Endpoint != rootBranches[1].Endpoint {
		t.Fatalf("compatible physical listener settings were not copied: %#v", rootBranches)
	}
	ruleLinks := map[string]Link{}
	for _, link := range rootBranches {
		if len(link.Rules) == 1 {
			ruleLinks[link.Rules[0].ID] = link
		}
	}
	if _, exists := ruleLinks[first.ID]; !exists {
		t.Fatalf("first Rule branch missing: %#v", rootBranches)
	}
	if _, exists := ruleLinks[second.ID]; !exists {
		t.Fatalf("second Rule branch missing: %#v", rootBranches)
	}
	for _, root := range rootBranches {
		children := 0
		for _, link := range got.Links {
			if link.ParentHopID == root.ChildHopID {
				children++
				if len(link.Rules) != 1 || link.Rules[0].Match != MatchDomain {
					t.Fatalf("downstream Rule was not cloned with the branch: %#v", link)
				}
			}
		}
		if children != 1 {
			t.Fatalf("branch child count = %d, want 1", children)
		}
	}

	compiled, err := Compile(store.Snapshot(), testResolver{
		"edge-a": "192.0.2.10", "edge-b": "192.0.2.11", "edge-c": "192.0.2.12",
	})
	if err != nil {
		t.Fatal(err)
	}
	var transit struct {
		Inbounds []struct {
			Users []struct {
				Name string `json:"name"`
			} `json:"users"`
		} `json:"inbounds"`
		Route struct {
			Rules []struct {
				AuthUser []string `json:"auth_user"`
				Domain   []string `json:"domain"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(compiled.Configs["edge-b"], &transit); err != nil {
		t.Fatal(err)
	}
	if len(transit.Inbounds) != 1 || len(transit.Inbounds[0].Users) != 2 {
		t.Fatalf("shared physical listener users = %#v", transit.Inbounds)
	}
	authUsers := make(map[string]bool)
	for _, rule := range transit.Route.Rules {
		if slices.Equal(rule.Domain, []string{"inside.example"}) && len(rule.AuthUser) == 1 {
			authUsers[rule.AuthUser[0]] = true
		}
	}
	if len(authUsers) != 2 {
		t.Fatalf("downstream routing was not scoped to two branch auth_users: %#v", transit.Route.Rules)
	}
}

func TestMoveHopPreservesSubtreeAndReplaceLinkDestinationDeletesIt(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	root, child, rule, err := store.AddBranch(node.ID, AddBranchInput{
		AddLinkInput: AddLinkInput{ParentHopID: node.Entrance.HopID, ChildAgent: "edge-b", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)},
		Match:        MatchDomainSuffix, Values: []string{"example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: child.ID, ChildAgent: "edge-a", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 10442),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeated ancestor Agent AddLink error = %v, want ErrConflict", err)
	}
	nested, grandchild, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: child.ID, ChildAgent: "edge-c", Endpoint: testTLSEndpoint(ProtocolHysteria2, 9443),
	})
	if err != nil {
		t.Fatal(err)
	}
	block, err := store.AddBlockBranch(node.ID, AddBlockBranchInput{
		ParentHopID: child.ID, Match: MatchProtocol, Values: []string{"bittorrent"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.MoveHop(node.ID, child.ID, "edge-d"); err != nil {
		t.Fatal(err)
	}
	moved, _ := store.ProxyNode(node.ID)
	movedChildIndex := slices.IndexFunc(moved.Hops, func(hop Hop) bool { return hop.ID == child.ID })
	if movedChildIndex < 0 || moved.Hops[movedChildIndex].AgentID != "edge-d" || moved.Hops[movedChildIndex].Name != "edge-d" {
		t.Fatalf("moved Hop = %#v", moved.Hops)
	}
	if !slices.ContainsFunc(moved.Links, func(link Link) bool { return link.ID == nested.ID && link.ParentHopID == child.ID }) ||
		!slices.ContainsFunc(moved.Hops, func(hop Hop) bool { return hop.ID == grandchild.ID }) ||
		!slices.ContainsFunc(moved.BlockBranches, func(branch BlockBranch) bool { return branch.Rule.ID == block.Rule.ID }) {
		t.Fatalf("moving Hop changed its subtree: %#v", moved)
	}
	if _, err := store.ReplaceLinkDestination(
		node.ID,
		root.ID,
		"edge-a",
		testTLSEndpoint(ProtocolAnyTLS, 10443),
		Target{Type: TargetDirect},
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeated ancestor Agent replacement error = %v, want ErrConflict", err)
	}

	replacementEndpoint := Endpoint{
		Protocol: ProtocolShadowsocks, Listen: "::", ListenPort: 10443, Family: "auto", Method: "2022-blake3-aes-128-gcm",
	}
	replacement, err := store.ReplaceLinkDestination(node.ID, root.ID, "edge-e", replacementEndpoint, Target{Type: TargetReject})
	if err != nil {
		t.Fatal(err)
	}
	updated, _ := store.ProxyNode(node.ID)
	retainedIndex := slices.IndexFunc(updated.Links, func(link Link) bool { return link.ID == root.ID })
	if retainedIndex < 0 {
		t.Fatal("destination replacement removed the parent Link")
	}
	retained := updated.Links[retainedIndex]
	if retained.ChildHopID != replacement.ID || retained.Credential == root.Credential || retained.Order != root.Order ||
		len(retained.Rules) != 1 || retained.Rules[0].ID != rule.ID {
		t.Fatalf("retained Link = %#v", retained)
	}
	if replacement.AgentID != "edge-e" || replacement.Name != "edge-e" || replacement.Final.Type != TargetReject {
		t.Fatalf("replacement Hop = %#v", replacement)
	}
	for _, removedID := range []string{child.ID, grandchild.ID} {
		if slices.ContainsFunc(updated.Hops, func(hop Hop) bool { return hop.ID == removedID }) {
			t.Fatalf("removed subtree Hop %q remains: %#v", removedID, updated.Hops)
		}
	}
	if slices.ContainsFunc(updated.Links, func(link Link) bool { return link.ID == nested.ID }) ||
		slices.ContainsFunc(updated.BlockBranches, func(branch BlockBranch) bool { return branch.Rule.ID == block.Rule.ID }) {
		t.Fatalf("removed subtree routing artifacts remain: %#v", updated)
	}
}

func TestOpenMigratesSchemaV3MultiRuleLinksIntoIndependentBranches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	link, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-b", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)})
	first, _ := store.AddRule(node.ID, AddRuleInput{LinkID: link.ID, Match: MatchDomainSuffix, Values: []string{"net.coffee"}})
	state := store.Snapshot()
	state.ProxyNodes[0].Links[0].Rules = append(state.ProxyNodes[0].Links[0].Rules, Rule{
		ID: "rul_abcdefghijklmnopqrst", Order: 1, Match: MatchDomainSuffix, Values: []string{"bgp.he.net"},
	})
	legacy := envelope{Schema: SchemaID, SchemaVersion: 3, LastUsedBy: normalizeBuild(testBuild(), time.Now()), Data: state}
	contents, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(contents, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := migrated.ProxyNode(node.ID)
	if len(got.Links) != 2 || len(got.Hops) != 3 {
		t.Fatalf("migrated topology = %#v", got)
	}
	if got.Links[0].ID != link.ID || got.Links[0].Rules[0].ID != first.ID {
		t.Fatalf("first branch identity was not preserved: %#v", got.Links)
	}
	if got.Links[0].ChildHopID == got.Links[1].ChildHopID || got.Links[0].Credential == got.Links[1].Credential || len(got.Links[1].Rules) != 1 {
		t.Fatalf("migrated branches are not isolated: %#v", got.Links)
	}
	if err := migrated.MarkReady(); err != nil {
		t.Fatal(err)
	}
	persisted, _ := os.ReadFile(path)
	if !strings.Contains(string(persisted), `"schema_version": `+strconv.Itoa(SchemaVersion)) {
		t.Fatalf("migrated state was not persisted as schema v%d: %s", SchemaVersion, persisted)
	}
}

func TestStoreRejectsCorruptNewStateInsteadOfResetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-node-state.json")
	contents := `{"schema":"theatropolis/proxy-node-state","schema_version":1,"last_used_by":{"component":"master","version":"v1","commit":"x","recorded_at":"2026-01-01T00:00:00Z"},"data":{"users":[],"proxy_nodes":[],"unexpected":true}}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, testBuild()); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Open() error = %v, want ErrInvalidState", err)
	}
	retained, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(retained) != contents {
		t.Fatal("invalid new state was rewritten")
	}
}

type testResolver map[string]string

func (r testResolver) AgentAddressForFamily(agentID string, _ pool.Family) (string, bool) {
	value, ok := r[agentID]
	return value, ok
}

func TestCompileKeepsAdministratorEntranceReadyForLiveUserManagement(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetAdministratorProxyAccess(true); err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootName: "Entrance", RootAgent: "edge-a",
		Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(store.Snapshot(), testResolver{"edge-a": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Tag   string           `json:"tag"`
			Users []map[string]any `json:"users"`
		} `json:"inbounds"`
		Services []struct {
			Type       string            `json:"type"`
			Tag        string            `json:"tag"`
			Listen     string            `json:"listen"`
			ListenPort int               `json:"listen_port"`
			Servers    map[string]string `json:"servers"`
		} `json:"services"`
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(compiled.Configs["edge-a"], &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || len(config.Inbounds[0].Users) != 1 {
		t.Fatalf("administrator entrance inbounds = %#v", config.Inbounds)
	}
	if len(config.Services) != 1 || config.Services[0].Type != "ssm-api" ||
		config.Services[0].Tag != singbox.ManagedUserAPIServiceTag ||
		config.Services[0].Listen != "127.0.0.1" ||
		config.Services[0].ListenPort != singbox.ManagedUserAPIListenPort ||
		config.Services[0].Servers["/"+config.Inbounds[0].Tag] != config.Inbounds[0].Tag {
		t.Fatalf("managed-user service = %#v", config.Services)
	}
	if len(config.Route.Rules) != 1 {
		t.Fatalf("empty entrance route rules = %#v", config.Route.Rules)
	}
	if _, exists := config.Route.Rules[0]["auth_user"]; exists {
		t.Fatalf("dedicated entrance route unnecessarily depends on mutable users: %#v", config.Route.Rules)
	}
	if node.Entrance.HopID == "" {
		t.Fatal("created entrance has no Hop ID")
	}
	user, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	withUser, err := Compile(store.Snapshot(), testResolver{"edge-a": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	withoutUsers := func(encoded []byte) map[string]any {
		t.Helper()
		var document map[string]any
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatal(err)
		}
		for _, raw := range document["inbounds"].([]any) {
			delete(raw.(map[string]any), "users")
		}
		return document
	}
	if !reflect.DeepEqual(
		withoutUsers(compiled.Configs["edge-a"]),
		withoutUsers(withUser.Configs["edge-a"]),
	) {
		t.Fatal("granting a user changed dedicated-listener routing or topology")
	}
}

func TestCompileUsesMultiUserModeForAdministratorShadowsocksListener(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetAdministratorProxyAccess(true); err != nil {
		t.Fatal(err)
	}
	endpoint := Endpoint{
		Protocol: ProtocolShadowsocks, Listen: "::", ListenPort: 20048,
		Family: "ipv4", Method: "2022-blake3-aes-256-gcm",
	}
	if _, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootName: "Entrance", RootAgent: "edge-a", Entrance: endpoint,
	}); err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(store.Snapshot(), testResolver{"edge-a": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Managed bool             `json:"managed"`
			Users   []map[string]any `json:"users"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(compiled.Configs["edge-a"], &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || config.Inbounds[0].Managed || len(config.Inbounds[0].Users) != 1 {
		t.Fatalf("administrator Shadowsocks inbound = %#v", config.Inbounds)
	}
}

func TestCompileCombinesCompatibleEntrancesAndRoutesByMembership(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := store.CreateUser("alice")
	bob, _ := store.CreateUser("bob")
	first, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootName: "A", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "archive", RootName: "A", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	if err != nil {
		t.Fatal(err)
	}
	firstMembership, _ := store.AddMembership(first.ID, alice.ID)
	secondMembership, _ := store.AddMembership(second.ID, bob.ID)
	if firstMembership.Credential.Secret == secondMembership.Credential.Secret {
		t.Fatal("memberships reused a credential")
	}
	compiled, err := Compile(store.Snapshot(), testResolver{"edge-a": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Type  string `json:"type"`
			Users []struct {
				Name     string `json:"name"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"inbounds"`
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(compiled.Configs["edge-a"], &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || len(config.Inbounds[0].Users) != 2 {
		t.Fatalf("combined inbounds = %#v", config.Inbounds)
	}
	compiledNames := make([]string, 0, len(config.Inbounds[0].Users))
	for _, compiledUser := range config.Inbounds[0].Users {
		compiledNames = append(compiledNames, compiledUser.Name)
	}
	if !slices.Contains(compiledNames, AuthenticatedUserLabel(secondMembership.ID)) ||
		!slices.Contains(compiledNames, AuthenticatedUserLabel(firstMembership.ID)) {
		t.Fatalf("compiled users = %#v", config.Inbounds[0].Users)
	}
	if len(config.Route.Rules) != 2 {
		t.Fatalf("route Rule count = %d, want one final Rule per Proxy Node", len(config.Route.Rules))
	}
}

func TestCompilePlacesTerminalOnFinalHopAgent(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootName: "Entrance", RootAgent: "edge-a",
		Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	link, child, err := store.AddLink(node.ID, AddLinkInput{
		ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-b",
		Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443), Final: Target{Type: TargetReject},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetLinkFallback(node.ID, link.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFinal(node.ID, child.ID, Target{Type: TargetLink, LinkID: link.ID}); err == nil {
		t.Fatal("leaf Hop accepted its parent's Link instead of requiring a terminal")
	}

	compiled, err := Compile(store.Snapshot(), testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"})
	if err != nil {
		t.Fatal(err)
	}
	type routeConfig struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	var entranceConfig, exitConfig routeConfig
	if err := json.Unmarshal(compiled.Configs["edge-a"], &entranceConfig); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(compiled.Configs["edge-b"], &exitConfig); err != nil {
		t.Fatal(err)
	}
	entranceRelays := slices.ContainsFunc(entranceConfig.Route.Rules, func(rule map[string]any) bool {
		return rule["outbound"] == linkOutboundTag(link.ID)
	})
	exitRejects := slices.ContainsFunc(exitConfig.Route.Rules, func(rule map[string]any) bool {
		return rule["action"] == "reject"
	})
	if !entranceRelays || !exitRejects {
		t.Fatalf("compiled path did not relay then terminate: entrance=%s exit=%s", compiled.Configs["edge-a"], compiled.Configs["edge-b"])
	}
}

func TestCompileSupportsEveryManagedProtocolOnLinksAndEveryRuleMatch(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := store.CreateUser("alice")
	node, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootName: "Root", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.AddMembership(node.ID, user.ID)
	protocols := []Protocol{ProtocolShadowsocks, ProtocolAnyTLS, ProtocolHysteria2}
	ports := []int{9001, 9002, 9003}
	links := make([]Link, 0, len(protocols))
	for index, protocol := range protocols {
		endpoint := testTLSEndpoint(protocol, ports[index])
		if protocol == ProtocolShadowsocks {
			endpoint = Endpoint{Protocol: protocol, Listen: "::", ListenPort: ports[index], Family: "ipv4", Method: "2022-blake3-aes-128-gcm"}
		}
		link, _, err := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Exit" + string(rune('A'+index)), ChildAgent: "edge-" + string(rune('b'+index)), Endpoint: endpoint})
		if err != nil {
			t.Fatal(err)
		}
		links = append(links, link)
	}
	matchTypes := []MatchType{MatchProtocol, MatchDomain, MatchDomainSuffix, MatchDomainKeyword, MatchDomainRegex, MatchIPCIDR, MatchGeosite, MatchGeoIP, MatchRuleSet, MatchNetwork}
	if err := store.UpsertRuleSet(node.ID, CustomRuleSet{Tag: "private-set", URL: "https://example.com/private.srs"}); err != nil {
		t.Fatal(err)
	}
	for index, match := range matchTypes {
		values := []string{"value"}
		switch match {
		case MatchGeosite:
			values = []string{"category-ads-all"}
		case MatchGeoIP:
			values = []string{"private"}
		case MatchRuleSet:
			values = []string{"private-set"}
		}
		if _, err := store.AddRule(node.ID, AddRuleInput{LinkID: links[index%len(links)].ID, Match: match, Values: values}); err != nil {
			t.Fatalf("add %s Rule: %v", match, err)
		}
	}
	compiled, err := Compile(store.Snapshot(), testResolver{
		"edge-a": "192.0.2.10", "edge-b": "192.0.2.11", "edge-c": "192.0.2.12", "edge-d": "192.0.2.13",
	})
	if err != nil {
		t.Fatal(err)
	}
	root := string(compiled.Configs["edge-a"])
	for _, required := range []string{`"type": "local"`, `"tag": "tp-local-dns"`, `"default_domain_resolver": "tp-local-dns"`} {
		if !strings.Contains(root, required) {
			t.Errorf("root config lacks DNS setting %s: %s", required, root)
		}
	}
	for _, protocol := range protocols {
		if !strings.Contains(root, `"type": "`+string(protocol)+`"`) {
			t.Errorf("root config lacks %s Link outbound: %s", protocol, root)
		}
	}
	for _, field := range []string{"protocol", "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "rule_set", "network"} {
		if !strings.Contains(root, `"`+field+`"`) {
			t.Errorf("root config lacks %s Rule field", field)
		}
	}
}

func TestInsertRequiredRouteActionsAtFirstMetadataUse(t *testing.T) {
	t.Parallel()
	rules := []map[string]any{
		{"network": []string{"udp"}, "action": "route", "outbound": "early"},
		{"domain_suffix": []string{"example.com"}, "action": "route", "outbound": "domain"},
		{"ip_cidr": []string{"192.0.2.0/24"}, "action": "route", "outbound": "ip"},
		{"rule_set": []string{"tp-rs-node-private"}, "action": "route", "outbound": "custom"},
	}

	normalized := insertRequiredRouteActions(rules)
	if len(normalized) != 6 {
		t.Fatalf("normalized Rule count = %d, want 6: %#v", len(normalized), normalized)
	}
	if normalized[0]["outbound"] != "early" || normalized[1]["action"] != "sniff" ||
		normalized[2]["outbound"] != "domain" || normalized[3]["action"] != "resolve" ||
		normalized[4]["outbound"] != "ip" || normalized[5]["outbound"] != "custom" {
		t.Fatalf("normalized Rules in unexpected order: %#v", normalized)
	}
}

func TestInsertRequiredRouteActionsPreparesBothForOpaqueRuleSet(t *testing.T) {
	t.Parallel()
	rules := []map[string]any{{
		"rule_set": []string{"tp-rs-node-private"}, "action": "route", "outbound": "custom",
	}}

	normalized := insertRequiredRouteActions(rules)
	if len(normalized) != 3 || normalized[0]["action"] != "resolve" ||
		normalized[1]["action"] != "sniff" || normalized[2]["outbound"] != "custom" {
		t.Fatalf("normalized Rules = %#v", normalized)
	}
}

func TestCompileMirrorsShadowsocksInboundMultiplexOntoManagedLinkOutbound(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootName: "Root", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := Endpoint{
		Protocol: ProtocolShadowsocks, Listen: "::", ListenPort: 9001, Family: "ipv4", Method: "2022-blake3-aes-128-gcm",
		Multiplex: &MultiplexConfig{Enabled: true, Padding: true, Brutal: &TCPBrutalConfig{Enabled: true, UpMbps: 100, DownMbps: 200}},
	}
	link, _, err := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Exit", ChildAgent: "edge-b", Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetLinkFallback(node.ID, link.ID, true); err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(store.Snapshot(), testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11"})
	if err != nil {
		t.Fatal(err)
	}
	for _, agentID := range []string{"edge-a", "edge-b"} {
		config := string(compiled.Configs[agentID])
		for _, expected := range []string{`"multiplex"`, `"padding": true`, `"up_mbps": 100`, `"down_mbps": 200`} {
			if !strings.Contains(config, expected) {
				t.Errorf("%s config lacks %s: %s", agentID, expected, config)
			}
		}
	}
	var parent struct {
		Outbounds []struct {
			Type      string         `json:"type"`
			Multiplex map[string]any `json:"multiplex"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(compiled.Configs["edge-a"], &parent); err != nil {
		t.Fatal(err)
	}
	var parentMultiplex map[string]any
	for _, outbound := range parent.Outbounds {
		if outbound.Type == string(ProtocolShadowsocks) {
			parentMultiplex = outbound.Multiplex
			break
		}
	}
	if got := parentMultiplex["protocol"]; got != "smux" {
		t.Fatalf("parent Shadowsocks multiplex protocol = %#v, want smux", got)
	}
	if parentMultiplex["max_connections"] != float64(4) || parentMultiplex["min_streams"] != float64(4) {
		t.Fatalf("parent Shadowsocks multiplex pool = %#v, want max_connections=4 and min_streams=4", parentMultiplex)
	}

	var child struct {
		Inbounds []struct {
			Type      string         `json:"type"`
			Multiplex map[string]any `json:"multiplex"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(compiled.Configs["edge-b"], &child); err != nil {
		t.Fatal(err)
	}
	var childMultiplex map[string]any
	for _, inbound := range child.Inbounds {
		if inbound.Type == string(ProtocolShadowsocks) {
			childMultiplex = inbound.Multiplex
			break
		}
	}
	if _, exists := childMultiplex["protocol"]; exists {
		t.Fatalf("child inbound unexpectedly received outbound-only multiplex protocol: %#v", childMultiplex)
	}
}

func TestSharedShadowsocksListenerEnablesMuxForOnlyRequestingLinks(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	plainNode, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "plain", RootAgent: "edge-plain", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	if err != nil {
		t.Fatal(err)
	}
	muxNode, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "mux", RootAgent: "edge-mux", Entrance: testTLSEndpoint(ProtocolAnyTLS, 444)})
	if err != nil {
		t.Fatal(err)
	}
	plainEndpoint := Endpoint{
		Protocol: ProtocolShadowsocks, Listen: "::", ListenPort: 20048, Family: "ipv4",
		Method: "2022-blake3-aes-128-gcm",
	}
	_, _, err = store.AddLink(plainNode.ID, AddLinkInput{
		ParentHopID: plainNode.Entrance.HopID, ChildName: "Shared", ChildAgent: "edge-shared", Endpoint: plainEndpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	muxEndpoint := plainEndpoint
	muxEndpoint.Multiplex = &MultiplexConfig{Enabled: true}
	muxLink, _, err := store.AddLink(muxNode.ID, AddLinkInput{
		ParentHopID: muxNode.Entrance.HopID, ChildName: "Shared", ChildAgent: "edge-shared", Endpoint: muxEndpoint,
	})
	if err != nil {
		t.Fatal(err)
	}

	compiled, err := Compile(store.Snapshot(), testResolver{
		"edge-plain": "192.0.2.10", "edge-mux": "192.0.2.11", "edge-shared": "192.0.2.12",
	})
	if err != nil {
		t.Fatal(err)
	}
	type renderedConfig struct {
		Inbounds []struct {
			Type      string         `json:"type"`
			Users     []renderUser   `json:"users"`
			Multiplex map[string]any `json:"multiplex"`
		} `json:"inbounds"`
		Outbounds []struct {
			Type      string         `json:"type"`
			Multiplex map[string]any `json:"multiplex"`
		} `json:"outbounds"`
	}
	decode := func(agentID string) renderedConfig {
		t.Helper()
		var config renderedConfig
		if err := json.Unmarshal(compiled.Configs[agentID], &config); err != nil {
			t.Fatal(err)
		}
		return config
	}
	shared := decode("edge-shared")
	if len(shared.Inbounds) != 1 || len(shared.Inbounds[0].Users) != 2 || shared.Inbounds[0].Multiplex["enabled"] != true {
		t.Fatalf("shared listener did not aggregate mux support: %#v", shared.Inbounds)
	}
	for agentID, wantMux := range map[string]bool{"edge-plain": false, "edge-mux": true} {
		config := decode(agentID)
		var outboundMux map[string]any
		for _, outbound := range config.Outbounds {
			if outbound.Type == string(ProtocolShadowsocks) {
				outboundMux = outbound.Multiplex
				break
			}
		}
		if wantMux && (outboundMux["protocol"] != "smux" || outboundMux["max_connections"] != float64(4) || outboundMux["min_streams"] != float64(4)) {
			t.Fatalf("%s mux outbound = %#v, want smux with the managed 4/4 pool", agentID, outboundMux)
		}
		if !wantMux && outboundMux != nil {
			t.Fatalf("%s plain outbound unexpectedly uses mux: %#v", agentID, outboundMux)
		}
	}

	padded := muxEndpoint
	padded.Multiplex = &MultiplexConfig{Enabled: true, Padding: true}
	if err := store.UpdateLink(muxNode.ID, muxLink.ID, padded); err != nil {
		t.Fatalf("atomic shared listener update: %v", err)
	}
	if err := store.DeleteLink(muxNode.ID, muxLink.ID); err != nil {
		t.Fatal(err)
	}
	compiled, err = Compile(store.Snapshot(), testResolver{
		"edge-plain": "192.0.2.10", "edge-mux": "192.0.2.11", "edge-shared": "192.0.2.12",
	})
	if err != nil {
		t.Fatal(err)
	}
	var sharedAfterDelete renderedConfig
	if err := json.Unmarshal(compiled.Configs["edge-shared"], &sharedAfterDelete); err != nil {
		t.Fatal(err)
	}
	if len(sharedAfterDelete.Inbounds) != 1 || sharedAfterDelete.Inbounds[0].Multiplex["padding"] != true {
		t.Fatalf("listener-wide padding did not propagate to the remaining ref: %#v", sharedAfterDelete.Inbounds)
	}
}

func TestCompileCombinesCompatibleRelayListenersAcrossProxyNodes(t *testing.T) {
	protocols := []Protocol{ProtocolShadowsocks, ProtocolAnyTLS, ProtocolHysteria2}
	for _, protocol := range protocols {
		t.Run(string(protocol), func(t *testing.T) {
			store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
			if err != nil {
				t.Fatal(err)
			}
			first, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "first", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
			if err != nil {
				t.Fatal(err)
			}
			second, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "second", RootAgent: "edge-b", Entrance: testTLSEndpoint(ProtocolAnyTLS, 444)})
			if err != nil {
				t.Fatal(err)
			}
			endpoint := testTLSEndpoint(protocol, 20048)
			if protocol == ProtocolShadowsocks {
				endpoint = Endpoint{
					Protocol: protocol, Listen: "::", ListenPort: 20048, Family: "ipv4",
					Method: "2022-blake3-aes-128-gcm", Multiplex: &MultiplexConfig{Enabled: true},
				}
			} else if protocol == ProtocolHysteria2 {
				endpoint.ObfsType = "salamander"
			}
			firstLink, _, err := store.AddLink(first.ID, AddLinkInput{
				ParentHopID: first.Entrance.HopID, ChildName: "Shared-C", ChildAgent: "edge-c", Endpoint: endpoint,
			})
			if err != nil {
				t.Fatal(err)
			}
			secondLink, _, err := store.AddLink(second.ID, AddLinkInput{
				ParentHopID: second.Entrance.HopID, ChildName: "Shared-C", ChildAgent: "edge-c", Endpoint: endpoint,
			})
			if err != nil {
				t.Fatal(err)
			}
			if firstLink.Credential.Secret == secondLink.Credential.Secret {
				t.Fatal("shared listener reused a Link user credential")
			}

			state := store.Snapshot()
			var firstEndpoint, secondEndpoint Endpoint
			for _, node := range state.ProxyNodes {
				for _, link := range node.Links {
					switch link.ID {
					case firstLink.ID:
						firstEndpoint = link.Endpoint
					case secondLink.ID:
						secondEndpoint = link.Endpoint
					}
				}
			}
			switch protocol {
			case ProtocolShadowsocks:
				if firstEndpoint.ServerKey == "" || firstEndpoint.ServerKey != secondEndpoint.ServerKey {
					t.Fatalf("Shadowsocks listener keys differ: %q != %q", firstEndpoint.ServerKey, secondEndpoint.ServerKey)
				}
			case ProtocolHysteria2:
				if firstEndpoint.ObfsSecret == "" || firstEndpoint.ObfsSecret != secondEndpoint.ObfsSecret {
					t.Fatalf("Hysteria2 listener obfuscation secrets differ: %q != %q", firstEndpoint.ObfsSecret, secondEndpoint.ObfsSecret)
				}
			}

			compiled, err := Compile(state, testResolver{
				"edge-a": "192.0.2.10", "edge-b": "192.0.2.11", "edge-c": "192.0.2.12",
			})
			if err != nil {
				t.Fatal(err)
			}
			var childConfig struct {
				Inbounds []struct {
					Type       string `json:"type"`
					BBRProfile string `json:"bbr_profile"`
					Users      []struct {
						Name     string `json:"name"`
						Password string `json:"password"`
					} `json:"users"`
				} `json:"inbounds"`
			}
			if err := json.Unmarshal(compiled.Configs["edge-c"], &childConfig); err != nil {
				t.Fatal(err)
			}
			if len(childConfig.Inbounds) != 1 || childConfig.Inbounds[0].Type != string(protocol) || len(childConfig.Inbounds[0].Users) != 2 {
				t.Fatalf("combined %s listener = %#v", protocol, childConfig.Inbounds)
			}
			if childConfig.Inbounds[0].Users[0].Name == childConfig.Inbounds[0].Users[1].Name ||
				childConfig.Inbounds[0].Users[0].Password == childConfig.Inbounds[0].Users[1].Password {
				t.Fatalf("combined %s listener did not retain distinct Link identities: %#v", protocol, childConfig.Inbounds[0].Users)
			}
			if protocol == ProtocolHysteria2 && childConfig.Inbounds[0].BBRProfile != "aggressive" {
				t.Fatalf("Hysteria2 listener bbr_profile = %q, want aggressive", childConfig.Inbounds[0].BBRProfile)
			}
			if protocol == ProtocolShadowsocks {
				for _, agentID := range []string{"edge-a", "edge-b"} {
					if !strings.Contains(string(compiled.Configs[agentID]), `"protocol": "smux"`) {
						t.Fatalf("%s did not use smux for shared Shadowsocks listener", agentID)
					}
				}
			}
		})
	}
}

func TestSharedListenerProtocolEditRotatesEveryReferenceAtomically(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	shadowsocks := Endpoint{
		Protocol: ProtocolShadowsocks, Listen: "::", ListenPort: 20048,
		Method: "2022-blake3-aes-256-gcm",
	}
	firstNode, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "first", RootAgent: "parent-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	firstLink, _, err := store.AddLink(firstNode.ID, AddLinkInput{
		ParentHopID: firstNode.Entrance.HopID, ChildName: "shared-a", ChildAgent: "shared",
		Endpoint: shadowsocks,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondNode, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "second", RootAgent: "parent-b", Entrance: testTLSEndpoint(ProtocolAnyTLS, 444),
	})
	if err != nil {
		t.Fatal(err)
	}
	secondLink, _, err := store.AddLink(secondNode.ID, AddLinkInput{
		ParentHopID: secondNode.Entrance.HopID, ChildName: "shared-b", ChildAgent: "shared",
		Endpoint: shadowsocks,
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement := testTLSEndpoint(ProtocolAnyTLS, 20048)
	if err := store.UpdateLink(firstNode.ID, firstLink.ID, replacement); err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	findLink := func(nodeID, linkID string) Link {
		t.Helper()
		for _, node := range state.ProxyNodes {
			if node.ID != nodeID {
				continue
			}
			for _, link := range node.Links {
				if link.ID == linkID {
					return link
				}
			}
		}
		t.Fatal("Link not found")
		return Link{}
	}
	updatedFirst := findLink(firstNode.ID, firstLink.ID)
	updatedSecond := findLink(secondNode.ID, secondLink.ID)
	if updatedFirst.Endpoint.Protocol != ProtocolAnyTLS || updatedSecond.Endpoint.Protocol != ProtocolAnyTLS ||
		updatedFirst.Endpoint.TLS != replacement.TLS || updatedSecond.Endpoint.TLS != replacement.TLS {
		t.Fatalf("shared listener was only partially changed: %#v %#v", updatedFirst.Endpoint, updatedSecond.Endpoint)
	}
	if updatedFirst.Credential == firstLink.Credential || updatedSecond.Credential == secondLink.Credential ||
		updatedFirst.Credential == updatedSecond.Credential {
		t.Fatal("shared protocol edit did not rotate distinct Link credentials")
	}
	compiled, err := Compile(state, testResolver{
		"parent-a": "192.0.2.10", "parent-b": "192.0.2.11", "shared": "192.0.2.12",
	})
	if err != nil {
		t.Fatal(err)
	}
	var sharedConfig struct {
		Inbounds []struct {
			Type  string       `json:"type"`
			Users []renderUser `json:"users"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(compiled.Configs["shared"], &sharedConfig); err != nil {
		t.Fatal(err)
	}
	if len(sharedConfig.Inbounds) != 1 || sharedConfig.Inbounds[0].Type != string(ProtocolAnyTLS) ||
		len(sharedConfig.Inbounds[0].Users) != 2 {
		t.Fatalf("compiled shared replacement = %#v", sharedConfig.Inbounds)
	}
}

func TestDeletingSharedLinkRemovesOnlyItsUserUntilLastReference(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolShadowsocks, ProtocolAnyTLS, ProtocolHysteria2} {
		t.Run(string(protocol), func(t *testing.T) {
			store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
			if err != nil {
				t.Fatal(err)
			}
			first, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "first", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
			second, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "second", RootAgent: "edge-b", Entrance: testTLSEndpoint(ProtocolAnyTLS, 444)})
			endpoint := testTLSEndpoint(protocol, 20048)
			if protocol == ProtocolShadowsocks {
				endpoint = Endpoint{
					Protocol: protocol, Listen: "::", ListenPort: 20048, Family: "ipv4",
					Method: "2022-blake3-aes-128-gcm", Multiplex: &MultiplexConfig{Enabled: true},
				}
			} else if protocol == ProtocolHysteria2 {
				endpoint.ObfsType = "salamander"
			}
			firstLink, _, err := store.AddLink(first.ID, AddLinkInput{
				ParentHopID: first.Entrance.HopID, ChildName: "First-C", ChildAgent: "edge-c", Endpoint: endpoint,
			})
			if err != nil {
				t.Fatal(err)
			}
			secondLink, _, err := store.AddLink(second.ID, AddLinkInput{
				ParentHopID: second.Entrance.HopID, ChildName: "Second-C", ChildAgent: "edge-c", Endpoint: endpoint,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.DeleteLink(first.ID, firstLink.ID); err != nil {
				t.Fatal(err)
			}
			compiled, err := Compile(store.Snapshot(), testResolver{
				"edge-a": "192.0.2.10", "edge-b": "192.0.2.11", "edge-c": "192.0.2.12",
			})
			if err != nil {
				t.Fatal(err)
			}
			var childConfig struct {
				Inbounds []struct {
					Users []struct {
						Name string `json:"name"`
					} `json:"users"`
				} `json:"inbounds"`
			}
			if err := json.Unmarshal(compiled.Configs["edge-c"], &childConfig); err != nil {
				t.Fatal(err)
			}
			if len(childConfig.Inbounds) != 1 || len(childConfig.Inbounds[0].Users) != 1 ||
				childConfig.Inbounds[0].Users[0].Name != linkUserLabel(secondLink.ID) {
				t.Fatalf("listener after deleting one shared Link = %#v", childConfig.Inbounds)
			}

			if err := store.SetManagedAgents([]string{"edge-a", "edge-b", "edge-c"}); err != nil {
				t.Fatal(err)
			}
			if err := store.DeleteLink(second.ID, secondLink.ID); err != nil {
				t.Fatal(err)
			}
			deployer, err := NewDeployer(store, testResolver{
				"edge-a": "192.0.2.10", "edge-b": "192.0.2.11", "edge-c": "192.0.2.12",
			}, &applyingController{})
			if err != nil {
				t.Fatal(err)
			}
			cleanup, _, err := deployer.compileCompleteFleet(deploymentTopology)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(cleanup.Configs["edge-c"], &childConfig); err != nil {
				t.Fatal(err)
			}
			if len(childConfig.Inbounds) != 0 {
				t.Fatalf("last shared listener was not removed: %#v", childConfig.Inbounds)
			}
		})
	}
}

func TestOpenReconcilesExistingSharedListenerSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	first, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "first", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	second, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "second", RootAgent: "edge-b", Entrance: testTLSEndpoint(ProtocolAnyTLS, 444)})
	endpoint := Endpoint{
		Protocol: ProtocolShadowsocks, Listen: "::", ListenPort: 20048, Family: "ipv4",
		Method: "2022-blake3-aes-128-gcm",
	}
	if _, _, err := store.AddLink(first.ID, AddLinkInput{ParentHopID: first.Entrance.HopID, ChildName: "First-C", ChildAgent: "edge-c", Endpoint: endpoint}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddLink(second.ID, AddLinkInput{ParentHopID: second.Entrance.HopID, ChildName: "Second-C", ChildAgent: "edge-c", Endpoint: endpoint}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored envelope
	if err := json.Unmarshal(contents, &stored); err != nil {
		t.Fatal(err)
	}
	canonical := stored.Data.ProxyNodes[0].Links[0].Endpoint.ServerKey
	legacyKey, err := randomBase64(16)
	if err != nil {
		t.Fatal(err)
	}
	for legacyKey == canonical {
		legacyKey, err = randomBase64(16)
		if err != nil {
			t.Fatal(err)
		}
	}
	stored.Data.ProxyNodes[1].Links[0].Endpoint.ServerKey = legacyKey
	legacyRevision := stored.Data.Revision
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	state := reloaded.Snapshot()
	if state.Revision != legacyRevision+1 {
		t.Fatalf("reconciled revision = %d, want %d", state.Revision, legacyRevision+1)
	}
	if got := state.ProxyNodes[1].Links[0].Endpoint.ServerKey; got != canonical {
		t.Fatalf("reconciled listener key = %q, want %q", got, canonical)
	}
	if err := reloaded.MarkReady(); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), legacyKey) {
		t.Fatal("MarkReady persisted the superseded per-Link listener key")
	}
}

func TestRestoreTopologyPreservesConcurrentUserPlaneChanges(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	alice, err := store.CreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	previous := store.Snapshot()
	if err := store.RenameProxyNode(node.ID, "candidate"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateMembershipPlan(node.ID, alice.ID, MembershipPlan{MonthlyQuotaBytes: 12345}); err != nil {
		t.Fatal(err)
	}
	bob, err := store.CreateUser("bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMembership(node.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreTopology(store.Snapshot().Revision, previous); err != nil {
		t.Fatal(err)
	}
	restored, exists := store.ProxyNode(node.ID)
	if !exists || restored.Name != "cinema" {
		t.Fatalf("restored Proxy Node = %#v, exists %v", restored, exists)
	}
	if len(restored.Memberships) != 2 {
		t.Fatalf("restored memberships = %#v", restored.Memberships)
	}
	aliceIndex := slices.IndexFunc(restored.Memberships, func(membership Membership) bool {
		return membership.UserID == alice.ID
	})
	bobIndex := slices.IndexFunc(restored.Memberships, func(membership Membership) bool {
		return membership.UserID == bob.ID
	})
	if aliceIndex < 0 || restored.Memberships[aliceIndex].MonthlyQuotaBytes != 12345 {
		t.Fatalf("Alice's concurrent plan was lost: %#v", restored.Memberships)
	}
	if bobIndex < 0 || restored.Memberships[bobIndex].PendingCredential != nil {
		t.Fatalf("Bob's concurrent membership was lost or retained a candidate credential: %#v", restored.Memberships)
	}
}

func TestStoreDetectsOverlappingProtocolTransportsOnOneSocket(t *testing.T) {
	shadowsocks := Endpoint{
		Protocol: ProtocolShadowsocks, Listen: "::", ListenPort: 20048, Family: "ipv4",
		Method: "2022-blake3-aes-128-gcm",
	}
	for _, firstProtocol := range []Protocol{ProtocolAnyTLS, ProtocolHysteria2} {
		t.Run("shadowsocks-conflicts-with-"+string(firstProtocol), func(t *testing.T) {
			store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "first", RootAgent: "edge-a", Entrance: testTLSEndpoint(firstProtocol, 20048)}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "second", RootAgent: "edge-a", Entrance: shadowsocks}); err == nil || !errors.Is(err, ErrConflict) {
				t.Fatalf("CreateProxyNode() error = %v, want transport conflict", err)
			}
		})
	}

	store, err := Open(filepath.Join(t.TempDir(), "compatible.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "tcp", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 20048)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "udp", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolHysteria2, 20048)}); err != nil {
		t.Fatalf("separate TCP and UDP listeners should share a port: %v", err)
	}
}

func TestLinksOwnMatchClausesOrderAndFallback(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := store.CreateUser("alice")
	node, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.AddMembership(node.ID, user.ID)
	first, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "First", ChildAgent: "edge-b", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)})
	second, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Second", ChildAgent: "edge-c", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 9443)})
	fallback, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Fallback", ChildAgent: "edge-d", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 10443)})
	firstDomain, err := store.AddRule(node.ID, AddRuleInput{LinkID: first.ID, Match: MatchDomainSuffix, Values: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	firstProtocol, err := store.AddRule(node.ID, AddRuleInput{LinkID: first.ID, Match: MatchProtocol, Values: []string{"bittorrent"}})
	if err != nil {
		t.Fatal(err)
	}
	secondNetwork, err := store.AddRule(node.ID, AddRuleInput{LinkID: second.ID, Match: MatchNetwork, Values: []string{"udp"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddRule(node.ID, AddRuleInput{LinkID: fallback.ID, Match: MatchDomain, Values: []string{"discarded.example"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetLinkFallback(node.ID, fallback.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddRule(node.ID, AddRuleInput{LinkID: fallback.ID, Match: MatchDomain, Values: []string{"blocked.example"}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("adding a clause to fallback Link error = %v, want conflict", err)
	}
	if err := store.MoveLink(node.ID, second.ID, -1); err != nil {
		t.Fatal(err)
	}
	if err := store.ReorderRules(node.ID, node.Entrance.HopID, []string{secondNetwork.ID, firstDomain.ID, firstProtocol.ID}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReorderRules(node.ID, node.Entrance.HopID, []string{secondNetwork.ID, secondNetwork.ID, firstProtocol.ID}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate dragged Rule order error = %v, want conflict", err)
	}

	state := store.Snapshot()
	updated := state.ProxyNodes[0]
	orders := map[string]int{}
	firstProtocolLinkID := ""
	for _, link := range updated.Links {
		orders[link.ID] = link.Order
		if len(link.Rules) == 1 && link.Rules[0].ID == firstProtocol.ID {
			firstProtocolLinkID = link.ID
		}
		if link.ID == fallback.ID && len(link.Rules) != 0 {
			t.Fatalf("fallback Link retained clauses: %#v", link.Rules)
		}
	}
	if len(orders) != 4 || orders[second.ID] != 0 || orders[first.ID] != 1 || orders[fallback.ID] != 3 {
		t.Fatalf("Link order = %#v", orders)
	}
	if err := store.MoveLink(node.ID, fallback.ID, -1); !errors.Is(err, ErrConflict) {
		t.Fatalf("moving fallback Link error = %v, want conflict", err)
	}

	compiled, err := Compile(store.Snapshot(), testResolver{"edge-a": "192.0.2.10", "edge-b": "192.0.2.11", "edge-c": "192.0.2.12", "edge-d": "192.0.2.13"})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(compiled.Configs["edge-a"], &config); err != nil {
		t.Fatal(err)
	}
	routingRules := make([]map[string]any, 0, len(config.Route.Rules))
	for _, rule := range config.Route.Rules {
		if rule["action"] != "sniff" && rule["action"] != "resolve" {
			routingRules = append(routingRules, rule)
		}
	}
	if len(routingRules) < 5 || firstProtocolLinkID == "" || routingRules[0]["outbound"] != linkOutboundTag(second.ID) || routingRules[1]["outbound"] != linkOutboundTag(first.ID) || routingRules[2]["outbound"] != linkOutboundTag(firstProtocolLinkID) || routingRules[3]["outbound"] != linkOutboundTag(fallback.ID) {
		t.Fatalf("compiled Link-owned rule order is wrong: %#v", config.Route.Rules)
	}
}

func TestOpenMigratesSchemaV2LinkGroupedRulesToHopPriority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	first, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "First", ChildAgent: "edge-b", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)})
	second, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Second", ChildAgent: "edge-c", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 9443)})
	firstRule, _ := store.AddRule(node.ID, AddRuleInput{LinkID: first.ID, Match: MatchDomain, Values: []string{"first.example"}})
	secondRule, _ := store.AddRule(node.ID, AddRuleInput{LinkID: second.ID, Match: MatchDomain, Values: []string{"second.example"}})
	state := store.Snapshot()
	for linkIndex := range state.ProxyNodes[0].Links {
		for ruleIndex := range state.ProxyNodes[0].Links[linkIndex].Rules {
			state.ProxyNodes[0].Links[linkIndex].Rules[ruleIndex].Order = 0
		}
	}
	legacy := envelope{Schema: SchemaID, SchemaVersion: 2, LastUsedBy: normalizeBuild(testBuild(), time.Now()), Data: state}
	encoded, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := migrated.ProxyNode(node.ID)
	orders := make(map[string]int)
	for _, link := range got.Links {
		for _, rule := range link.Rules {
			orders[rule.ID] = rule.Order
		}
	}
	if orders[firstRule.ID] != 0 || orders[secondRule.ID] != 1 {
		t.Fatalf("migrated Rule order = %#v", orders)
	}
}

func TestOpenMigratesSchemaV1HopRulesOntoLinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	conditional, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Conditional", ChildAgent: "edge-b", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)})
	fallback, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Fallback", ChildAgent: "edge-c", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 9443)})
	state := store.Snapshot()
	legacyTarget := Target{Type: TargetLink, LinkID: conditional.ID}
	state.ProxyNodes[0].Hops[0].LegacyRules = []Rule{{ID: "rul_abcdefghijklmnopqrst", Match: MatchDomainSuffix, Values: []string{"example.com"}, LegacyTarget: &legacyTarget}}
	state.ProxyNodes[0].Hops[0].Final = Target{Type: TargetLink, LinkID: fallback.ID}
	for index := range state.ProxyNodes[0].Links {
		state.ProxyNodes[0].Links[index].Order = 0
		state.ProxyNodes[0].Links[index].Rules = nil
		state.ProxyNodes[0].Links[index].Fallback = false
	}
	legacy := envelope{Schema: SchemaID, SchemaVersion: 1, LastUsedBy: normalizeBuild(testBuild(), time.Now()), Data: state}
	encoded, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(path, BuildInfo{Component: "master", Version: "v2.0.0", Commit: "schema-v2"})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := migrated.ProxyNode(node.ID)
	if len(got.Hops[0].LegacyRules) != 0 || got.Hops[0].Final.Type != TargetReject {
		t.Fatalf("migrated Hop = %#v", got.Hops[0])
	}
	if len(got.Links[0].Rules) != 1 || got.Links[0].Rules[0].LegacyTarget != nil || !got.Links[1].Fallback || got.Links[1].Order != 1 {
		t.Fatalf("migrated Links = %#v", got.Links)
	}
	if err := migrated.MarkReady(); err != nil {
		t.Fatal(err)
	}
	contents, _ := os.ReadFile(path)
	if !strings.Contains(string(contents), `"schema_version": `+strconv.Itoa(SchemaVersion)) || strings.Contains(string(contents), `"target"`) || strings.Contains(string(contents), `"rules": null`) {
		t.Fatalf("migrated state was not persisted as schema v%d: %s", SchemaVersion, contents)
	}
}

func TestSchemaV1MigrationPreservesUnconditionalTerminalRule(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	link, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Conditional", ChildAgent: "edge-b", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)})
	state := store.Snapshot()
	linkTarget := Target{Type: TargetLink, LinkID: link.ID}
	rejectTarget := Target{Type: TargetReject}
	state.ProxyNodes[0].Hops[0].LegacyRules = []Rule{
		{ID: "rul_abcdefghijklmnopqrst", Match: MatchDomainSuffix, Values: []string{"example.com"}, LegacyTarget: &linkTarget},
		{ID: "rul_bcdefghijklmnopqrstu", Match: MatchNone, LegacyTarget: &rejectTarget},
	}
	state.ProxyNodes[0].Hops[0].Final = Target{Type: TargetLink, LinkID: link.ID}

	if err := migrateSchemaV1(&state); err != nil {
		t.Fatal(err)
	}
	got := state.ProxyNodes[0]
	if got.Hops[0].Final.Type != TargetReject || len(got.Links[0].Rules) != 1 || got.Links[0].Fallback {
		t.Fatalf("migrated terminal fallback = Hop %#v, Link %#v", got.Hops[0], got.Links[0])
	}
}

func TestSchemaV1MigrationRejectsInterleavedLinkRules(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	node, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "cinema", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	first, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "First", ChildAgent: "edge-b", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)})
	second, _, _ := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildName: "Second", ChildAgent: "edge-c", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 9443)})
	state := store.Snapshot()
	firstTarget := Target{Type: TargetLink, LinkID: first.ID}
	secondTarget := Target{Type: TargetLink, LinkID: second.ID}
	state.ProxyNodes[0].Hops[0].LegacyRules = []Rule{
		{ID: "rul_abcdefghijklmnopqrst", Match: MatchDomain, Values: []string{"first.example"}, LegacyTarget: &firstTarget},
		{ID: "rul_bcdefghijklmnopqrstu", Match: MatchDomain, Values: []string{"second.example"}, LegacyTarget: &secondTarget},
		{ID: "rul_cdefghijklmnopqrstuv", Match: MatchDomain, Values: []string{"third.example"}, LegacyTarget: &firstTarget},
	}

	if err := migrateSchemaV1(&state); err == nil || !strings.Contains(err.Error(), "interleaves Rules") {
		t.Fatalf("migrateSchemaV1() error = %v, want an interleaving error", err)
	}
}

func TestStoreAndCompilerRejectIncompatibleLogicalInboundsOnOneSocket(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := store.CreateUser("alice")
	first, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "first", RootName: "A", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	secondEndpoint := testTLSEndpoint(ProtocolAnyTLS, 8443)
	secondEndpoint.TLS.ServerName = "different.example.com"
	second, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "second", RootName: "A", RootAgent: "edge-a", Entrance: secondEndpoint})
	_, _ = store.AddMembership(first.ID, user.ID)
	other, _ := store.CreateUser("bob")
	_, _ = store.AddMembership(second.ID, other.ID)
	conflicting := secondEndpoint
	conflicting.ListenPort = 443
	if err := store.UpdateEntrance(second.ID, conflicting); err == nil || !strings.Contains(err.Error(), "incompatible logical inbounds") {
		t.Fatalf("UpdateEntrance() error = %v, want listener conflict", err)
	}
	legacyState := store.Snapshot()
	legacyState.ProxyNodes[1].Entrance.Endpoint = conflicting
	if _, err := Compile(legacyState, testResolver{"edge-a": "192.0.2.10"}); err == nil || !strings.Contains(err.Error(), "incompatible logical inbounds") {
		t.Fatalf("Compile() error = %v, want listener conflict", err)
	}
}

func TestBuildTimestampIsUTC(t *testing.T) {
	build := normalizeBuild(testBuild(), time.Date(2026, 1, 1, 1, 2, 3, 0, time.FixedZone("test", 3600)))
	if build.RecordedAt.Location() != time.UTC {
		t.Fatalf("RecordedAt location = %v", build.RecordedAt.Location())
	}
}
