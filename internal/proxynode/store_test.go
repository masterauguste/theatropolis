package proxynode

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/pool"
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
		HopID: node.Entrance.HopID, Match: MatchDomainSuffix,
		Values: []string{"example.com"}, Target: Target{Type: TargetLink, LinkID: link.ID},
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
	if !ok || got.Name != "archive" || len(got.Links) != 1 || len(got.Hops[0].Rules) != 1 {
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

func (testResolver) DefaultTLSAddress(string) string { return "" }

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
	if config.Inbounds[0].Users[0].Name != "archive-bob" || config.Inbounds[0].Users[1].Name != "cinema-alice" {
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
	if err := store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetLink, LinkID: link.ID}); err != nil {
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
	matchTypes := []MatchType{MatchNone, MatchProtocol, MatchDomain, MatchDomainSuffix, MatchDomainKeyword, MatchDomainRegex, MatchIPCIDR, MatchGeosite, MatchGeoIP, MatchRuleSet, MatchNetwork}
	if err := store.UpsertRuleSet(node.ID, CustomRuleSet{Tag: "private-set", URL: "https://example.com/private.srs"}); err != nil {
		t.Fatal(err)
	}
	for index, match := range matchTypes {
		values := []string{"value"}
		switch match {
		case MatchNone:
			values = nil
		case MatchGeosite:
			values = []string{"category-ads-all"}
		case MatchGeoIP:
			values = []string{"private"}
		case MatchRuleSet:
			values = []string{"private-set"}
		}
		if _, err := store.AddRule(node.ID, AddRuleInput{HopID: node.Entrance.HopID, Match: match, Values: values, Target: Target{Type: TargetLink, LinkID: links[index%len(links)].ID}}); err != nil {
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
	if err := store.SetFinal(node.ID, node.Entrance.HopID, Target{Type: TargetLink, LinkID: link.ID}); err != nil {
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
}

func TestCompileRejectsIncompatibleLogicalInboundsOnOneSocket(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := store.CreateUser("alice")
	first, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "first", RootName: "A", RootAgent: "edge-a", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	secondEndpoint := testTLSEndpoint(ProtocolAnyTLS, 443)
	secondEndpoint.TLS.ServerName = "different.example.com"
	second, _ := store.CreateProxyNode(CreateProxyNodeInput{Name: "second", RootName: "A", RootAgent: "edge-a", Entrance: secondEndpoint})
	_, _ = store.AddMembership(first.ID, user.ID)
	other, _ := store.CreateUser("bob")
	_, _ = store.AddMembership(second.ID, other.ID)
	if _, err := Compile(store.Snapshot(), testResolver{"edge-a": "192.0.2.10"}); err == nil || !strings.Contains(err.Error(), "incompatible logical inbounds") {
		t.Fatalf("Compile() error = %v, want listener conflict", err)
	}
}

func TestBuildTimestampIsUTC(t *testing.T) {
	build := normalizeBuild(testBuild(), time.Date(2026, 1, 1, 1, 2, 3, 0, time.FixedZone("test", 3600)))
	if build.RecordedAt.Location() != time.UTC {
		t.Fatalf("RecordedAt location = %v", build.RecordedAt.Location())
	}
}
