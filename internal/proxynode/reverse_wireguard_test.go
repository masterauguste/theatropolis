package proxynode

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

func reverseFixture(t *testing.T) (*Store, ProxyNode, Link, Hop) {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SetAgentReverseOnly("nat-child", true); err != nil {
		t.Fatal(err)
	}
	node, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "Reverse", RootAgent: "public-parent", Entrance: testTLSEndpoint(ProtocolAnyTLS, 443)})
	if err != nil {
		t.Fatal(err)
	}
	link, hop, _, err := store.AddBranch(node.ID, AddBranchInput{AddLinkInput: AddLinkInput{ParentHopID: node.Entrance.HopID, ChildAgent: "nat-child", Endpoint: Endpoint{Protocol: ProtocolReverseWireGuard, ListenPort: 51820}}, Match: MatchNone})
	if err != nil {
		t.Fatal(err)
	}
	node, _ = store.ProxyNode(node.ID)
	link = node.Links[0]
	return store, node, link, hop
}

func TestReverseOnlyPolicyAndParentSocketOwnership(t *testing.T) {
	store, node, link, child := reverseFixture(t)
	if link.WireGuard == nil || link.WireGuard.PrivateKey == link.Endpoint.ServerKey {
		t.Fatal("missing independent tunnel credentials")
	}
	if _, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "Invalid entrance", RootAgent: "nat-child", Entrance: testTLSEndpoint(ProtocolAnyTLS, 9443)}); err == nil {
		t.Fatal("CGNAT entrance accepted")
	}
	if _, _, err := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildAgent: "nat-child", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)}); err == nil {
		t.Fatal("normal incoming protocol accepted")
	}
	if err := store.SetAgentReverseOnly("nat-child", false); !errors.Is(err, ErrConflict) {
		t.Fatalf("referenced mode change: %v", err)
	}
	if err := store.SetAgentReverseOnly("nat-other", true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddLink(node.ID, AddLinkInput{ParentHopID: child.ID, ChildAgent: "nat-other", Endpoint: Endpoint{Protocol: ProtocolReverseWireGuard, ListenPort: 51821}}); err == nil {
		t.Fatal("consecutive CGNAT Hops accepted")
	}
	// WireGuard owns the parent's UDP socket, not the child's public port.
	if _, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "UDP collision", RootAgent: "public-parent", Entrance: testTLSEndpoint(ProtocolHysteria2, 51820)}); err == nil {
		t.Fatal("parent UDP collision accepted")
	}
	if _, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "TCP coexistence", RootAgent: "public-parent", Entrance: testTLSEndpoint(ProtocolAnyTLS, 51820)}); err != nil {
		t.Fatalf("TCP/UDP coexistence: %v", err)
	}
	if _, _, err := store.AddLink(node.ID, AddLinkInput{ParentHopID: child.ID, ChildAgent: "public-exit", Endpoint: testTLSEndpoint(ProtocolAnyTLS, 8443)}); err != nil {
		t.Fatalf("CGNAT outgoing normal Link: %v", err)
	}
}

func TestReverseCompileUsesParentAddressAndPrivateSOCKS(t *testing.T) {
	store, node, link, _ := reverseFixture(t)
	resolver := testAddressResolver{"public-parent": "203.0.113.20"}
	compiled, err := Compile(store.Snapshot(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	var parent, child map[string]any
	_ = json.Unmarshal(compiled.Configs["public-parent"], &parent)
	_ = json.Unmarshal(compiled.Configs["nat-child"], &child)
	outbounds := parent["outbounds"].([]any)
	var out map[string]any
	for _, raw := range outbounds {
		candidate := raw.(map[string]any)
		if candidate["tag"] == linkOutboundTag(link.ID) {
			out = candidate
		}
	}
	if out["type"] != "socks" || out["username"] != linkUserLabel(link.ID) || out["server"] != wireGuardChildIP(link.ID) {
		t.Fatalf("wrong SOCKS outbound: %#v", out)
	}
	endpoints := child["endpoints"].([]any)
	peer := endpoints[0].(map[string]any)["peers"].([]any)[0].(map[string]any)
	if peer["address"] != resolver["public-parent"] || peer["persistent_keepalive_interval"] != float64(25) {
		t.Fatalf("wrong child peer: %#v", peer)
	}
	inbound := child["inbounds"].([]any)[0].(map[string]any)
	if inbound["type"] != "socks" || inbound["listen"] != "::1" {
		t.Fatalf("public SOCKS listener: %#v", inbound)
	}
	if _, exists := child["services"]; exists {
		t.Fatal("SOCKS wrongly registered in managed-user API")
	}
	if _, err := singbox.BuildManagedUserAuthorityVariant(compiled.Configs["nat-child"]); err != nil {
		t.Fatalf("relay-only authority: %v", err)
	}
	_, err = Compile(store.Snapshot(), testAddressResolver{})
	var unavailable *AgentAddressUnavailableError
	if !errors.As(err, &unavailable) || unavailable.AgentID != "public-parent" {
		t.Fatalf("missing parent address: %v", err)
	}
	// Reloading/renaming must retain durable key material and private ports.
	if err := store.RenameProxyNode(node.ID, "Renamed"); err != nil {
		t.Fatal(err)
	}
	after, _ := store.ProxyNode(node.ID)
	if !reflect.DeepEqual(after.Links[0].WireGuard, link.WireGuard) || after.Links[0].Endpoint.ServerKey != link.Endpoint.ServerKey {
		t.Fatal("ordinary mutation changed tunnel identity")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(store.path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reloaded, _ := reopened.ProxyNode(node.ID)
	if !reopened.AgentReverseOnly("nat-child") || !reflect.DeepEqual(reloaded.Links[0].WireGuard, link.WireGuard) || reloaded.Links[0].Endpoint.ServerKey != link.Endpoint.ServerKey {
		t.Fatal("reopening changed reverse mode or tunnel material")
	}
}

func TestReverseSharedParentListenerAndBranchClone(t *testing.T) {
	store, node, original, _ := reverseFixture(t)
	if err := store.SetAgentReverseOnly("nat-second", true); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := store.AddBranch(node.ID, AddBranchInput{AddLinkInput: AddLinkInput{ParentHopID: node.Entrance.HopID, ChildAgent: "nat-second", Endpoint: Endpoint{Protocol: ProtocolReverseWireGuard, ListenPort: 51820}}, Match: MatchDomainSuffix, Values: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(store.Snapshot(), testAddressResolver{"public-parent": "203.0.113.20"})
	if err != nil {
		t.Fatal(err)
	}
	var parent struct {
		Endpoints []struct{ Peers []json.RawMessage }
	}
	_ = json.Unmarshal(compiled.Configs["public-parent"], &parent)
	if len(parent.Endpoints) != 1 || len(parent.Endpoints[0].Peers) != 2 {
		t.Fatalf("shared WireGuard socket: %#v", parent)
	}
	// A second match on an active Link clones its subtree and peer identity.
	if err := store.SetLinkFallback(node.ID, original.ID, false); err != nil {
		t.Fatal(err)
	}
	_, err = store.AddRule(node.ID, AddRuleInput{LinkID: original.ID, Match: MatchDomain, Values: []string{"other.example"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.AddRule(node.ID, AddRuleInput{LinkID: original.ID, Match: MatchDomain, Values: []string{"clone.example"}})
	if err != nil {
		t.Fatal(err)
	}
	updated, _ := store.ProxyNode(node.ID)
	hops := map[string]Hop{}
	for _, hop := range updated.Hops {
		hops[hop.ID] = hop
	}
	clones := 0
	for _, link := range updated.Links {
		child := hops[link.ChildHopID]
		if link.ID != original.ID && child.AgentID == "nat-child" {
			clones++
			if link.WireGuard.PrivateKey == original.WireGuard.PrivateKey || link.WireGuard.SOCKSPort == original.WireGuard.SOCKSPort || link.WireGuard.ProbePort == original.WireGuard.ProbePort {
				t.Fatal("cloned branch reused WireGuard peer identity or private socket")
			}
		}
	}
	if clones != 1 {
		t.Fatalf("expected one cloned branch, got %d", clones)
	}
	if _, err := Compile(store.Snapshot(), testAddressResolver{"public-parent": "203.0.113.20"}); err != nil {
		t.Fatal(err)
	}
}

func TestReverseHopMovesReallocatePrivateSockets(t *testing.T) {
	store, node, link, child := reverseFixture(t)
	if err := store.SetAgentReverseOnly("nat-second", true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddLink(node.ID, AddLinkInput{ParentHopID: node.Entrance.HopID, ChildAgent: "nat-second", Endpoint: Endpoint{Protocol: ProtocolReverseWireGuard, ListenPort: 51821}}); err != nil {
		t.Fatal(err)
	}
	if err := store.MoveHop(node.ID, child.ID, "nat-second"); err != nil {
		t.Fatal(err)
	}
	updated, _ := store.ProxyNode(node.ID)
	moved := updated.Links[0]
	if moved.WireGuard.PrivateKey != link.WireGuard.PrivateKey || moved.WireGuard.SOCKSPort == link.WireGuard.SOCKSPort {
		t.Fatal("move did not preserve key and reallocate occupied child socket")
	}
	if _, err := store.CreateProxyNode(CreateProxyNodeInput{Name: "Other parent", RootAgent: "public-second", Entrance: testTLSEndpoint(ProtocolAnyTLS, link.WireGuard.ProbePort)}); err != nil {
		t.Fatal(err)
	}
	if err := store.MoveHop(node.ID, node.Entrance.HopID, "public-second"); err != nil {
		t.Fatal(err)
	}
	updated, _ = store.ProxyNode(node.ID)
	if updated.Links[0].WireGuard.ProbePort == link.WireGuard.ProbePort {
		t.Fatal("move reused occupied parent readiness socket")
	}
}

type reverseApplyingController struct {
	*applyingController
	probeErr error
	probes   []string
}

func (c *reverseApplyingController) CanDeployReverseWireGuard(string) bool { return true }
func (c *reverseApplyingController) CheckReverseTunnels(_ context.Context, id string, _ []byte) error {
	c.probes = append(c.probes, id)
	return c.probeErr
}

func TestReverseFleetCommitRequiresTunnelReadiness(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(strconv.FormatBool(failed), func(t *testing.T) {
			store, _, _, _ := reverseFixture(t)
			controller := &reverseApplyingController{applyingController: &applyingController{store: deployment.NewMemoryStore(), deployable: map[string]bool{"nat-child": true, "public-parent": true}}}
			if failed {
				controller.probeErr = errors.New("UDP blocked")
			}
			deployer, err := NewDeployer(store, testAddressResolver{"public-parent": "203.0.113.20"}, controller)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := deployer.Start(); err != nil {
				t.Fatal(err)
			}
			if failed {
				waitForFailedFleetDeployment(t, deployer)
				if store.Snapshot().AppliedRevision != 0 {
					t.Fatal("unreachable tunnel marked applied")
				}
			} else {
				waitForFleetDeployment(t, deployer)
				if store.Snapshot().AppliedRevision != store.Snapshot().Revision {
					t.Fatal("ready tunnel not committed")
				}
			}
			if len(controller.probes) != 1 || controller.probes[0] != "public-parent" {
				t.Fatalf("wrong readiness owner: %#v", controller.probes)
			}
		})
	}
}

func TestReverseFleetWaitsForCompatibleAgents(t *testing.T) {
	store, _, _, _ := reverseFixture(t)
	controller := &applyingController{store: deployment.NewMemoryStore(), deployable: map[string]bool{"nat-child": true, "public-parent": true}}
	deployer, err := NewDeployer(store, testAddressResolver{"public-parent": "203.0.113.20"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	job, err := deployer.Start()
	if err != nil || job.Status != FleetDeploymentPending {
		t.Fatalf("incompatible fleet: %s, %v", job.Status, err)
	}
	if store.Snapshot().AppliedRevision != 0 {
		t.Fatal("incompatible fleet marked applied")
	}
	if records, _ := controller.store.List(context.Background()); len(records) != 0 {
		t.Fatal("incompatible fleet was deployed")
	}
}

func TestReverseRetainedAddressUsesChildPeerNotPrivateSOCKS(t *testing.T) {
	store, _, link, _ := reverseFixture(t)
	state := store.Snapshot()
	if err := store.MarkTopologyApplied(state.Revision, []string{"public-parent", "nat-child"}); err != nil {
		t.Fatal(err)
	}
	rollback, err := CompileAppliedUsers(store.Snapshot(), testAddressResolver{"public-parent": "203.0.113.20"})
	if err != nil {
		t.Fatal(err)
	}
	deployer, err := NewDeployer(store, testAddressResolver{}, &applyingController{store: deployment.NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	deployer.transaction = &topologyTransaction{Agents: []topologyTransactionAgent{{AgentID: "nat-child", RollbackConfig: rollback.Configs["nat-child"]}, {AgentID: "public-parent", RollbackConfig: rollback.Configs["public-parent"]}}}
	resolver := deployer.resolverForState(store.Snapshot())
	address, ok := resolver.AgentAddressForFamily("public-parent", pool.FamilyIPv4)
	if !ok || address != "203.0.113.20" {
		t.Fatalf("retained reverse parent: %q, %v", address, ok)
	}
	if address, ok := resolver.AgentAddressForFamily("nat-child", pool.FamilyAuto); ok || address == wireGuardChildIP(link.ID) {
		t.Fatal("private SOCKS address escaped into public resolver")
	}
	if _, err := CompileAppliedUsers(store.Snapshot(), resolver); err != nil {
		t.Fatalf("applied profile unavailable after address loss: %v", err)
	}
}

// Optional real-engine test. It needs no root or OS WireGuard interface. CI or
// an operator can point this at a sing-box 1.14+ binary with wireguard/gvisor.
func TestReverseWireGuardRealEngine(t *testing.T) {
	boxBinary := os.Getenv("THEATROPOLIS_TEST_WIREGUARD_SING_BOX")
	if boxBinary == "" {
		t.Skip("set THEATROPOLIS_TEST_WIREGUARD_SING_BOX for real userspace tunnel test")
	}
	store, node, _, _ := reverseFixture(t)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	_ = udp.Close()
	if err := store.UpdateLink(node.ID, node.Links[0].ID, Endpoint{Protocol: ProtocolReverseWireGuard, ListenPort: port}); err != nil {
		t.Fatal(err)
	}
	// Two logical machines share this test host. Keep their loopback ports
	// distinct so a direct child connection cannot impersonate the WG bridge.
	if err := store.mutate(func(state *State) error {
		state.ProxyNodes[0].Links[0].WireGuard.ProbePort = 21001
		state.ProxyNodes[0].Links[0].WireGuard.SOCKSPort = 21002
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(store.Snapshot(), testAddressResolver{"public-parent": "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Upstream binaries lack our managed-user patch. Remove only the unrelated
	// public entrance and its SSM service; the reverse transport is unchanged.
	var parent map[string]any
	_ = json.Unmarshal(compiled.Configs["public-parent"], &parent)
	parent["inbounds"] = parent["inbounds"].([]any)[1:]
	delete(parent, "services")
	entry, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	entryPort := entry.Addr().(*net.TCPAddr).Port
	_ = entry.Close()
	parent["inbounds"] = append(parent["inbounds"].([]any), map[string]any{"type": "socks", "tag": "test-entry", "listen": "::1", "listen_port": entryPort})
	route := parent["route"].(map[string]any)
	route["rules"] = append(route["rules"].([]any), map[string]any{"inbound": []string{"test-entry"}, "action": "route", "outbound": linkOutboundTag(node.Links[0].ID)})
	for _, agent := range []string{"nat-child", "public-parent"} {
		config := compiled.Configs[agent]
		if agent == "public-parent" {
			config, _ = json.Marshal(parent)
		}
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, config, 0600); err != nil {
			t.Fatal(err)
		}
		check := exec.CommandContext(ctx, boxBinary, "check", "-c", path)
		if output, err := check.CombinedOutput(); err != nil {
			t.Fatalf("engine rejected %s: %v %s", agent, err, output)
		}
		cmd := exec.CommandContext(ctx, boxBinary, "run", "-c", path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			select {
			case <-exited:
			case <-time.After(time.Second):
			}
		})
		time.Sleep(100 * time.Millisecond)
		select {
		case err := <-exited:
			t.Fatalf("%s engine exited: %v", agent, err)
		default:
		}
	}
	// Validate the generated private bridge using the same readiness checker
	// through an inactive Manager with an explicitly written active profile.
	config, _ := json.Marshal(parent)
	dir := t.TempDir()
	manager, err := singbox.NewManager(singbox.ManagerOptions{Validator: singbox.Validator{BinaryPath: boxBinary, StateDirectory: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sing-box"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sing-box", "active.json"), config, 0600); err != nil {
		t.Fatal(err)
	}
	variant, err := singbox.BuildManagedUserAuthorityVariant(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.CheckReverseTunnels(ctx, variant.TopologySHA256[:]); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "reverse-ok") }))
	defer server.Close()
	proxy, _ := url.Parse("socks5://" + net.JoinHostPort("::1", strconv.Itoa(entryPort)))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("TCP through parent -> WireGuard -> child: %v", err)
	}
	contents, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(contents) != "reverse-ok" {
		t.Fatalf("TCP response: %q", contents)
	}
	// Exercise SagerNet UoT v2 through the parent SOCKS inbound, its generated
	// SOCKS outbound, the WG tunnel, and the child's UDP exit.
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 256)
		n, from, err := echo.ReadFrom(buffer)
		if err == nil {
			_, _ = echo.WriteTo(buffer[:n], from)
		}
	}()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("::1", strconv.Itoa(entryPort)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	if err != nil || !reflect.DeepEqual(reply, []byte{5, 0}) {
		t.Fatalf("UoT greeting: %v %v", reply, err)
	}
	magic := "sp.v2.udp-over-tcp.arpa"
	request := append([]byte{5, 1, 0, 3, byte(len(magic))}, []byte(magic)...)
	request = append(request, 0, 0)
	_, _ = conn.Write(request)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil || header[1] != 0 {
		t.Fatalf("UoT SOCKS connect: %v %v", header, err)
	}
	addressLen := 4
	if header[3] == 4 {
		addressLen = 16
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addressLen+2)); err != nil {
		t.Fatal(err)
	}
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	packet := []byte{1, 1, 127, 0, 0, 1, byte(echoPort >> 8), byte(echoPort)}
	payload := []byte("udp-reverse-ok")
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(payload)))
	packet = append(packet, payload...)
	_, _ = conn.Write(packet)
	length := make([]byte, 2)
	if _, err := io.ReadFull(conn, length); err != nil {
		t.Fatalf("UDP through reverse tunnel: %v", err)
	}
	udpReply := make([]byte, binary.BigEndian.Uint16(length))
	if _, err := io.ReadFull(conn, udpReply); err != nil || string(udpReply) != string(payload) {
		t.Fatalf("UDP echo: %q %v", udpReply, err)
	}
}

type testAddressResolver map[string]string

func (r testAddressResolver) AgentAddressForFamily(id string, _ pool.Family) (string, bool) {
	address, ok := r[id]
	return address, ok
}
