package webui

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

func TestCGNATEnrollmentAndConnectivityControls(t *testing.T) {
	fixture := newWebFixture(t)
	form := url.Values{"display_name": {"NAT Server"}, "ttl_seconds": {"900"}, "csrf_token": {fixture.session.CSRFToken}, "reverse_only": {"1"}}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form.Encode()))
	if response.Code != http.StatusSeeOther {
		t.Fatalf("enrollment: %d %s", response.Code, response.Body.String())
	}
	var id string
	for _, snapshot := range fixture.registry.Snapshot(fixture.now) {
		if snapshot.DisplayName == "NAT Server" {
			id = snapshot.ID
		}
	}
	if id == "" || !fixture.proxyNodes.AgentReverseOnly(id) {
		t.Fatal("mode not persisted with enrollment")
	}
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.authenticatedMutationRequest(http.MethodPost, "/servers", form.Encode()))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `<option value="1" selected>`) {
		t.Fatalf("failed enrollment lost connectivity selection: %d", response.Code)
	}
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.authenticatedRequest(http.MethodGet, "/servers/"+id+"/manage", ""))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `name="reverse_only"`) {
		t.Fatalf("connectivity control: %d", response.Code)
	}
	form = url.Values{"csrf_token": {fixture.session.CSRFToken}, "reverse_only": {"0"}}
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.authenticatedMutationRequest(http.MethodPost, "/servers/"+id+"/connectivity", form.Encode()))
	if response.Code != http.StatusSeeOther || fixture.proxyNodes.AgentReverseOnly(id) {
		t.Fatalf("mode update: %d %s", response.Code, response.Body.String())
	}
	if err := fixture.proxyNodes.SetAgentReverseOnly("edge-online", true); err != nil {
		t.Fatal(err)
	}
	enrollAgent(t, fixture.registry, "edge-online")
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.authenticatedRequest(http.MethodGet, "/proxy-nodes/new", ""))
	if strings.Contains(response.Body.String(), `<option value="edge-online"`) {
		t.Fatal("CGNAT entrance offered")
	}
}

func TestReverseBranchEditorUsesParentAndOnlyReverseProtocol(t *testing.T) {
	fixture := newWebFixture(t)
	for _, id := range []string{"edge-online", "edge-offline"} {
		enrollAgent(t, fixture.registry, id)
	}
	if err := fixture.proxyNodes.SetAgentReverseOnly("edge-offline", true); err != nil {
		t.Fatal(err)
	}
	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{Name: "Reverse UI", RootAgent: "edge-online", Entrance: proxynode.Endpoint{Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "proxy.example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = fixture.proxyNodes.AddBranch(node.ID, proxynode.AddBranchInput{AddLinkInput: proxynode.AddLinkInput{ParentHopID: node.Entrance.HopID, ChildAgent: "edge-offline", Endpoint: proxynode.Endpoint{Protocol: proxynode.ProtocolReverseWireGuard, ListenPort: 51820}}, Match: proxynode.MatchNone})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), ""))
	if response.Code != http.StatusOK {
		t.Fatalf("tree: %d %s", response.Code, response.Body.String())
	}
	for _, expected := range []string{`data-parent-agent="edge-online"`, `data-reverse-only="1"`, `value="reverse_wireguard" selected`, `Reverse WireGuard + SOCKS5`} {
		if !strings.Contains(html.UnescapeString(response.Body.String()), expected) {
			t.Errorf("missing editor control %q", expected)
		}
	}
	// A permanently removed reverse-only Server remains a visible disabled
	// current Hop selection, so the operator can redirect or delete its branch.
	if err := fixture.registry.Revoke(t.Context(), "edge-offline"); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.authenticatedRequest(http.MethodGet, proxyNodeURL(node.ID), ""))
	if !strings.Contains(response.Body.String(), `<option value="" selected disabled>edge-offline`) {
		t.Fatal("deleted CGNAT current Hop disappeared from its selector")
	}
}
