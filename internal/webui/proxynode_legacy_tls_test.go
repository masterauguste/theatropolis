package webui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

func TestParseEndpointFormRestrictsLegacyFileCertificates(t *testing.T) {
	t.Parallel()

	const certificatePath = "/etc/theatropolis/certs/server.pem"
	const keyPath = "/etc/theatropolis/certs/server.key"
	form := proxyTLSEndpointForm(proxynode.TLSModeFiles, certificatePath, keyPath, 443)
	if _, err := parseEndpointForm(form); err == nil || !strings.Contains(err.Error(), "cannot be selected") {
		t.Fatalf("new legacy file endpoint error = %v", err)
	}

	current := proxynode.Endpoint{
		Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
		TLS: proxynode.TLSConfig{
			Mode: proxynode.TLSModeFiles, CertificatePath: certificatePath, KeyPath: keyPath,
		},
	}
	roundTripped, err := parseEndpointForm(form, current)
	if err != nil {
		t.Fatal(err)
	}
	if roundTripped.TLS != current.TLS {
		t.Fatalf("legacy file TLS round-trip = %#v, want %#v", roundTripped.TLS, current.TLS)
	}

	tampered := cloneProxyForm(form)
	tampered.Set("certificate_path", "/tmp/attacker.pem")
	if _, err := parseEndpointForm(tampered, current); err == nil || !strings.Contains(err.Error(), "cannot be changed") {
		t.Fatalf("changed legacy file path error = %v", err)
	}

	managed := cloneProxyForm(form)
	managed.Set("tls_mode", string(proxynode.TLSModeSelfSigned))
	managed.Set("server_name", "legacy.example")
	parsed, err := parseEndpointForm(managed, current)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TLS.CertificatePath != "" || parsed.TLS.KeyPath != "" {
		t.Fatalf("Agent-managed TLS retained crafted file paths: %#v", parsed.TLS)
	}
}

func TestProxyNodePOSTsRestrictLegacyFileCertificates(t *testing.T) {
	t.Parallel()

	fixture := newWebFixture(t)
	for _, agentID := range []string{"edge-a", "edge-b", "edge-c"} {
		enrollAgent(t, fixture.registry, agentID)
	}
	const certificatePath = "/etc/theatropolis/certs/server.pem"
	const keyPath = "/etc/theatropolis/certs/server.key"

	create := proxyTLSEndpointForm(proxynode.TLSModeFiles, certificatePath, keyPath, 443)
	create.Set("csrf_token", fixture.session.CSRFToken)
	create.Set("name", "Crafted Files")
	create.Set("agent_id", "edge-a")
	create.Set("terminal", string(proxynode.TargetDirect))
	response := fixture.postProxyMutation("/proxy-nodes", create)
	if response.Code != http.StatusBadRequest || len(fixture.proxyNodes.Snapshot().ProxyNodes) != 0 {
		t.Fatalf("crafted file-TLS Proxy Node create = %d nodes=%d body=%q", response.Code, len(fixture.proxyNodes.Snapshot().ProxyNodes), response.Body.String())
	}

	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name: "Legacy TLS", RootAgent: "edge-a", Final: proxynode.Target{Type: proxynode.TargetDirect},
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{
				Mode: proxynode.TLSModeFiles, CertificatePath: certificatePath, KeyPath: keyPath,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	entranceForm := proxyTLSEndpointForm(proxynode.TLSModeFiles, certificatePath, keyPath, 443)
	entranceForm.Set("csrf_token", fixture.session.CSRFToken)
	response = fixture.postProxyMutation("/proxy-nodes/"+url.PathEscape(node.ID)+"/entrance", entranceForm)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("exact legacy entrance round-trip = %d %q", response.Code, response.Body.String())
	}

	tamperedEntrance := cloneProxyForm(entranceForm)
	tamperedEntrance.Set("key_path", "/tmp/attacker.key")
	response = fixture.postProxyMutation("/proxy-nodes/"+url.PathEscape(node.ID)+"/entrance", tamperedEntrance)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("changed legacy entrance key path = %d %q", response.Code, response.Body.String())
	}

	response = fixture.postProxyMutation(
		"/proxy-nodes/"+url.PathEscape(node.ID)+"/hops/"+url.PathEscape(node.Entrance.HopID),
		url.Values{"csrf_token": {fixture.session.CSRFToken}, "agent_id": {"edge-b"}},
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("legacy entrance move = %d %q", response.Code, response.Body.String())
	}
	afterMove, _ := fixture.proxyNodes.ProxyNode(node.ID)
	entranceHop, _ := proxyHop(afterMove, afterMove.Entrance.HopID)
	if entranceHop.AgentID != "edge-a" {
		t.Fatalf("rejected legacy entrance move changed Agent to %q", entranceHop.AgentID)
	}

	branch := proxyTLSEndpointForm(proxynode.TLSModeFiles, certificatePath, keyPath, 7443)
	branch.Set("csrf_token", fixture.session.CSRFToken)
	branch.Set("match", string(proxynode.MatchDomain))
	branch.Set("values", "crafted.example")
	branch.Set("child_agent", "edge-b")
	branch.Set("child_terminal", string(proxynode.TargetDirect))
	response = fixture.postProxyMutation(
		"/proxy-nodes/"+url.PathEscape(node.ID)+"/hops/"+url.PathEscape(node.Entrance.HopID)+"/links",
		branch,
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("crafted file-TLS branch = %d %q", response.Code, response.Body.String())
	}
	afterBranch, _ := fixture.proxyNodes.ProxyNode(node.ID)
	if len(afterBranch.Links) != 0 || len(afterBranch.Hops) != 1 {
		t.Fatalf("rejected file-TLS branch changed topology: %#v", afterBranch)
	}

	firstLink, firstChild, _, err := fixture.proxyNodes.AddBranch(node.ID, proxynode.AddBranchInput{
		AddLinkInput: proxynode.AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildAgent: "edge-b",
			Endpoint: proxynode.Endpoint{
				Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 8443, Family: "auto",
				TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeFiles, CertificatePath: certificatePath, KeyPath: keyPath},
			},
			Final: proxynode.Target{Type: proxynode.TargetDirect},
		},
		Match: proxynode.MatchDomain, Values: []string{"first.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	secondLink, secondChild, _, err := fixture.proxyNodes.AddBranch(node.ID, proxynode.AddBranchInput{
		AddLinkInput: proxynode.AddLinkInput{
			ParentHopID: node.Entrance.HopID, ChildAgent: "edge-b",
			Endpoint: proxynode.Endpoint{
				Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 9443, Family: "auto",
				TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeFiles, CertificatePath: certificatePath, KeyPath: keyPath},
			},
			Final: proxynode.Target{Type: proxynode.TargetDirect},
		},
		Match: proxynode.MatchDomain, Values: []string{"second.example"},
	})
	if err != nil {
		t.Fatal(err)
	}

	firstEdit := proxyTLSEndpointForm(proxynode.TLSModeFiles, certificatePath, keyPath, 8443)
	firstEdit.Set("csrf_token", fixture.session.CSRFToken)
	response = fixture.postProxyMutation(proxyLinkURL(node.ID, firstLink.ID), firstEdit)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("exact legacy Link round-trip = %d %q", response.Code, response.Body.String())
	}
	tamperedLink := cloneProxyForm(firstEdit)
	tamperedLink.Set("certificate_path", "/tmp/attacker.pem")
	response = fixture.postProxyMutation(proxyLinkURL(node.ID, firstLink.ID), tamperedLink)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("changed legacy Link certificate path = %d %q", response.Code, response.Body.String())
	}

	response = fixture.postProxyMutation(
		"/proxy-nodes/"+url.PathEscape(node.ID)+"/hops/"+url.PathEscape(secondChild.ID),
		url.Values{"csrf_token": {fixture.session.CSRFToken}, "agent_id": {"edge-c"}},
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("legacy child Hop move = %d %q", response.Code, response.Body.String())
	}
	unchanged, _ := fixture.proxyNodes.ProxyNode(node.ID)
	unchangedChild, _ := proxyHop(unchanged, secondChild.ID)
	if unchangedChild.AgentID != "edge-b" {
		t.Fatalf("rejected legacy child move changed Agent to %q", unchangedChild.AgentID)
	}

	replaceFiles := proxyTLSEndpointForm(proxynode.TLSModeFiles, certificatePath, keyPath, 9443)
	replaceFiles.Set("csrf_token", fixture.session.CSRFToken)
	replaceFiles.Set("agent_id", "edge-c")
	replaceFiles.Set("terminal", string(proxynode.TargetDirect))
	replaceFiles.Set("confirm_replace", "yes")
	response = fixture.postProxyMutation(proxyLinkURL(node.ID, secondLink.ID)+"/destination", replaceFiles)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("legacy file-TLS destination replacement = %d %q", response.Code, response.Body.String())
	}
	unchanged, _ = fixture.proxyNodes.ProxyNode(node.ID)
	stillSecond, _ := proxyLink(unchanged, secondLink.ID)
	if stillSecond.ChildHopID != secondChild.ID {
		t.Fatal("rejected file-TLS destination replacement deleted the old subtree")
	}

	managedEdit := cloneProxyForm(firstEdit)
	managedEdit.Set("tls_mode", string(proxynode.TLSModeACME))
	managedEdit.Set("server_name", "relay.example")
	managedEdit.Set("email", "admin@example.com")
	response = fixture.postProxyMutation(proxyLinkURL(node.ID, firstLink.ID), managedEdit)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("legacy Link to ACME = %d %q", response.Code, response.Body.String())
	}
	updated, _ := fixture.proxyNodes.ProxyNode(node.ID)
	updatedFirst, _ := proxyLink(updated, firstLink.ID)
	if updatedFirst.Endpoint.TLS.Mode != proxynode.TLSModeACME || updatedFirst.Endpoint.TLS.CertificatePath != "" || updatedFirst.Endpoint.TLS.KeyPath != "" {
		t.Fatalf("legacy Link to ACME retained file paths: %#v", updatedFirst.Endpoint.TLS)
	}

	replaceManaged := proxyTLSEndpointForm(proxynode.TLSModeSelfSigned, certificatePath, keyPath, 9443)
	replaceManaged.Set("server_name", "replacement.example")
	replaceManaged.Set("csrf_token", fixture.session.CSRFToken)
	replaceManaged.Set("agent_id", "edge-c")
	replaceManaged.Set("terminal", string(proxynode.TargetDirect))
	replaceManaged.Set("confirm_replace", "yes")
	response = fixture.postProxyMutation(proxyLinkURL(node.ID, secondLink.ID)+"/destination", replaceManaged)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("Agent-managed destination replacement = %d %q", response.Code, response.Body.String())
	}
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	updatedSecond, _ := proxyLink(updated, secondLink.ID)
	if updatedSecond.ChildHopID == secondChild.ID || updatedSecond.Endpoint.TLS.CertificatePath != "" || updatedSecond.Endpoint.TLS.KeyPath != "" {
		t.Fatalf("destination replacement retained legacy file material: %#v", updatedSecond)
	}
	if _, exists := proxyHop(updated, firstChild.ID); !exists {
		t.Fatal("unrelated first Link subtree disappeared")
	}

	managedEntrance := cloneProxyForm(entranceForm)
	managedEntrance.Set("tls_mode", string(proxynode.TLSModeSelfSigned))
	managedEntrance.Set("server_name", "entrance.example")
	response = fixture.postProxyMutation("/proxy-nodes/"+url.PathEscape(node.ID)+"/entrance", managedEntrance)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("legacy entrance to self-signed = %d %q", response.Code, response.Body.String())
	}
	updated, _ = fixture.proxyNodes.ProxyNode(node.ID)
	if updated.Entrance.Endpoint.TLS.Mode != proxynode.TLSModeSelfSigned || updated.Entrance.Endpoint.TLS.CertificatePath != "" || updated.Entrance.Endpoint.TLS.KeyPath != "" {
		t.Fatalf("legacy entrance to self-signed retained file paths: %#v", updated.Entrance.Endpoint.TLS)
	}
}

func proxyTLSEndpointForm(mode proxynode.TLSMode, certificatePath, keyPath string, port int) url.Values {
	return url.Values{
		"protocol": {string(proxynode.ProtocolAnyTLS)}, "listen": {"::"}, "listen_port": {strconv.Itoa(port)}, "family": {"auto"}, "method": {""},
		"mux_enabled": {"0"}, "mux_padding": {"0"}, "mux_brutal": {"0"}, "mux_brutal_up_mbps": {""}, "mux_brutal_down_mbps": {""},
		"tls_mode": {string(mode)}, "server_name": {""}, "email": {""}, "certificate_path": {certificatePath}, "key_path": {keyPath},
		"up_mbps": {""}, "down_mbps": {""}, "obfs_type": {""},
	}
}

func cloneProxyForm(source url.Values) url.Values {
	result := make(url.Values, len(source))
	for key, values := range source {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func (f webFixture) postProxyMutation(path string, form url.Values) *httptest.ResponseRecorder {
	request := f.authenticatedMutationRequest(http.MethodPost, path, form.Encode())
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}
