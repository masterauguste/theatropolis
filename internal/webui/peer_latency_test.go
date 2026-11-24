package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
)

func TestDestinationOptionsUseAllToAllPeerLatencyAndReverseFlip(t *testing.T) {
	fixture := newWebFixture(t)
	enrollAgent(t, fixture.registry, "edge-online")
	enrollAgent(t, fixture.registry, "edge-public")
	enrollAgent(t, fixture.registry, "edge-cgnat")
	enrollAgent(t, fixture.registry, "edge-offline")
	fixture.controller.sessions["edge-public"] = true
	fixture.controller.sessions["edge-cgnat"] = true

	poolRegistry, err := pool.Open(filepath.Join(t.TempDir(), "pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.controller.poolRegistry = poolRegistry
	if _, err := poolRegistry.SetReported("edge-online", []string{"203.0.113.10"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := poolRegistry.SetReported("edge-public", []string{"203.0.113.20"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := fixture.proxyNodes.SetAgentReverseOnly("edge-cgnat", true); err != nil {
		t.Fatal(err)
	}

	node, err := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name:      "Edge",
		RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolAnyTLS, Listen: "::", ListenPort: 443, Family: "auto",
			TLS: proxynode.TLSConfig{Mode: proxynode.TLSModeSelfSigned, ServerName: "edge.example"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	now := fixture.handler.(*Handler).now()
	fixture.controller.RecordPeerLatency("edge-online", "edge-public", control.LinkLatencyState{
		ProbeType: "tcp", Responded: true, Connected: true, Duration: 28 * time.Millisecond, ObservedAt: now,
	})
	// For reverse-only destination edge-cgnat, the measured direction is edge-cgnat -> edge-online.
	fixture.controller.RecordPeerLatency("edge-cgnat", "edge-online", control.LinkLatencyState{
		ProbeType: "tcp", Responded: true, Connected: true, Duration: 41 * time.Millisecond, ObservedAt: now,
	})

	options := fixture.handler.(*Handler).proxyDestinationAgentOptions(node, node.Entrance.HopID, "")
	byID := make(map[string]agentOptionView, len(options))
	for _, option := range options {
		byID[option.ID] = option
	}
	if got := byID["edge-public"]; got.LatencyStatus != "reachable" || got.LatencyDetail != "28 ms · TCP" {
		t.Fatalf("edge-public option = %+v, want reachable / 28 ms · TCP", got)
	}
	if got := byID["edge-cgnat"]; got.LatencyStatus != "reachable" || got.LatencyDetail != "41 ms · TCP" {
		t.Fatalf("edge-cgnat option = %+v, want reachable / 41 ms · TCP", got)
	}
	if got := byID["edge-offline"]; got.LatencyStatus != "offline" || got.LatencyDetail != "Offline" {
		t.Fatalf("edge-offline option = %+v, want offline / Offline", got)
	}

	// Live probe for a reverse-only destination flips source/target and probes TCP port 20045.
	fixture.controller.linkProbeResult = control.LinkLatencyState{
		ProbeType: "tcp", Responded: true, Connected: true, Duration: 39 * time.Millisecond, ObservedAt: now,
	}
	req := fixture.authenticatedMutationRequest(
		http.MethodPost,
		"/proxy-nodes/"+node.ID+"/hops/"+node.Entrance.HopID+"/latency-probe",
		url.Values{
			"csrf_token": {fixture.session.CSRFToken},
			"agent_id":   {"edge-cgnat"},
			"family":     {"ipv4"},
		}.Encode(),
	)
	rec := httptest.NewRecorder()
	fixture.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("hop latency-probe status = %d body=%s", rec.Code, rec.Body.String())
	}
	if fixture.controller.linkProbeAgent != "edge-cgnat" ||
		fixture.controller.linkProbeAddress != "203.0.113.10" ||
		fixture.controller.linkProbePort != control.PeerLatencyListenPort ||
		fixture.controller.linkProbeType != "tcp" {
		t.Fatalf("probe target = agent:%q addr:%q port:%d type:%q",
			fixture.controller.linkProbeAgent, fixture.controller.linkProbeAddress, fixture.controller.linkProbePort, fixture.controller.linkProbeType)
	}
	var payload linkLatencyView
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Status != "reachable" || payload.Label != "39 ms" {
		t.Fatalf("payload = %+v", payload)
	}

	// Port 20045 is rejected for Proxy Node listeners.
	_, createErr := fixture.proxyNodes.CreateProxyNode(proxynode.CreateProxyNodeInput{
		Name:      "Reserved",
		RootAgent: "edge-online",
		Entrance: proxynode.Endpoint{
			Protocol: proxynode.ProtocolShadowsocks, Listen: "::", ListenPort: control.PeerLatencyListenPort,
			Family: "auto", Method: "2022-blake3-aes-128-gcm",
		},
	})
	if createErr == nil || !strings.Contains(createErr.Error(), "reserved") {
		t.Fatalf("CreateProxyNode on port 20045 err = %v, want reserved error", createErr)
	}
}
