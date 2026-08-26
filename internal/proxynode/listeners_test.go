package proxynode

import "testing"

func TestListenerPresetsCollapseCompatibleReferencesAndStripSecrets(t *testing.T) {
	shared := Endpoint{
		Protocol: ProtocolHysteria2, Listen: "::", ListenPort: 8443, Family: "auto",
		TLS:      TLSConfig{Mode: TLSModeSelfSigned, ServerName: "relay.example.com"},
		ObfsType: "salamander", ObfsSecret: "must-not-leave-master-state",
	}
	state := State{ProxyNodes: []ProxyNode{{
		ID: "cinema",
		Hops: []Hop{
			{ID: "entrance", AgentID: "edge-a"},
			{ID: "shared-a", AgentID: "edge-shared"},
			{ID: "shared-b", AgentID: "edge-shared"},
		},
		Entrance: Entrance{HopID: "entrance", Endpoint: Endpoint{
			Protocol: ProtocolAnyTLS, Listen: "::", ListenPort: 443,
			TLS: TLSConfig{Mode: TLSModeSelfSigned, ServerName: "entrance.example.com"},
		}},
		Links: []Link{
			{ID: "link-a", ChildHopID: "shared-a", Endpoint: shared},
			{ID: "link-b", ChildHopID: "shared-b", Endpoint: shared},
		},
	}}}

	var got *ListenerPreset
	for _, preset := range ListenerPresets(state) {
		if preset.AgentID == "edge-shared" {
			copy := preset
			got = &copy
			break
		}
	}
	if got == nil {
		t.Fatal("shared listener preset was not returned")
	}
	if got.ReferenceCount != 2 {
		t.Fatalf("reference count = %d, want 2", got.ReferenceCount)
	}
	if got.ID == "" || got.ID != ListenerPresetID("edge-shared", shared) {
		t.Fatalf("preset ID = %q, want stable listener ID", got.ID)
	}
	if got.Endpoint.ObfsSecret != "" || got.Endpoint.ServerKey != "" {
		t.Fatalf("listener preset leaked generated secrets: %#v", got.Endpoint)
	}
	if state.ProxyNodes[0].Links[0].Endpoint.ObfsSecret == "" {
		t.Fatal("ListenerPresets modified the source state while scrubbing its copy")
	}
}

func TestListenerCompatibilityIgnoresInactiveTLSModeFields(t *testing.T) {
	clean := Endpoint{
		Protocol: ProtocolAnyTLS, Listen: "::", ListenPort: 443,
		TLS: TLSConfig{Mode: TLSModeSelfSigned, ServerName: "relay.example.com"},
	}
	stale := clean
	stale.TLS.Email = "old-acme@example.com"
	stale.TLS.CertificatePath = "/old/certificate.pem"
	stale.TLS.KeyPath = "/old/private-key.pem"

	cleanKey, _, err := listenerKeys("edge-a", clean)
	if err != nil {
		t.Fatal(err)
	}
	staleKey, _, err := listenerKeys("edge-a", stale)
	if err != nil {
		t.Fatal(err)
	}
	if staleKey != cleanKey {
		t.Fatalf("inactive TLS fields changed listener compatibility:\nclean %q\nstale %q", cleanKey, staleKey)
	}
	if ListenerPresetID("edge-a", stale) != ListenerPresetID("edge-a", clean) {
		t.Fatal("inactive TLS fields changed the listener preset identity")
	}
}

func TestNormalizeEndpointClearsInactiveTLSModeFields(t *testing.T) {
	tests := []struct {
		name string
		mode TLSMode
		want TLSConfig
	}{
		{
			name: "acme", mode: TLSModeACME,
			want: TLSConfig{Mode: TLSModeACME, ServerName: "relay.example.com", Email: "admin@example.com"},
		},
		{
			name: "self-signed", mode: TLSModeSelfSigned,
			want: TLSConfig{Mode: TLSModeSelfSigned, ServerName: "relay.example.com"},
		},
		{
			name: "files", mode: TLSModeFiles,
			want: TLSConfig{Mode: TLSModeFiles, ServerName: "relay.example.com", CertificatePath: "/certificate.pem", KeyPath: "/private-key.pem"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := normalizeEndpoint(Endpoint{TLS: TLSConfig{
				Mode: test.mode, ServerName: " relay.example.com ", Email: " admin@example.com ",
				CertificatePath: " /certificate.pem ", KeyPath: " /private-key.pem ",
			}})
			if endpoint.TLS != test.want {
				t.Fatalf("normalized TLS = %#v, want %#v", endpoint.TLS, test.want)
			}
		})
	}
}
