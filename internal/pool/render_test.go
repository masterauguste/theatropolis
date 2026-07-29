package pool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/masterauguste/theatropolis/internal/deployment"
)

const renderParisConfig = `{
	"inbounds": [
		{"type":"shadowsocks","tag":"ss-key","listen_port":8388,"method":"2022-blake3-aes-128-gcm","password":"srvkey"},
		{"type":"shadowsocks","tag":"ss-users","listen_port":8389,"method":"2022-blake3-aes-256-gcm","password":"srvkey2","users":[{"name":"carol","password":"carolkey"}]},
		{"type":"anytls","tag":"tls-acme","listen_port":8443,"users":[{"name":"alice","password":"pa"}],"tls":{"enabled":true,"certificate_provider":"theatropolis-acme-tls-acme"}},
		{"type":"anytls","tag":"tls-files","listen_port":8444,"users":[{"name":"bob","password":"pb"}],"tls":{"enabled":true,"certificate_path":"/cert.pem","key_path":"/key.pem"}},
		{"type":"hysteria2","tag":"hy2","listen_port":443,"up_mbps":100,"down_mbps":200,"obfs":{"type":"salamander","password":"obfskey"},"users":[{"name":"dan","password":"pd"}],"tls":{"enabled":true,"certificate_provider":"missing-provider"}}
	],
	"certificate_providers": [
		{"tag":"theatropolis-acme-tls-acme","type":"acme","domain":["paris.example.com"],"email":"op@example.com"}
	]
}`

func renderSource(t *testing.T) DeriveSource {
	t.Helper()
	record := deploymentRecord(t, "edge-paris-1", renderParisConfig)
	return func(agentID string) *deployment.Record {
		if agentID == "edge-paris-1" {
			return record
		}
		return nil
	}
}

func renderTestRegistry(t *testing.T) *Registry {
	t.Helper()
	registry := deriveTestRegistry(t) // edge-paris-1 → 203.0.113.10
	if err := registry.UpsertManual("upstream", json.RawMessage(`{"type":"socks","server":"10.0.0.1","server_port":1080,"version":"5"}`)); err != nil {
		t.Fatalf("UpsertManual() error = %v", err)
	}
	return registry
}

func renderOutbound(t *testing.T, rendered []byte, tag string) map[string]any {
	t.Helper()
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(rendered, &document); err != nil {
		t.Fatalf("rendered config is not valid JSON: %v", err)
	}
	for _, outbound := range document.Outbounds {
		if outbound["tag"] == tag {
			return outbound
		}
	}
	t.Fatalf("rendered config has no outbound with tag %q: %s", tag, rendered)
	return nil
}

func logicalConfig(outbounds string) []byte {
	return []byte(`{"log":{"disabled":true},"outbounds":` + outbounds + `,"route":{"final":"plain"}}`)
}

func TestRenderFastPath(t *testing.T) {
	registry := renderTestRegistry(t)
	logical := logicalConfig(`[{"type":"direct","tag":"plain"}]`)
	rendered, refs, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if string(rendered) != string(logical) {
		t.Fatalf("Render() = %s, want input unchanged", rendered)
	}
	if refs != nil {
		t.Fatalf("refs = %v, want nil", refs)
	}

	// The marker string outside outbounds must not trigger rewriting.
	withMarkerElsewhere := []byte(`{"notes":"mentions theatropolis-pool-ref","outbounds":[{"type":"direct","tag":"plain"}]}`)
	rendered, refs, err = Render(registry, withMarkerElsewhere, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if string(rendered) != string(withMarkerElsewhere) {
		t.Fatalf("Render() rewrote outbounds without refs: %s", rendered)
	}
	if len(refs) != 0 {
		t.Fatalf("refs = %v, want none", refs)
	}

	// outbounds absent: return input as-is.
	noOutbounds := []byte(`{"notes":"theatropolis-pool-ref","route":{}}`)
	rendered, refs, err = Render(registry, noOutbounds, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if string(rendered) != string(noOutbounds) || refs != nil {
		t.Fatalf("Render() = %s, %v, want input unchanged, nil refs", rendered, refs)
	}
}

func TestRenderShadowsocks(t *testing.T) {
	registry := renderTestRegistry(t)
	logical := logicalConfig(`[
		{"type":"theatropolis-pool-ref","tag":"via-key","ref":"agent/edge-paris-1/ss-key/_server"},
		{"type":"theatropolis-pool-ref","tag":"via-carol","ref":"agent/edge-paris-1/ss-users/carol"}
	]`)
	rendered, refs, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if strings.Join(refs, ",") != "agent/edge-paris-1/ss-key/_server,agent/edge-paris-1/ss-users/carol" {
		t.Fatalf("refs = %v", refs)
	}

	serverKey := renderOutbound(t, rendered, "via-key")
	if serverKey["type"] != "shadowsocks" ||
		serverKey["server"] != "203.0.113.10" ||
		serverKey["server_port"] != float64(8388) ||
		serverKey["method"] != "2022-blake3-aes-128-gcm" ||
		serverKey["password"] != "srvkey" {
		t.Fatalf("server-key outbound = %v", serverKey)
	}
	if _, leaked := serverKey["listen"]; leaked {
		t.Fatalf("server-key outbound leaks inbound-only key: %v", serverKey)
	}

	carol := renderOutbound(t, rendered, "via-carol")
	if carol["password"] != "srvkey2:carolkey" {
		t.Fatalf("EIH password = %v, want srvkey2:carolkey", carol["password"])
	}
	if carol["method"] != "2022-blake3-aes-256-gcm" {
		t.Fatalf("method = %v", carol["method"])
	}
}

func TestRenderAnytlsACMEAndFiles(t *testing.T) {
	registry := renderTestRegistry(t)
	logical := logicalConfig(`[
		{"type":"theatropolis-pool-ref","tag":"via-acme","ref":"agent/edge-paris-1/tls-acme/alice"},
		{"type":"theatropolis-pool-ref","tag":"via-files","ref":"agent/edge-paris-1/tls-files/bob"}
	]`)
	rendered, _, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	acme := renderOutbound(t, rendered, "via-acme")
	if acme["type"] != "anytls" || acme["password"] != "pa" || acme["server_port"] != float64(8443) {
		t.Fatalf("acme outbound = %v", acme)
	}
	tlsBlock, ok := acme["tls"].(map[string]any)
	if !ok {
		t.Fatalf("acme tls = %v", acme["tls"])
	}
	if tlsBlock["enabled"] != true || tlsBlock["server_name"] != "paris.example.com" || tlsBlock["insecure"] != false {
		t.Fatalf("acme tls = %v, want verified paris.example.com", tlsBlock)
	}

	files := renderOutbound(t, rendered, "via-files")
	tlsBlock, ok = files["tls"].(map[string]any)
	if !ok {
		t.Fatalf("files tls = %v", files["tls"])
	}
	if tlsBlock["server_name"] != "" || tlsBlock["insecure"] != true {
		t.Fatalf("files tls = %v, want self-signed assumption (insecure, no server_name)", tlsBlock)
	}
}

func TestRenderTLSHostnameOverride(t *testing.T) {
	registry := renderTestRegistry(t)
	logical := logicalConfig(`[
		{"type":"theatropolis-pool-ref","tag":"via-domain","ref":"agent/edge-paris-1/tls-acme/alice","server":"Edge.Example.COM."},
		{"type":"theatropolis-pool-ref","tag":"ss-domain","ref":"agent/edge-paris-1/ss-key/_server","server":"edge.example.com"}
	]`)
	rendered, _, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	outbound := renderOutbound(t, rendered, "via-domain")
	if outbound["type"] != "anytls" || outbound["server"] != "edge.example.com" {
		t.Fatalf("TLS hostname outbound = %v", outbound)
	}
	tlsBlock, ok := outbound["tls"].(map[string]any)
	if !ok || tlsBlock["server_name"] != "paris.example.com" || tlsBlock["insecure"] != false {
		t.Fatalf("TLS hostname verification changed unexpectedly: %v", outbound["tls"])
	}
	if fallback := renderOutbound(t, rendered, "ss-domain"); fallback["type"] != "direct" {
		t.Fatalf("Shadowsocks hostname override = %v, want direct fallback", fallback)
	}
}

func TestRenderHysteria2(t *testing.T) {
	registry := renderTestRegistry(t)
	logical := logicalConfig(`[
		{"type":"theatropolis-pool-ref","tag":"via-hy2","ref":"agent/edge-paris-1/hy2/dan"}
	]`)
	rendered, _, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	outbound := renderOutbound(t, rendered, "via-hy2")
	if outbound["type"] != "hysteria2" ||
		outbound["password"] != "pd" ||
		outbound["up_mbps"] != float64(100) ||
		outbound["down_mbps"] != float64(200) {
		t.Fatalf("hy2 outbound = %v", outbound)
	}
	obfs, ok := outbound["obfs"].(map[string]any)
	if !ok || obfs["type"] != "salamander" || obfs["password"] != "obfskey" {
		t.Fatalf("hy2 obfs = %v", outbound["obfs"])
	}
	// The certificate provider does not resolve → self-signed assumption.
	tlsBlock, ok := outbound["tls"].(map[string]any)
	if !ok || tlsBlock["insecure"] != true || tlsBlock["server_name"] != "" {
		t.Fatalf("hy2 tls = %v", outbound["tls"])
	}
}

func TestRenderManual(t *testing.T) {
	registry := renderTestRegistry(t)
	logical := logicalConfig(`[
		{"type":"theatropolis-pool-ref","tag":"shared","ref":"manual/upstream"}
	]`)
	rendered, _, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	outbound := renderOutbound(t, rendered, "shared")
	if outbound["type"] != "socks" || outbound["server"] != "10.0.0.1" || outbound["version"] != "5" {
		t.Fatalf("manual outbound = %v", outbound)
	}
	// The stored manual entry keeps its own (absent) tag; only the copy is forced.
	entry, _ := registry.ManualByName("upstream")
	if strings.Contains(string(entry.Outbound), `"tag"`) {
		t.Fatalf("stored manual outbound mutated: %s", entry.Outbound)
	}
}

func TestRenderDeadRefsBecomeDirect(t *testing.T) {
	registry := renderTestRegistry(t)
	cases := []struct {
		name string
		ref  string
	}{
		{"unknown manual", "manual/nope"},
		{"agent gone", "agent/edge-gone-1/ss-key/_server"},
		{"inbound missing", "agent/edge-paris-1/no-such-inbound/alice"},
		{"user missing", "agent/edge-paris-1/tls-acme/mallory"},
		{"server key on anytls", "agent/edge-paris-1/tls-acme/_server"},
		{"no address", "agent/edge-lyon-1/ss-key/_server"},
		{"malformed ref", "agent/edge-paris-1"},
		{"empty ref", ""},
		{"bad component charset", "agent/edge-paris-1/bad tag!/alice"},
	}
	outbounds := make([]string, 0, len(cases))
	for index, testCase := range cases {
		outbounds = append(outbounds,
			`{"type":"theatropolis-pool-ref","tag":"t`+string(rune('a'+index))+`","ref":"`+testCase.ref+`"}`)
	}
	logical := logicalConfig(`[` + strings.Join(outbounds, ",") + `]`)
	rendered, refs, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v, want dead refs to degrade", err)
	}
	if len(refs) != len(cases) {
		t.Fatalf("refs = %v, want %d entries", refs, len(cases))
	}
	for index, testCase := range cases {
		outbound := renderOutbound(t, rendered, "t"+string(rune('a'+index)))
		if outbound["type"] != "direct" {
			t.Errorf("%s: outbound = %v, want direct fallback", testCase.name, outbound)
		}
		if len(outbound) != 2 {
			t.Errorf("%s: fallback carries extra keys: %v", testCase.name, outbound)
		}
	}
}

func TestRenderPassthrough(t *testing.T) {
	registry := renderTestRegistry(t)
	logical := logicalConfig(`[
		{"type":"selector","tag":"plain","outbounds":["a","b"],"interrupt_exist_connections":true},
		{"type":"theatropolis-pool-ref","tag":"via-key","ref":"agent/edge-paris-1/ss-key/_server"}
	]`)
	rendered, _, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	plain := renderOutbound(t, rendered, "plain")
	if plain["type"] != "selector" || plain["interrupt_exist_connections"] != true {
		t.Fatalf("passthrough outbound = %v", plain)
	}
	outbounds, ok := plain["outbounds"].([]any)
	if !ok || len(outbounds) != 2 || outbounds[0] != "a" {
		t.Fatalf("passthrough nested outbounds = %v", plain["outbounds"])
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(rendered, &document); err != nil {
		t.Fatalf("rendered config invalid: %v", err)
	}
	if _, ok := document["route"]; !ok {
		t.Fatal("rendered config dropped the route section")
	}
	if _, ok := document["log"]; !ok {
		t.Fatal("rendered config dropped the log section")
	}
}

func TestRenderRefRequiresTag(t *testing.T) {
	registry := renderTestRegistry(t)
	for _, outbounds := range []string{
		`[{"type":"theatropolis-pool-ref","ref":"manual/upstream"}]`,
		`[{"type":"theatropolis-pool-ref","tag":"","ref":"manual/upstream"}]`,
		`[{"type":"theatropolis-pool-ref","tag":"bad tag!","ref":"manual/upstream"}]`,
		`[{"type":"theatropolis-pool-ref","tag":7,"ref":"manual/upstream"}]`,
	} {
		if _, _, err := Render(registry, logicalConfig(outbounds), renderSource(t)); err == nil {
			t.Errorf("Render(%s) error = nil, want tag error", outbounds)
		}
	}
}

func TestRenderRejectsMalformedConfigs(t *testing.T) {
	registry := renderTestRegistry(t)
	if _, _, err := Render(registry, []byte(`{"outbounds": "theatropolis-pool-ref"`), renderSource(t)); err == nil {
		t.Fatal("Render() error = nil, want outbounds-not-array error")
	}
	if _, _, err := Render(registry, []byte(`{"outbounds": [{"type":"theatropolis-pool-ref"`), renderSource(t)); err == nil {
		t.Fatal("Render() error = nil, want JSON error")
	}
}

func TestRefsHelper(t *testing.T) {
	logical := logicalConfig(`[
		{"type":"direct","tag":"plain"},
		{"type":"theatropolis-pool-ref","tag":"a","ref":"manual/upstream"},
		{"type":"theatropolis-pool-ref","tag":"b","ref":"agent/edge-paris-1/ss-key/_server"}
	]`)
	refs := Refs(logical)
	if strings.Join(refs, ",") != "manual/upstream,agent/edge-paris-1/ss-key/_server" {
		t.Fatalf("Refs() = %v", refs)
	}
	if refs := Refs([]byte(`{"outbounds":[{"type":"direct","tag":"plain"}]}`)); refs != nil {
		t.Fatalf("Refs() = %v, want nil without marker", refs)
	}
	if refs := Refs([]byte(`{not json theatropolis-pool-ref`)); refs != nil {
		t.Fatalf("Refs() = %v, want nil for broken JSON", refs)
	}
	if refs := Refs([]byte(`{"note":"theatropolis-pool-ref"}`)); refs != nil {
		t.Fatalf("Refs() = %v, want nil without outbounds", refs)
	}
}

func renderDualFamilyRegistry(t *testing.T) *Registry {
	t.Helper()
	registry := renderTestRegistry(t)
	if _, err := registry.SetReported("edge-paris-1", []string{"203.0.113.10"}, []string{"2001:db8::10"}); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	return registry
}

func TestRenderFamilySelection(t *testing.T) {
	registry := renderDualFamilyRegistry(t)
	logical := logicalConfig(`[
		{"type":"theatropolis-pool-ref","tag":"via-v4","ref":"agent/edge-paris-1/ss-key/_server","family":"ipv4"},
		{"type":"theatropolis-pool-ref","tag":"via-v6","ref":"agent/edge-paris-1/ss-key/_server","family":"ipv6"},
		{"type":"theatropolis-pool-ref","tag":"via-auto","ref":"agent/edge-paris-1/ss-key/_server","family":"auto"},
		{"type":"theatropolis-pool-ref","tag":"via-default","ref":"agent/edge-paris-1/ss-key/_server"}
	]`)
	rendered, refs, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if len(refs) != 4 {
		t.Fatalf("refs = %v, want 4", refs)
	}
	if got := renderOutbound(t, rendered, "via-v4")["server"]; got != "203.0.113.10" {
		t.Fatalf("ipv4 ref server = %v, want 203.0.113.10", got)
	}
	if got := renderOutbound(t, rendered, "via-v6")["server"]; got != "2001:db8::10" {
		t.Fatalf("ipv6 ref server = %v, want 2001:db8::10", got)
	}
	// auto and absent family both walk v4 first.
	if got := renderOutbound(t, rendered, "via-auto")["server"]; got != "203.0.113.10" {
		t.Fatalf("auto ref server = %v, want 203.0.113.10", got)
	}
	if got := renderOutbound(t, rendered, "via-default")["server"]; got != "203.0.113.10" {
		t.Fatalf("default ref server = %v, want 203.0.113.10", got)
	}
}

func TestRenderPrivateOnlySourceRendersDirect(t *testing.T) {
	// A source agent whose only reported addresses are non-routable has no
	// usable pool address: refs to it render as the direct fallback.
	registry, _ := openTestRegistry(t)
	if _, err := registry.SetReported("edge-paris-1", []string{"10.0.0.8"}, []string{"fd00::9"}); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	logical := logicalConfig(`[
		{"type":"direct","tag":"plain"},
		{"type":"theatropolis-pool-ref","tag":"via-key","ref":"agent/edge-paris-1/ss-key/_server"}
	]`)
	rendered, _, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if outbound := renderOutbound(t, rendered, "via-key"); outbound["type"] != "direct" {
		t.Fatalf("private-only source outbound = %v, want direct fallback", outbound)
	}
}

func TestRenderFamilyDeadRefs(t *testing.T) {
	// renderTestRegistry gives edge-paris-1 a reported v4 address only.
	registry := renderTestRegistry(t)
	cases := []struct {
		name     string
		outbound string
	}{
		{"invalid family value", `{"type":"theatropolis-pool-ref","tag":"ta","ref":"agent/edge-paris-1/ss-key/_server","family":"ipv5"}`},
		{"non-string family", `{"type":"theatropolis-pool-ref","tag":"tb","ref":"agent/edge-paris-1/ss-key/_server","family":7}`},
		{"ipv6 requested, v4 only", `{"type":"theatropolis-pool-ref","tag":"tc","ref":"agent/edge-paris-1/ss-key/_server","family":"ipv6"}`},
	}
	logical := logicalConfig(`[` + cases[0].outbound + `,` + cases[1].outbound + `,` + cases[2].outbound + `]`)
	rendered, refs, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v, want dead refs to degrade", err)
	}
	if len(refs) != len(cases) {
		t.Fatalf("refs = %v, want %d entries", refs, len(cases))
	}
	for index, testCase := range cases {
		outbound := renderOutbound(t, rendered, "t"+string(rune('a'+index)))
		if outbound["type"] != "direct" || len(outbound) != 2 {
			t.Errorf("%s: outbound = %v, want direct fallback", testCase.name, outbound)
		}
	}
}

func TestRenderManualIgnoresFamily(t *testing.T) {
	registry := renderTestRegistry(t)
	logical := logicalConfig(`[
		{"type":"theatropolis-pool-ref","tag":"shared","ref":"manual/upstream","family":"ipv6"}
	]`)
	rendered, _, err := Render(registry, logical, renderSource(t))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	outbound := renderOutbound(t, rendered, "shared")
	if outbound["type"] != "socks" || outbound["server"] != "10.0.0.1" {
		t.Fatalf("manual outbound with family = %v, want pass-through", outbound)
	}
}
