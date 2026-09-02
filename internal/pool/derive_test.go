package pool

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
)

func deploymentRecord(t *testing.T, agentID, config string) *deployment.Record {
	t.Helper()
	record, err := deployment.New("dep-"+agentID, agentID, "rev-1", []byte(config), time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("deployment.New() error = %v", err)
	}
	return &record
}

func deriveTestRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, _ := openTestRegistry(t)
	if _, err := registry.SetReported("edge-paris-1", []string{"203.0.113.10"}, nil); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	return registry
}

func entryRefs(entries []Entry) []string {
	refs := make([]string, 0, len(entries))
	for _, entry := range entries {
		refs = append(refs, entry.Ref)
	}
	return refs
}

func TestDeriveMultiUserAndServerKey(t *testing.T) {
	registry := deriveTestRegistry(t)
	parisConfig := `{"inbounds":[
		{"type":"anytls","tag":"tls-in","listen_port":8443,"users":[{"name":"alice","password":"pa"},{"name":"bob","password":"pb"}],"tls":{"enabled":true,"certificate_path":"/cert","key_path":"/key"}},
		{"type":"shadowsocks","tag":"ss-key","listen_port":8388,"method":"2022-blake3-aes-128-gcm","password":"srvkey"},
		{"type":"shadowsocks","tag":"ss-users","listen_port":8389,"method":"2022-blake3-aes-128-gcm","password":"srvkey","users":[{"name":"carol","password":"pc"}]}
	]}`
	input := DeriveInput{
		AgentIDs: []string{"edge-paris-1"},
		Deployments: map[string]*deployment.Record{
			"edge-paris-1": deploymentRecord(t, "edge-paris-1", parisConfig),
		},
		Registry: registry,
	}
	entries := Derive(input)

	wantRefs := []string{
		"agent/edge-paris-1/ss-key/_server",
		"agent/edge-paris-1/ss-users/carol",
		"agent/edge-paris-1/tls-in/alice",
		"agent/edge-paris-1/tls-in/bob",
	}
	gotRefs := entryRefs(entries)
	if strings.Join(gotRefs, ",") != strings.Join(wantRefs, ",") {
		t.Fatalf("refs = %v, want %v", gotRefs, wantRefs)
	}

	byRef := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		byRef[entry.Ref] = entry
	}
	serverKey := byRef["agent/edge-paris-1/ss-key/_server"]
	if !serverKey.ServerKeyOnly || serverKey.User != "" || serverKey.Type != "shadowsocks" || serverKey.Port != 8388 {
		t.Fatalf("server-key entry = %+v", serverKey)
	}
	alice := byRef["agent/edge-paris-1/tls-in/alice"]
	if alice.User != "alice" || alice.Type != "anytls" || alice.IPv4 != "203.0.113.10" || alice.IPv6 != "" || !alice.Available {
		t.Fatalf("alice entry = %+v", alice)
	}
}

func TestDeriveUnnamedUser(t *testing.T) {
	registry := deriveTestRegistry(t)
	config := `{"inbounds":[
		{"type":"hysteria2","tag":"hy2","listen_port":443,"users":[{"name":"","password":"p"}]}
	]}`
	entries := Derive(DeriveInput{
		AgentIDs:    []string{"edge-paris-1"},
		Deployments: map[string]*deployment.Record{"edge-paris-1": deploymentRecord(t, "edge-paris-1", config)},
		Registry:    registry,
	})
	if len(entries) != 1 {
		t.Fatalf("Derive() = %v entries, want 1", entries)
	}
	if entries[0].Ref != "agent/edge-paris-1/hy2/_server" || entries[0].User != "" || entries[0].ServerKeyOnly {
		t.Fatalf("unnamed user entry = %+v", entries[0])
	}
}

func TestDeriveSkipsAndDiagnostics(t *testing.T) {
	registry := deriveTestRegistry(t)
	badShapeConfig := `{"inbounds":[
		{"type":"trojan","tag":"trojan-in","listen_port":443,"users":[{"name":"u","password":"p"}]},
		{"type":"anytls","tag":"bad tag!","listen_port":8443,"users":[{"name":"u","password":"p"}]},
		{"type":"anytls","tag":"ok-in","listen_port":8444,"users":[{"name":"bad\u0000user","password":"p"},{"name":"good","password":"p"}]},
		"not-an-object"
	]}`
	var diagnostics []string
	entries := Derive(DeriveInput{
		AgentIDs: []string{"edge-paris-1", "edge-broken", "edge-undep"},
		Deployments: map[string]*deployment.Record{
			"edge-paris-1": deploymentRecord(t, "edge-paris-1", badShapeConfig),
			// Built directly: deployment.New would reject invalid JSON, but a
			// record with unusable config bytes must still be skipped safely.
			"edge-broken": {AgentID: "edge-broken", ConfigJSON: []byte(`{"inbounds":[`)},
		},
		Registry:    registry,
		Diagnostics: &diagnostics,
	})

	gotRefs := entryRefs(entries)
	if len(gotRefs) != 1 || gotRefs[0] != "agent/edge-paris-1/ok-in/good" {
		t.Fatalf("refs = %v, want only the valid user", gotRefs)
	}
	joined := strings.Join(diagnostics, "\n")
	for _, want := range []string{"edge-broken", "bad tag!", "invalid managed-user name", "an inbound was skipped"} {
		if !strings.Contains(joined, want) {
			t.Errorf("diagnostics missing %q; got:\n%s", want, joined)
		}
	}
}

func TestDeriveUnicodeAndSpaceUserRef(t *testing.T) {
	registry := deriveTestRegistry(t)
	const unicodeUser = "上海 用户"
	config := `{"inbounds":[
		{"type":"anytls","tag":"tls-in","listen_port":8443,"users":[
			{"name":"alice","password":"pa"},
			{"name":"上海 用户","password":"p-utf8"}
		]}
	]}`
	var diagnostics []string
	entries := Derive(DeriveInput{
		AgentIDs: []string{"edge-paris-1"},
		Deployments: map[string]*deployment.Record{
			"edge-paris-1": deploymentRecord(t, "edge-paris-1", config),
		},
		Registry:    registry,
		Diagnostics: &diagnostics,
	})
	if len(diagnostics) != 0 {
		t.Fatalf("Derive() diagnostics = %v, want none", diagnostics)
	}
	if len(entries) != 2 {
		t.Fatalf("Derive() = %v entries, want 2", entries)
	}
	byUser := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		byUser[entry.User] = entry
	}
	if got := byUser["alice"].Ref; got != "agent/edge-paris-1/tls-in/alice" {
		t.Fatalf("legacy ASCII ref = %q, want unchanged", got)
	}
	wantComponent := encodedUserRefPrefix + base64.RawURLEncoding.EncodeToString([]byte(unicodeUser))
	if got := byUser[unicodeUser].Ref; got != "agent/edge-paris-1/tls-in/"+wantComponent {
		t.Fatalf("Unicode user ref = %q, want encoded component %q", got, wantComponent)
	}
}

func TestDeriveNoAddressUnavailable(t *testing.T) {
	registry, _ := openTestRegistry(t) // no addresses set
	config := `{"inbounds":[{"type":"shadowsocks","tag":"ss","listen_port":8388,"method":"m","password":"k"}]}`
	entries := Derive(DeriveInput{
		AgentIDs:    []string{"edge-paris-1"},
		Deployments: map[string]*deployment.Record{"edge-paris-1": deploymentRecord(t, "edge-paris-1", config)},
		Registry:    registry,
	})
	if len(entries) != 1 {
		t.Fatalf("Derive() = %v entries, want 1", entries)
	}
	if entries[0].Available || entries[0].IPv4 != "" || entries[0].IPv6 != "" {
		t.Fatalf("entry = %+v, want unavailable with empty addresses", entries[0])
	}
}

func TestDeriveManualEntries(t *testing.T) {
	registry, _ := openTestRegistry(t)
	if err := registry.UpsertManual("upstream-socks", json.RawMessage(`{"type":"socks","server":"10.0.0.1","server_port":1080}`)); err != nil {
		t.Fatalf("UpsertManual() error = %v", err)
	}
	if err := registry.UpsertManual("backup", json.RawMessage(`{"type":"http","server":"10.0.0.2"}`)); err != nil {
		t.Fatalf("UpsertManual() error = %v", err)
	}

	entries := Derive(DeriveInput{AgentIDs: nil, Registry: registry})
	if len(entries) != 2 {
		t.Fatalf("Derive() = %v entries, want 2", entries)
	}
	// Manual entries have an empty agent ID and sort first, ordered by ref.
	if entries[0].Ref != "manual/backup" || entries[1].Ref != "manual/upstream-socks" {
		t.Fatalf("refs = %v", entryRefs(entries))
	}
	socks := entries[1]
	if !socks.Manual || !socks.Available || socks.Type != "socks" || socks.Port != 1080 || socks.AgentID != "" {
		t.Fatalf("manual entry = %+v", socks)
	}
	if entries[0].Port != 0 {
		t.Fatalf("manual entry without server_port: Port = %d, want 0", entries[0].Port)
	}
}

func TestDeriveDeterministicSort(t *testing.T) {
	registry := deriveTestRegistry(t)
	if _, err := registry.SetReported("edge-lyon-1", []string{"203.0.113.20"}, nil); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	configA := `{"inbounds":[{"type":"anytls","tag":"b-in","listen_port":1,"users":[{"name":"z","password":"p"},{"name":"a","password":"p"}]}]}`
	configB := `{"inbounds":[{"type":"anytls","tag":"a-in","listen_port":2,"users":[{"name":"m","password":"p"}]}]}`
	entries := Derive(DeriveInput{
		AgentIDs: []string{"edge-paris-1", "edge-lyon-1"},
		Deployments: map[string]*deployment.Record{
			"edge-paris-1": deploymentRecord(t, "edge-paris-1", configA),
			"edge-lyon-1":  deploymentRecord(t, "edge-lyon-1", configB),
		},
		Registry: registry,
	})
	want := []string{
		"agent/edge-lyon-1/a-in/m",
		"agent/edge-paris-1/b-in/a",
		"agent/edge-paris-1/b-in/z",
	}
	if strings.Join(entryRefs(entries), ",") != strings.Join(want, ",") {
		t.Fatalf("refs = %v, want %v", entryRefs(entries), want)
	}
}

func TestDerivePrivateOnlySourceUnavailable(t *testing.T) {
	// An agent whose only reported addresses are non-routable has no usable
	// pool address: its derived entries are unavailable.
	registry, _ := openTestRegistry(t)
	if _, err := registry.SetReported("edge-paris-1", []string{"192.168.1.2"}, []string{"fd00::9"}); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	config := `{"inbounds":[{"type":"anytls","tag":"in","listen_port":8443,"users":[{"name":"u","password":"p"}]}]}`
	entries := Derive(DeriveInput{
		AgentIDs: []string{"edge-paris-1"},
		Deployments: map[string]*deployment.Record{
			"edge-paris-1": deploymentRecord(t, "edge-paris-1", config),
		},
		Registry: registry,
	})
	if len(entries) != 1 {
		t.Fatalf("Derive() = %v entries, want 1", entryRefs(entries))
	}
	if entries[0].Available || entries[0].IPv4 != "" || entries[0].IPv6 != "" {
		t.Fatalf("entry = %+v, want unavailable with no addresses", entries[0])
	}
}

func TestDeriveDualFamilyAddresses(t *testing.T) {
	registry, _ := openTestRegistry(t)
	// edge-paris-1 has both families; edge-lyon-1 only v6 (via observed).
	if _, err := registry.SetReported("edge-paris-1", []string{"203.0.113.10"}, []string{"2001:db8::10"}); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	if _, err := registry.SetObserved("edge-lyon-1", "2001:db8::99"); err != nil {
		t.Fatalf("SetObserved() error = %v", err)
	}
	config := `{"inbounds":[{"type":"anytls","tag":"in","listen_port":8443,"users":[{"name":"u","password":"p"}]}]}`
	entries := Derive(DeriveInput{
		AgentIDs: []string{"edge-paris-1", "edge-lyon-1"},
		Deployments: map[string]*deployment.Record{
			"edge-paris-1": deploymentRecord(t, "edge-paris-1", config),
			"edge-lyon-1":  deploymentRecord(t, "edge-lyon-1", config),
		},
		Registry: registry,
	})
	if len(entries) != 2 {
		t.Fatalf("Derive() = %v entries, want 2", entries)
	}
	byAgent := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		byAgent[entry.AgentID] = entry
	}
	paris := byAgent["edge-paris-1"]
	if paris.IPv4 != "203.0.113.10" || paris.IPv6 != "2001:db8::10" || !paris.Available {
		t.Fatalf("paris entry = %+v, want both families", paris)
	}
	lyon := byAgent["edge-lyon-1"]
	if lyon.IPv4 != "" || lyon.IPv6 != "2001:db8::99" || !lyon.Available {
		t.Fatalf("lyon entry = %+v, want v6 only, still available", lyon)
	}
}

func TestDeriveManualEntriesHaveNoAddresses(t *testing.T) {
	registry, _ := openTestRegistry(t)
	if err := registry.UpsertManual("upstream-socks", json.RawMessage(`{"type":"socks","server":"10.0.0.1","server_port":1080}`)); err != nil {
		t.Fatalf("UpsertManual() error = %v", err)
	}
	entries := Derive(DeriveInput{Registry: registry})
	if len(entries) != 1 {
		t.Fatalf("Derive() = %v entries, want 1", entries)
	}
	manual := entries[0]
	if manual.IPv4 != "" || manual.IPv6 != "" || !manual.Available {
		t.Fatalf("manual entry = %+v, want empty addresses, available", manual)
	}
}
