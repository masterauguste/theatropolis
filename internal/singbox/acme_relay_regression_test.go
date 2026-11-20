package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestAuditRelayPreservesUserAuthority(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(managedUserTestConfig(`[{"name":"cinema-alice-m-AAAAAAAAAAAA","password":"alice"}]`), &document); err != nil {
		t.Fatal(err)
	}
	inbound := document["inbounds"].([]any)[0].(map[string]any)
	inbound["type"] = "anytls"
	inbound["tls"] = map[string]any{"enabled": true, "certificate_provider": "acme"}
	delete(inbound, "method")
	document["certificate_providers"] = []any{map[string]any{"type": "acme", "tag": "acme", "domain": []string{"proxy.test"}}}
	logical, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := BuildManagedUserAuthorityVariant(logical)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := ConfigureACMEHTTP01Relay(logical)
	if err != nil {
		t.Fatal(err)
	}
	overlaid, matched, err := applyManagedUserAuthority(rendered, []ManagedUserAuthorityVariant{authority})
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("co-located ACME rendering invalidates the master's user-authority fingerprint")
	}
	if err := json.Unmarshal(overlaid, &document); err != nil {
		t.Fatal(err)
	}
	if document["certificate_providers"].([]any)[0].(map[string]any)["alternative_http_port"] != float64(ACMEHTTP01RelayPort) {
		t.Fatal("authority overlay removed the runtime relay setting")
	}
	for _, replacement := range [][]byte{
		bytes.ReplaceAll(rendered, []byte(`19091`), []byte(`19092`)),
		bytes.ReplaceAll(rendered, []byte(`proxy.test`), []byte(`different.test`)),
	} {
		_, matched, err := applyManagedUserAuthority(replacement, []ManagedUserAuthorityVariant{authority})
		if err != nil || matched {
			t.Fatalf("unrelated provider changes must not match authority: matched=%v err=%v", matched, err)
		}
	}
}

func TestManagerReconcilesPersistedACMEHostRole(t *testing.T) {
	for _, relay := range []bool{false, true} {
		t.Run(map[bool]string{false: "Master removed", true: "Master added"}[relay], func(t *testing.T) {
			manager := newTestManager(t, &fakeProcessFactory{}, nil)
			manager.acmeHTTP01Relay = &relay
			config := []byte(`{"inbounds":[],"certificate_providers":[{"type":"acme","tag":"acme","domain":["proxy.test"]}]}`)
			if !relay {
				var err error
				config, err = ConfigureACMEHTTP01Relay(config)
				if err != nil {
					t.Fatal(err)
				}
			}
			writeActiveConfig(t, manager, config)
			if _, err := manager.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer stopTestManager(t, manager)
			active, exists, err := manager.loadActiveConfig()
			if err != nil || !exists {
				t.Fatalf("load active: exists=%v err=%v", exists, err)
			}
			if bytes.Contains(active, []byte(`"alternative_http_port":19091`)) != relay {
				t.Fatalf("persisted ACME configuration did not follow host role: %s", active)
			}
		})
	}
}

func TestRemoveACMEHTTP01RelayPreservesOtherProviderSettings(t *testing.T) {
	config := []byte(`{"certificate_providers":[{"type":"acme","alternative_http_port":19091,"domain":["proxy.test"]},{"type":"acme","alternative_http_port":8888},{"type":"other","alternative_http_port":19091}]}`)
	got, err := RemoveACMEHTTP01Relay(config)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Providers []map[string]any `json:"certificate_providers"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if _, exists := doc.Providers[0]["alternative_http_port"]; exists {
		t.Fatal("relay port retained")
	}
	if doc.Providers[1]["alternative_http_port"] != float64(8888) || doc.Providers[2]["alternative_http_port"] != float64(19091) {
		t.Fatal("unrelated provider settings changed")
	}
	unchanged, err := RemoveACMEHTTP01Relay(got)
	if err != nil || !bytes.Equal(got, unchanged) {
		t.Fatalf("removal is not idempotent: %v", err)
	}
}

func TestManagerACMEHostConflictKeepsControlAvailable(t *testing.T) {
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	relay := true
	manager.acmeHTTP01Relay = &relay
	writeActiveConfig(t, manager, []byte(`{"inbounds":[{"type":"anytls","listen_port":19091}],"certificate_providers":[{"type":"acme","tag":"acme","domain":["proxy.test"]}]}`))
	startup, err := manager.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stopTestManager(t, manager)
	if startup.Status != StartupValidationFailed {
		t.Fatalf("startup=%+v", startup)
	}
	processes, _ := factory.snapshot()
	if len(processes) != 0 {
		t.Fatal("conflicting profile started")
	}
}
