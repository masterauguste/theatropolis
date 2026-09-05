package singbox

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestConfigureACMEHTTP01Relay(t *testing.T) {
	t.Parallel()

	logical := []byte(`{
		"inbounds":[{"type":"anytls","listen_port":443}],
		"certificate_providers":[
			{"type":"acme","tag":"managed","domain":["proxy.example.com"]},
			{"type":"local","tag":"static"}
		]
	}`)
	configured, err := ConfigureACMEHTTP01Relay(logical)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Providers []map[string]any `json:"certificate_providers"`
	}
	if err := json.Unmarshal(configured, &document); err != nil {
		t.Fatal(err)
	}
	if got := document.Providers[0]["alternative_http_port"]; got != float64(ACMEHTTP01RelayPort) {
		t.Fatalf("alternative_http_port = %#v, want %d", got, ACMEHTTP01RelayPort)
	}
	if _, exists := document.Providers[1]["alternative_http_port"]; exists {
		t.Fatal("non-ACME provider received alternative_http_port")
	}
}

func TestConfigureACMEHTTP01RelayLeavesConfigurationWithoutACMEUntouched(t *testing.T) {
	t.Parallel()

	config := []byte(`{"inbounds":[{"type":"anytls","listen_port":19091}]}`)
	configured, err := ConfigureACMEHTTP01Relay(config)
	if err != nil {
		t.Fatal(err)
	}
	if string(configured) != string(config) {
		t.Fatalf("configuration changed without ACME: %s", configured)
	}
}

func TestConfigureACMEHTTP01RelayRejectsInboundCollision(t *testing.T) {
	t.Parallel()

	config := []byte(`{
		"inbounds":[{"type":"anytls","listen_port":19091.0}],
		"certificate_providers":[{"type":"acme","tag":"managed"}]
	}`)
	_, err := ConfigureACMEHTTP01Relay(config)
	if !errors.Is(err, ErrACMEHTTP01RelayPortConflict) {
		t.Fatalf("error = %v, want %v", err, ErrACMEHTTP01RelayPortConflict)
	}
}

func TestConfigureACMEHTTP01RelayAllowsUDPOnlyInboundOnSamePort(t *testing.T) {
	t.Parallel()

	config := []byte(`{
		"inbounds":[{"type":"hysteria2","listen_port":19091}],
		"certificate_providers":[{"type":"acme","tag":"managed"}]
	}`)
	configured, err := ConfigureACMEHTTP01Relay(config)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(configured) {
		t.Fatalf("configured document is invalid: %s", configured)
	}
}
