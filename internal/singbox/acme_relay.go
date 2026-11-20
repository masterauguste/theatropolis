package singbox

import (
	"encoding/json"
	"errors"
	"fmt"
)

const ACMEHTTP01RelayPort = 19091

var ErrACMEHTTP01RelayPortConflict = errors.New("ACME HTTP-01 relay port conflicts with an inbound")

// RemoveACMEHTTP01Relay restores the public HTTP-01 listener when the local
// Master has been removed. Only the installer's reserved port is removed;
// unrelated custom provider settings are preserved.
func RemoveACMEHTTP01Relay(config []byte) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(config, &document); err != nil {
		return nil, err
	}
	raw, exists := document["certificate_providers"]
	if !exists {
		return config, nil
	}
	var providers []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &providers); err != nil {
		return nil, err
	}
	changed := false
	for _, provider := range providers {
		var kind string
		var port float64
		if json.Unmarshal(provider["type"], &kind) == nil && kind == "acme" &&
			json.Unmarshal(provider["alternative_http_port"], &port) == nil && port == ACMEHTTP01RelayPort {
			delete(provider, "alternative_http_port")
			changed = true
		}
	}
	if !changed {
		return config, nil
	}
	encoded, err := json.Marshal(providers)
	if err != nil {
		return nil, err
	}
	document["certificate_providers"] = encoded
	return json.Marshal(document)
}

// ConfigureACMEHTTP01Relay rewrites a rendered, agent-bound configuration so
// ACME HTTP-01 solvers listen behind the co-located Master's Caddy instance.
// Logical configurations remain portable and never persist this host detail.
func ConfigureACMEHTTP01Relay(config []byte) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(config, &document); err != nil {
		return nil, fmt.Errorf("decode configuration for ACME HTTP-01 relay: %w", err)
	}

	var providers []map[string]json.RawMessage
	if raw := document["certificate_providers"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &providers); err != nil {
			return nil, fmt.Errorf("decode certificate providers for ACME HTTP-01 relay: %w", err)
		}
	}
	hasACME := false
	for _, provider := range providers {
		var providerType string
		if err := json.Unmarshal(provider["type"], &providerType); err == nil && providerType == "acme" {
			hasACME = true
			break
		}
	}
	if !hasACME {
		return config, nil
	}

	var inbounds []struct {
		Type       string      `json:"type"`
		ListenPort json.Number `json:"listen_port"`
	}
	if raw := document["inbounds"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &inbounds); err != nil {
			return nil, fmt.Errorf("decode inbounds for ACME HTTP-01 relay: %w", err)
		}
	}
	for _, inbound := range inbounds {
		port, err := inbound.ListenPort.Int64()
		conflicts := err == nil && port == ACMEHTTP01RelayPort
		if err != nil {
			decimalPort, decimalErr := inbound.ListenPort.Float64()
			conflicts = decimalErr == nil && decimalPort == ACMEHTTP01RelayPort
		}
		// Hysteria2 and TUIC claim UDP only, so they can share the numeric
		// port with the relay's loopback TCP listener.
		if conflicts && inbound.Type != "hysteria2" && inbound.Type != "tuic" {
			return nil, fmt.Errorf(
				"%w: port %d is reserved on a co-located Master and Agent",
				ErrACMEHTTP01RelayPortConflict,
				ACMEHTTP01RelayPort,
			)
		}
	}

	port := json.RawMessage(fmt.Appendf(nil, "%d", ACMEHTTP01RelayPort))
	for _, provider := range providers {
		var providerType string
		if err := json.Unmarshal(provider["type"], &providerType); err == nil && providerType == "acme" {
			provider["alternative_http_port"] = port
		}
	}
	encodedProviders, err := json.Marshal(providers)
	if err != nil {
		return nil, fmt.Errorf("encode certificate providers for ACME HTTP-01 relay: %w", err)
	}
	document["certificate_providers"] = encodedProviders
	configured, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode configuration for ACME HTTP-01 relay: %w", err)
	}
	return configured, nil
}
