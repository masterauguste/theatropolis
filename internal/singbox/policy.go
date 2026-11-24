package singbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

const (
	HTTP01ListenPort      = 80
	PeerLatencyListenPort = 20045
)

const disabledManagedConfig = "{\n  \"inbounds\": [],\n  \"outbounds\": [{\"type\": \"direct\", \"tag\": \"tp-direct\"}, {\"type\": \"block\", \"tag\": \"tp-reject\"}],\n  \"route\": {\"rules\": [], \"final\": \"tp-reject\"}\n}\n"

var ErrReservedListenPort = errors.New(
	"an inbound uses port 80, which is reserved for ACME HTTP-01",
)

var ErrManagedUserAPIListenPort = errors.New(
	"an inbound uses the port reserved for the loopback managed-user API",
)

var ErrPeerLatencyListenPort = errors.New(
	"an inbound uses port 20045, which is reserved for inter-server TCP latency probes",
)

var ErrUnsafeManagedUserAPI = errors.New(
	"the managed-user API must use its reserved loopback endpoint",
)

// DisabledManagedConfig is the authoritative no-service profile used when a
// master has no desired configuration for an Agent. It has no listeners and
// rejects any traffic that could otherwise reach its route table.
func DisabledManagedConfig() []byte {
	return []byte(disabledManagedConfig)
}

// ValidateManagedConfig enforces Theatropolis-owned safety constraints which
// apply in addition to sing-box's own schema validation.
func ValidateManagedConfig(config []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(config))
	decoder.UseNumber()
	var document struct {
		Inbounds  []json.RawMessage `json:"inbounds"`
		Endpoints []json.RawMessage `json:"endpoints"`
		Services  []json.RawMessage `json:"services"`
	}
	if err := decoder.Decode(&document); err != nil {
		return errors.New("configuration is not valid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("configuration contains trailing JSON data")
	}
	for _, inboundJSON := range document.Inbounds {
		var inbound map[string]json.RawMessage
		if err := json.Unmarshal(inboundJSON, &inbound); err != nil {
			return errors.New("configuration contains an invalid inbound")
		}
		rawPort, exists := inbound["listen_port"]
		if !exists {
			continue
		}
		var port json.Number
		portDecoder := json.NewDecoder(bytes.NewReader(rawPort))
		portDecoder.UseNumber()
		if err := portDecoder.Decode(&port); err != nil {
			// sing-box check will provide the authoritative type diagnostic.
			continue
		}
		numericPort, err := strconv.ParseFloat(port.String(), 64)
		if err == nil && numericPort == HTTP01ListenPort {
			return ErrReservedListenPort
		}
		if err == nil && numericPort == ManagedUserAPIListenPort {
			return ErrManagedUserAPIListenPort
		}
		if err == nil && numericPort == PeerLatencyListenPort {
			return ErrPeerLatencyListenPort
		}
	}
	for _, serviceJSON := range document.Services {
		var service map[string]json.RawMessage
		if err := json.Unmarshal(serviceJSON, &service); err != nil {
			return errors.New("configuration contains an invalid service")
		}
		var serviceType string
		if err := json.Unmarshal(service["type"], &serviceType); err != nil || serviceType != "ssm-api" {
			continue
		}
		var tag, listen string
		var port json.Number
		portDecoder := json.NewDecoder(bytes.NewReader(service["listen_port"]))
		portDecoder.UseNumber()
		if json.Unmarshal(service["tag"], &tag) != nil ||
			json.Unmarshal(service["listen"], &listen) != nil ||
			portDecoder.Decode(&port) != nil ||
			tag != ManagedUserAPIServiceTag || listen != "127.0.0.1" ||
			port.String() != strconv.Itoa(ManagedUserAPIListenPort) {
			return ErrUnsafeManagedUserAPI
		}
	}
	for _, raw := range document.Endpoints {
		var endpoint struct {
			Type   string
			System bool
			Port   int `json:"listen_port"`
		}
		if json.Unmarshal(raw, &endpoint) != nil {
			return errors.New("configuration contains an invalid endpoint")
		}
		if endpoint.Type != "wireguard" {
			continue
		}
		if endpoint.System || endpoint.Port < 0 || endpoint.Port > 65535 || (endpoint.Port > 0 && endpoint.Port < 1024) || endpoint.Port == ManagedUserAPIListenPort || endpoint.Port == ACMEHTTP01RelayPort || endpoint.Port == PeerLatencyListenPort {
			return errors.New("managed WireGuard must be userspace and use an unprivileged, non-reserved UDP port")
		}
	}
	return nil
}

func ReservedListenPortMessage() string {
	return fmt.Sprintf(
		"Port %d is reserved for ACME HTTP-01 certificate issuance.",
		HTTP01ListenPort,
	)
}
