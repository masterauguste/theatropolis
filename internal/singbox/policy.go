package singbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

const HTTP01ListenPort = 80

var ErrReservedListenPort = errors.New(
	"an inbound uses port 80, which is reserved for ACME HTTP-01",
)

// ValidateManagedConfig enforces Theatropolis-owned safety constraints which
// apply in addition to sing-box's own schema validation.
func ValidateManagedConfig(config []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(config))
	decoder.UseNumber()
	var document struct {
		Inbounds []json.RawMessage `json:"inbounds"`
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
	}
	return nil
}

func ReservedListenPortMessage() string {
	return fmt.Sprintf(
		"Port %d is reserved for ACME HTTP-01 certificate issuance.",
		HTTP01ListenPort,
	)
}
