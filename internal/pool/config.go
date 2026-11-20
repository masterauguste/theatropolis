package pool

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	// MaxConfigBytes caps logical, deployed, and rendered configurations.
	MaxConfigBytes = 4 << 20

	maxJSONDepth = 128
)

var (
	errConfigTooLarge  = errors.New("pool: configuration exceeds the 4 MiB size limit")
	errConfigNotJSON   = errors.New("pool: configuration is not valid JSON")
	errConfigNotObject = errors.New("pool: configuration must be a JSON object")
	errConfigTooDeep   = errors.New("pool: configuration is nested too deeply")
)

// checkConfigStructure validates that data holds one complete JSON object
// within the depth cap. It mirrors the depth-capped token walk of the web
// UI's validateConfigurationJSON.
func checkConfigStructure(data []byte) error {
	if len(data) == 0 {
		return errConfigNotJSON
	}
	if len(data) > MaxConfigBytes {
		return errConfigTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return errConfigNotJSON
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errConfigNotObject
	}
	if err := consumeObject(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errConfigNotJSON
	}
	return nil
}

func consumeObject(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errConfigTooDeep
	}
	for decoder.More() {
		if _, err := decoder.Token(); err != nil {
			return errConfigNotJSON
		}
		if err := consumeValue(decoder, depth); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return errConfigNotJSON
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return errConfigNotJSON
	}
	return nil
}

func consumeValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return errConfigNotJSON
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		return consumeObject(decoder, depth+1)
	case '[':
		if depth >= maxJSONDepth {
			return errConfigTooDeep
		}
		for decoder.More() {
			if err := consumeValue(decoder, depth+1); err != nil {
				return err
			}
		}
		token, err := decoder.Token()
		if err != nil {
			return errConfigNotJSON
		}
		if closing, ok := token.(json.Delim); !ok || closing != ']' {
			return errConfigNotJSON
		}
		return nil
	default:
		return errConfigNotJSON
	}
}

// deployedConfig is the pool-relevant view of an agent's deployed sing-box
// configuration. Inbounds and certificate providers stay raw so one malformed
// element does not sink the whole document.
type deployedConfig struct {
	Inbounds             []json.RawMessage `json:"inbounds"`
	CertificateProviders []json.RawMessage `json:"certificate_providers"`
}

func parseDeployedConfig(data []byte) (*deployedConfig, error) {
	if err := checkConfigStructure(data); err != nil {
		return nil, err
	}
	var config deployedConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, errConfigNotJSON
	}
	return &config, nil
}

// inboundConfig is the pool-relevant view of one deployed inbound.
type inboundConfig struct {
	Type       string        `json:"type"`
	Tag        string        `json:"tag"`
	ListenPort int           `json:"listen_port"`
	Method     string        `json:"method"`
	Password   string        `json:"password"`
	Users      []inboundUser `json:"users"`
	UpMbps     int           `json:"up_mbps"`
	DownMbps   int           `json:"down_mbps"`
	Obfs       *inboundObfs  `json:"obfs"`
	TLS        *inboundTLS   `json:"tls"`
}

type inboundUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type inboundObfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type inboundTLS struct {
	Enabled             bool   `json:"enabled"`
	CertificateProvider string `json:"certificate_provider"`
}

type certificateProvider struct {
	Tag    string   `json:"tag"`
	Type   string   `json:"type"`
	Domain []string `json:"domain"`
}

// acmeDomain resolves the ACME domain for an inbound's certificate provider,
// or "" when the provider is missing, not ACME, or has no domain.
func (c *deployedConfig) acmeDomain(inbound inboundConfig) string {
	if inbound.TLS == nil || inbound.TLS.CertificateProvider == "" {
		return ""
	}
	for _, raw := range c.CertificateProviders {
		var provider certificateProvider
		if err := json.Unmarshal(raw, &provider); err != nil {
			continue
		}
		if provider.Tag == inbound.TLS.CertificateProvider &&
			provider.Type == "acme" &&
			len(provider.Domain) > 0 &&
			provider.Domain[0] != "" {
			return provider.Domain[0]
		}
	}
	return ""
}

func parseInbound(raw json.RawMessage) (inboundConfig, error) {
	var inbound inboundConfig
	if err := json.Unmarshal(raw, &inbound); err != nil {
		return inboundConfig{}, err
	}
	return inbound, nil
}

func supportedInboundType(inboundType string) bool {
	switch inboundType {
	case "shadowsocks", "anytls", "hysteria2":
		return true
	default:
		return false
	}
}

// stringField extracts a string value from a raw JSON object.
func stringField(object map[string]json.RawMessage, key string) (string, bool) {
	raw, exists := object[key]
	if !exists {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}
