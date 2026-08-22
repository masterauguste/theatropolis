package proxynode

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

func randomID(prefix string) (string, error) {
	buffer := make([]byte, 18)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate %s ID: %w", prefix, err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func generateEndpointSecrets(endpoint *Endpoint) error {
	if endpoint == nil {
		return errors.New("proxy node endpoint is required")
	}
	if endpoint.Protocol == ProtocolShadowsocks {
		length, err := shadowsocksKeyLength(endpoint.Method)
		if err != nil {
			return err
		}
		secret, err := randomBase64(length)
		if err != nil {
			return err
		}
		endpoint.ServerKey = secret
	}
	if endpoint.Protocol == ProtocolHysteria2 && endpoint.ObfsType != "" && endpoint.ObfsSecret == "" {
		secret, err := randomURLSecret(32)
		if err != nil {
			return err
		}
		endpoint.ObfsSecret = secret
	}
	return nil
}

func generateCredential(endpoint Endpoint) (Credential, error) {
	if endpoint.Protocol == ProtocolShadowsocks {
		length, err := shadowsocksKeyLength(endpoint.Method)
		if err != nil {
			return Credential{}, err
		}
		secret, err := randomBase64(length)
		return Credential{Secret: secret}, err
	}
	secret, err := randomURLSecret(32)
	return Credential{Secret: secret}, err
}

func randomBase64(length int) (string, error) {
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate proxy credential: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buffer), nil
}

func randomURLSecret(length int) (string, error) {
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate proxy credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func shadowsocksKeyLength(method string) (int, error) {
	switch method {
	case "2022-blake3-aes-128-gcm":
		return 16, nil
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32, nil
	default:
		return 0, errors.New("unsupported Shadowsocks 2022 method")
	}
}
