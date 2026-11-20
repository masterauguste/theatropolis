package singbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const managedLinkOutboundTagPrefix = "tp-out-"

var (
	linkLatencyCGNAT       = netip.MustParsePrefix("100.64.0.0/10")
	linkLatencyReserved240 = netip.MustParsePrefix("240.0.0.0/4")
)

// LinkLatencyTarget is one generated relay outbound needed for a parent-Agent
// path probe. Hysteria2 obfuscation material stays local to the Agent and is
// never included in its latency report.
type LinkLatencyTarget struct {
	OutboundTag string
	Address     string
	Port        uint16
	Transport   string
	ServerName  string
	ObfsType    string
	ObfsSecret  string
}

// LinkLatencyTargets returns generated relay outbounds from the currently
// active configuration. TCP relays use a connect probe and Hysteria2 uses a
// QUIC handshake; arbitrary user-authored outbounds are ignored by tag.
func (m *Manager) LinkLatencyTargets() ([]LinkLatencyTarget, error) {
	config, exists, err := m.loadActiveConfig()
	if err != nil || !exists {
		return nil, err
	}
	defer clear(config)
	return ParseLinkLatencyTargets(config)
}

// ParseLinkLatencyTargets extracts the bounded local monitor view.
func ParseLinkLatencyTargets(config []byte) ([]LinkLatencyTarget, error) {
	var document struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
			TLS        struct {
				ServerName string `json:"server_name"`
			} `json:"tls"`
			Obfs struct {
				Type     string `json:"type"`
				Password string `json:"password"`
			} `json:"obfs"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(config, &document); err != nil {
		return nil, fmt.Errorf("parse active sing-box configuration for Link monitoring: %w", err)
	}
	if len(document.Outbounds) > 4096 {
		return nil, errors.New("active sing-box configuration has too many outbounds")
	}
	targets := make([]LinkLatencyTarget, 0)
	seen := make(map[string]struct{})
	for _, outbound := range document.Outbounds {
		if outbound.Type != "anytls" && outbound.Type != "shadowsocks" && outbound.Type != "hysteria2" {
			continue
		}
		tag := strings.TrimSpace(outbound.Tag)
		address := strings.TrimSpace(outbound.Server)
		if !strings.HasPrefix(tag, managedLinkOutboundTagPrefix) || len(tag) > 128 ||
			address == "" || len(address) > 253 || outbound.ServerPort < 1 || outbound.ServerPort > 65535 {
			continue
		}
		parsedAddress, err := netip.ParseAddr(address)
		if err != nil || !parsedAddress.IsGlobalUnicast() || parsedAddress.IsPrivate() ||
			linkLatencyCGNAT.Contains(parsedAddress) || linkLatencyReserved240.Contains(parsedAddress) {
			continue
		}
		if _, duplicate := seen[tag]; duplicate {
			continue
		}
		seen[tag] = struct{}{}
		transport := "tcp"
		if outbound.Type == "hysteria2" {
			transport = "quic"
		}
		targets = append(targets, LinkLatencyTarget{
			OutboundTag: tag,
			Address:     address,
			Port:        uint16(outbound.ServerPort),
			Transport:   transport,
			ServerName:  strings.TrimSpace(outbound.TLS.ServerName),
			ObfsType:    strings.TrimSpace(outbound.Obfs.Type),
			ObfsSecret:  outbound.Obfs.Password,
		})
	}
	return targets, nil
}
