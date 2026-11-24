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
// TCP path probe on PeerLatencyListenPort.
type LinkLatencyTarget struct {
	OutboundTag string
	Address     string
	Port        uint16
	Transport   string
}

// LinkLatencyTargets returns generated relay outbounds from the currently
// active configuration. Every relay outbound is probed via TCP on
// PeerLatencyListenPort (20045); arbitrary user-authored outbounds are ignored
// by tag.
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
		targets = append(targets, LinkLatencyTarget{
			OutboundTag: tag,
			Address:     address,
			Port:        PeerLatencyListenPort,
			Transport:   "tcp",
		})
	}
	return targets, nil
}
