package proxynode

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

func (s *Store) AgentReverseOnly(agentID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Contains(s.state.ReverseOnlyAgents, agentID)
}

// Connectivity changes are topology mutations, serialized with deployments.
// Retire existing references first: silently converting their protocol would
// relocate sockets and change credentials without an explicit Link edit.
func (s *Store) SetAgentReverseOnly(agentID string, enabled bool) error {
	if !validAgentID(agentID) {
		return ErrInvalidState
	}
	if s.AgentReverseOnly(agentID) == enabled {
		return nil
	}
	return s.mutate(func(state *State) error {
		for _, nodes := range [][]ProxyNode{state.ProxyNodes, state.AppliedProxyNodes} {
			for _, node := range nodes {
				if slices.ContainsFunc(node.Hops, func(h Hop) bool { return h.AgentID == agentID }) {
					return fmt.Errorf("%w: retire this Server's desired and applied Hops before changing its connectivity mode", ErrConflict)
				}
			}
		}
		if slices.Contains(state.ManagedAgents, agentID) {
			return fmt.Errorf("%w: Server retirement is still pending", ErrConflict)
		}
		state.ReverseOnlyAgents = slices.DeleteFunc(state.ReverseOnlyAgents, func(id string) bool { return id == agentID })
		if enabled {
			state.ReverseOnlyAgents = append(state.ReverseOnlyAgents, agentID)
			slices.Sort(state.ReverseOnlyAgents)
		}
		return nil
	})
}

func validateAgentConnectivity(state State) error {
	seen := map[string]bool{}
	for _, id := range state.ReverseOnlyAgents {
		if !validAgentID(id) || seen[id] {
			return fmt.Errorf("%w: invalid reverse-only Agent", ErrInvalidState)
		}
		seen[id] = true
	}
	for _, node := range state.ProxyNodes {
		hops := map[string]Hop{}
		for _, hop := range node.Hops {
			hops[hop.ID] = hop
		}
		if seen[hops[node.Entrance.HopID].AgentID] {
			return fmt.Errorf("%w: reverse-only Servers cannot serve an entrance", ErrConflict)
		}
		for _, link := range node.Links {
			reverse := link.Endpoint.Protocol == ProtocolReverseWireGuard
			if reverse != seen[hops[link.ChildHopID].AgentID] {
				return fmt.Errorf("%w: incoming Links to a reverse-only Server must use Reverse WireGuard + SOCKS5", ErrConflict)
			}
			if reverse && seen[hops[link.ParentHopID].AgentID] {
				return fmt.Errorf("%w: a reverse WireGuard Link requires a publicly reachable parent; consecutive reverse-only Hops are unsupported", ErrConflict)
			}
		}
	}
	if err := validateListenerLayout(&state); err != nil {
		return err
	}
	return validateReverseSocketLayout(state)
}

func generateWireGuardKey() (string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	bytes := key.Bytes()
	bytes[0] &= 248
	bytes[31] &= 127
	bytes[31] |= 64
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func wireGuardPublicKey(encoded string) string {
	bytes, _ := base64.StdEncoding.DecodeString(encoded)
	key, err := ecdh.X25519().NewPrivateKey(bytes)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

// A separate userspace stack per Link gives both sides fixed private addresses
// without host routes. Parent stacks sharing one socket are coalesced below;
// their peers receive unique /128 addresses derived from immutable Link IDs.
const wireGuardParentIP = "fd73:7468:6561::1"

func configUsesWireGuard(config []byte) bool {
	var doc struct{ Endpoints []struct{ Type string } }
	_ = json.Unmarshal(config, &doc)
	return slices.ContainsFunc(doc.Endpoints, func(endpoint struct{ Type string }) bool { return endpoint.Type == "wireguard" })
}

func configHasReverseParent(config []byte) bool {
	var doc struct{ Endpoints []struct{ Tag string } }
	_ = json.Unmarshal(config, &doc)
	return slices.ContainsFunc(doc.Endpoints, func(endpoint struct{ Tag string }) bool { return strings.HasPrefix(endpoint.Tag, "tp-wg-parent-") })
}

func includeReverseTransportParents(state State, compiled CompileResult, changed []string) []string {
	selected := map[string]bool{}
	for _, id := range changed {
		selected[id] = true
	}
	for _, node := range state.ProxyNodes {
		hops := map[string]string{}
		for _, hop := range node.Hops {
			hops[hop.ID] = hop.AgentID
		}
		for _, link := range node.Links {
			if link.Endpoint.Protocol == ProtocolReverseWireGuard && selected[hops[link.ChildHopID]] {
				selected[hops[link.ParentHopID]] = true
			}
		}
	}
	result := []string{}
	for _, id := range deploymentOrder(compiled) {
		if selected[id] {
			result = append(result, id)
		}
	}
	return result
}

func wireGuardChildIP(id string) string {
	digest := sha256.Sum256([]byte("theatropolis-wireguard\x00" + id))
	return fmt.Sprintf("fd73:7468:6561:%x:%x:%x:%x:%x", digest[0:2], digest[2:4], digest[4:6], digest[6:8], digest[8:10])
}

func reconcileReverseLinks(state *State, previous State) error {
	previousLinks := map[string]Link{}
	previousOwners := map[string][2]string{}
	for _, node := range previous.ProxyNodes {
		hops := map[string]string{}
		for _, hop := range node.Hops {
			hops[hop.ID] = hop.AgentID
		}
		for _, link := range node.Links {
			previousLinks[link.ID] = link
			previousOwners[link.ID] = [2]string{hops[link.ParentHopID], hops[link.ChildHopID]}
		}
	}
	used := map[string]map[int]bool{}
	claim := func(agent string, port int) {
		if used[agent] == nil {
			used[agent] = map[int]bool{}
		}
		used[agent][port] = true
	}
	allocate := func(agent, kind string) (int, error) {
		for port := 20000; port <= 65535; port++ {
			if port == singbox.PeerLatencyListenPort {
				continue
			}
			if !used[agent][port] {
				claim(agent, port)
				return port, nil
			}
		}
		return 0, fmt.Errorf("%w: no private %s port available", ErrConflict, kind)
	}
	for _, nodes := range [][]ProxyNode{state.ProxyNodes, state.AppliedProxyNodes} {
		for _, node := range nodes {
			hops := map[string]string{}
			for _, hop := range node.Hops {
				hops[hop.ID] = hop.AgentID
			}
			claim(hops[node.Entrance.HopID], node.Entrance.Endpoint.ListenPort)
			for _, link := range node.Links {
				if link.Endpoint.Protocol != ProtocolReverseWireGuard {
					claim(hops[link.ChildHopID], link.Endpoint.ListenPort)
				}
				if link.WireGuard != nil {
					claim(hops[link.ChildHopID], link.WireGuard.SOCKSPort)
					claim(hops[link.ParentHopID], link.WireGuard.ProbePort)
				}
			}
		}
	}
	for ni := range state.ProxyNodes {
		node := &state.ProxyNodes[ni]
		hops := map[string]string{}
		for _, hop := range node.Hops {
			hops[hop.ID] = hop.AgentID
		}
		for li := range node.Links {
			link := &node.Links[li]
			if link.Endpoint.Protocol != ProtocolReverseWireGuard {
				link.WireGuard = nil
				continue
			}
			old, exists := previousLinks[link.ID]
			agent := hops[link.ChildHopID]
			parent := hops[link.ParentHopID]
			retained := exists && old.WireGuard != nil && old.Endpoint.Protocol == ProtocolReverseWireGuard && link.WireGuard != nil
			if !retained {
				key, err := generateWireGuardKey()
				if err != nil {
					return err
				}
				link.WireGuard = &ReverseWireGuard{PrivateKey: key}
			}
			// Moves keep the peer key but choose unused host-local sockets on the
			// new machine. Old applied sockets remain reserved until retirement.
			if !retained || previousOwners[link.ID][1] != agent {
				port, err := allocate(agent, "SOCKS")
				if err != nil {
					return err
				}
				link.WireGuard.SOCKSPort = port
			}
			if !retained || previousOwners[link.ID][0] != parent {
				port, err := allocate(parent, "readiness")
				if err != nil {
					return err
				}
				link.WireGuard.ProbePort = port
			}
		}
	}
	return nil
}

func validateReverseSocketLayout(state State) error {
	refs := stateListenerRefs(&state)
	for _, ref := range refs {
		if ref.endpoint.Protocol != ProtocolReverseWireGuard {
			continue
		}
		for _, other := range refs {
			if other.agentID != ref.agentID || other.endpoint.ListenPort != ref.endpoint.ListenPort || other.endpoint.Protocol == ProtocolReverseWireGuard || other.endpoint.Protocol == ProtocolAnyTLS {
				continue
			}
			return fmt.Errorf("%w: parent's WireGuard UDP port conflicts with an existing UDP listener", ErrConflict)
		}
	}
	seen := map[string]string{}
	addresses := map[string]bool{}
	for _, node := range state.ProxyNodes {
		hops := map[string]string{}
		for _, hop := range node.Hops {
			hops[hop.ID] = hop.AgentID
		}
		for _, link := range node.Links {
			if link.WireGuard == nil {
				continue
			} // filled before persisted-state validation
			key := hops[link.ChildHopID] + "/" + strconv.Itoa(link.WireGuard.SOCKSPort)
			if seen[key] != "" {
				return fmt.Errorf("%w: private SOCKS listener collision", ErrConflict)
			}
			seen[key] = link.ID
			probeKey := hops[link.ParentHopID] + "/" + strconv.Itoa(link.WireGuard.ProbePort)
			if seen[probeKey] != "" {
				return fmt.Errorf("%w: private readiness listener collision", ErrConflict)
			}
			seen[probeKey] = link.ID
			ip := wireGuardChildIP(link.ID)
			if addresses[ip] {
				return fmt.Errorf("%w: tunnel address collision", ErrConflict)
			}
			addresses[ip] = true
			for _, ref := range refs {
				if ref.agentID == hops[link.ParentHopID] && ref.endpoint.Protocol != ProtocolReverseWireGuard && ref.endpoint.Protocol != ProtocolHysteria2 && ref.endpoint.ListenPort == link.WireGuard.ProbePort && (ref.endpoint.Listen == "::" || ref.endpoint.Listen == "::1") {
					return fmt.Errorf("%w: private readiness port conflicts with parent listener", ErrConflict)
				}
				if ref.agentID != hops[link.ChildHopID] || ref.endpoint.Protocol == ProtocolReverseWireGuard || ref.endpoint.Protocol == ProtocolHysteria2 || ref.endpoint.ListenPort != link.WireGuard.SOCKSPort {
					continue
				}
				if ref.endpoint.Listen == "::" || ref.endpoint.Listen == "::1" {
					return fmt.Errorf("%w: private SOCKS port conflicts with child listener", ErrConflict)
				}
			}
		}
	}
	return nil
}

func reverseParentTag(agent string, endpoint Endpoint) string {
	key, _, _ := listenerKeys(agent, endpoint)
	return "tp-wg-parent-" + shortDigest(key)
}

func renderReverseLink(node ProxyNode, link Link, parent, child Hop, resolver AddressResolver, byAgent map[string]*agentRender) error {
	family, err := pool.ParseFamily(link.Endpoint.Family)
	if err != nil {
		return err
	}
	address, ok := resolver.AgentAddressForFamily(parent.AgentID, family)
	if !ok {
		return &AgentAddressUnavailableError{ProxyNodeID: node.ID, ProxyNodeName: node.Name, LinkID: link.ID, AgentID: parent.AgentID, Family: family}
	}
	parentRender, childRender := byAgent[parent.AgentID], byAgent[child.AgentID]
	tag := reverseParentTag(parent.AgentID, link.Endpoint)
	var endpoint map[string]any
	for _, existing := range parentRender.endpoints {
		if existing["tag"] == tag {
			endpoint = existing
			break
		}
	}
	if endpoint == nil {
		endpoint = map[string]any{"type": "wireguard", "tag": tag, "system": false, "mtu": 1280, "address": []string{wireGuardParentIP + "/128"}, "private_key": link.Endpoint.ServerKey, "listen_port": link.Endpoint.ListenPort, "peers": []map[string]any{}}
		parentRender.endpoints = append(parentRender.endpoints, endpoint)
	}
	childIP := wireGuardChildIP(link.ID)
	endpoint["peers"] = append(endpoint["peers"].([]map[string]any), map[string]any{"public_key": wireGuardPublicKey(link.WireGuard.PrivateKey), "allowed_ips": []string{childIP + "/128"}})
	childTag := "tp-wg-child-" + link.ID
	childRender.endpoints = append(childRender.endpoints, map[string]any{
		"type": "wireguard", "tag": childTag, "system": false, "mtu": 1280, "address": []string{childIP + "/128"}, "private_key": link.WireGuard.PrivateKey,
		"peers": []map[string]any{{"address": address, "port": link.Endpoint.ListenPort, "public_key": wireGuardPublicKey(link.Endpoint.ServerKey), "allowed_ips": []string{wireGuardParentIP + "/128"}, "persistent_keepalive_interval": 25}},
	})
	// sing-box maps traffic for the endpoint's own virtual address to loopback.
	// Permit only the private SOCKS socket, then reject every other tunnel flow.
	childRender.rules = append(childRender.rules,
		map[string]any{"inbound": []string{childTag}, "network": "tcp", "ip_cidr": []string{"::1/128"}, "port": []int{link.WireGuard.SOCKSPort}, "action": "route", "outbound": "tp-direct"},
		map[string]any{"inbound": []string{childTag}, "action": "reject"},
	)
	parentRender.rules = append(parentRender.rules, map[string]any{"inbound": []string{tag}, "action": "reject"})
	parentRender.outbounds = append(parentRender.outbounds, map[string]any{
		"type": "socks", "tag": linkOutboundTag(link.ID), "server": childIP, "server_port": link.WireGuard.SOCKSPort,
		"version": "5", "username": linkUserLabel(link.ID), "password": link.Credential.Secret, "detour": tag,
		"udp_over_tcp": map[string]any{"enabled": true, "version": 2},
	})
	probeTag := "tp-wg-probe-" + strings.TrimPrefix(linkOutboundTag(link.ID), "tp-out-")
	parentRender.extraInbounds = append(parentRender.extraInbounds, map[string]any{"type": "direct", "tag": probeTag, "listen": "::1", "listen_port": link.WireGuard.ProbePort, "network": "tcp", "override_address": childIP, "override_port": link.WireGuard.SOCKSPort})
	parentRender.rules = append(parentRender.rules, map[string]any{"inbound": []string{probeTag}, "action": "route", "outbound": tag})
	return nil
}
