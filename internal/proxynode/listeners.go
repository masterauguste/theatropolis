package proxynode

import (
	"encoding/json"
	"errors"
	"fmt"
)

// listenerRef identifies one logical inbound. Several refs may intentionally
// share one physical listener when their user-selected options are compatible.
type listenerRef struct {
	agentID  string
	endpoint *Endpoint
}

type listenerSecrets struct {
	serverKey  string
	obfsSecret string
}

// listenerMultiplexPolicy contains only the inbound-wide parts of multiplex
// configuration. Whether an individual Link uses multiplex belongs to its
// parent outbound and therefore does not make an otherwise identical listener
// incompatible.
type listenerMultiplexPolicy struct {
	Padding bool             `json:"padding,omitempty"`
	Brutal  *TCPBrutalConfig `json:"brutal,omitempty"`
}

// listenerKeys deliberately excludes listener-owned generated secrets. Those
// values are reconciled across compatible refs while per-user credentials stay
// unique. Listener-wide options remain part of the compatibility key; the
// per-Link mux usage toggle is aggregated separately by the compiler.
func listenerKeys(agentID string, endpoint Endpoint) (string, string, error) {
	compatible := struct {
		Protocol   Protocol                `json:"protocol"`
		Listen     string                  `json:"listen"`
		ListenPort int                     `json:"listen_port"`
		Method     string                  `json:"method,omitempty"`
		Multiplex  listenerMultiplexPolicy `json:"multiplex"`
		TLS        TLSConfig               `json:"tls,omitempty"`
		UpMbps     int                     `json:"up_mbps,omitempty"`
		DownMbps   int                     `json:"down_mbps,omitempty"`
		ObfsType   string                  `json:"obfs_type,omitempty"`
	}{
		Protocol: endpoint.Protocol, Listen: endpoint.Listen, ListenPort: endpoint.ListenPort, Method: endpoint.Method,
		Multiplex: listenerMultiplexPolicyFor(endpoint.Multiplex), TLS: endpoint.TLS,
		UpMbps: endpoint.UpMbps, DownMbps: endpoint.DownMbps, ObfsType: endpoint.ObfsType,
	}
	encoded, err := json.Marshal(compatible)
	if err != nil {
		return "", "", err
	}
	network := "tcp"
	if endpoint.Protocol == ProtocolHysteria2 {
		network = "udp"
	} else if endpoint.Protocol == ProtocolShadowsocks {
		network = "tcp+udp"
	}
	socket := agentID + "/" + network + "/" + endpoint.Listen + ":" + fmt.Sprint(endpoint.ListenPort)
	return socket + "/" + string(encoded), socket, nil
}

func listenerMultiplexPolicyFor(config *MultiplexConfig) listenerMultiplexPolicy {
	if config == nil {
		return listenerMultiplexPolicy{}
	}
	return listenerMultiplexPolicy{Padding: config.Padding, Brutal: config.Brutal}
}

func listenerSocketClaims(agentID string, endpoint Endpoint) ([]string, error) {
	networks := []string{"tcp"}
	switch endpoint.Protocol {
	case ProtocolShadowsocks:
		networks = []string{"tcp", "udp"}
	case ProtocolHysteria2:
		networks = []string{"udp"}
	case ProtocolAnyTLS:
	default:
		return nil, errors.New("unsupported listener protocol")
	}
	claims := make([]string, 0, len(networks))
	for _, network := range networks {
		claims = append(claims, agentID+"/"+network+"/"+endpoint.Listen+":"+fmt.Sprint(endpoint.ListenPort))
	}
	return claims, nil
}

func stateListenerRefs(state *State) []listenerRef {
	refs := make([]listenerRef, 0)
	for nodeIndex := range state.ProxyNodes {
		node := &state.ProxyNodes[nodeIndex]
		agents := make(map[string]string, len(node.Hops))
		for _, hop := range node.Hops {
			agents[hop.ID] = hop.AgentID
		}
		if agentID := agents[node.Entrance.HopID]; agentID != "" {
			refs = append(refs, listenerRef{agentID: agentID, endpoint: &node.Entrance.Endpoint})
		}
		for linkIndex := range node.Links {
			link := &node.Links[linkIndex]
			if agentID := agents[link.ChildHopID]; agentID != "" {
				refs = append(refs, listenerRef{agentID: agentID, endpoint: &link.Endpoint})
			}
		}
	}
	return refs
}

func endpointListenerSecrets(endpoint Endpoint) listenerSecrets {
	return listenerSecrets{serverKey: endpoint.ServerKey, obfsSecret: endpoint.ObfsSecret}
}

func applyListenerSecrets(endpoint *Endpoint, secrets listenerSecrets) {
	switch endpoint.Protocol {
	case ProtocolShadowsocks:
		endpoint.ServerKey = secrets.serverKey
	case ProtocolHysteria2:
		if endpoint.ObfsType != "" {
			endpoint.ObfsSecret = secrets.obfsSecret
		}
	}
}

// reconcileSharedListenerSecrets preserves the material already active on a
// compatible physical listener. On first load of older state, the earliest
// stored logical inbound becomes canonical and the result is persisted when
// the master marks the store ready.
func reconcileSharedListenerSecrets(state *State, previous *State) (bool, error) {
	preferred := make(map[string]listenerSecrets)
	if previous != nil {
		for _, ref := range stateListenerRefs(previous) {
			key, _, err := listenerKeys(ref.agentID, *ref.endpoint)
			if err != nil {
				return false, err
			}
			if _, exists := preferred[key]; !exists {
				preferred[key] = endpointListenerSecrets(*ref.endpoint)
			}
		}
	}
	selected := make(map[string]listenerSecrets)
	changed := false
	for _, ref := range stateListenerRefs(state) {
		key, _, err := listenerKeys(ref.agentID, *ref.endpoint)
		if err != nil {
			return false, err
		}
		secrets, exists := selected[key]
		if !exists {
			secrets, exists = preferred[key]
			if !exists {
				secrets = endpointListenerSecrets(*ref.endpoint)
			}
			selected[key] = secrets
		}
		before := endpointListenerSecrets(*ref.endpoint)
		applyListenerSecrets(ref.endpoint, secrets)
		if endpointListenerSecrets(*ref.endpoint) != before {
			changed = true
		}
	}
	return changed, nil
}

func validateListenerLayout(state *State) error {
	sockets := make(map[string]string)
	for _, ref := range stateListenerRefs(state) {
		key, socket, err := listenerKeys(ref.agentID, *ref.endpoint)
		if err != nil {
			return err
		}
		claims, err := listenerSocketClaims(ref.agentID, *ref.endpoint)
		if err != nil {
			return err
		}
		for _, claim := range claims {
			if existing, exists := sockets[claim]; exists && existing != key {
				return fmt.Errorf("%w: Agent %q has incompatible logical inbounds on %s (%s)", ErrConflict, ref.agentID, socket, claim)
			}
			sockets[claim] = key
		}
	}
	return nil
}
