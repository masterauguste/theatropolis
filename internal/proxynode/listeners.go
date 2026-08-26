package proxynode

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

type ListenerPreset struct {
	ID             string
	AgentID        string
	Endpoint       Endpoint
	ReferenceCount int
}

// ListenerPresets returns secret-free physical-listener choices for guided UI
// reuse. Logical refs with the same compatibility key collapse into one item.
func ListenerPresets(state State) []ListenerPreset {
	state = cloneState(state)
	byKey := make(map[string]*ListenerPreset)
	for _, ref := range stateListenerRefs(&state) {
		key, _, err := listenerKeys(ref.agentID, *ref.endpoint)
		if err != nil {
			continue
		}
		preset := byKey[key]
		if preset == nil {
			endpoint := *ref.endpoint
			endpoint.TLS = normalizeTLSConfig(endpoint.TLS)
			endpoint.ServerKey = ""
			endpoint.ObfsSecret = ""
			preset = &ListenerPreset{
				ID: "listener-" + shortDigest(key), AgentID: ref.agentID, Endpoint: endpoint,
			}
			byKey[key] = preset
		}
		preset.ReferenceCount++
	}
	result := make([]ListenerPreset, 0, len(byKey))
	for _, preset := range byKey {
		result = append(result, *preset)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].AgentID != result[right].AgentID {
			return result[left].AgentID < result[right].AgentID
		}
		if result[left].Endpoint.ListenPort != result[right].Endpoint.ListenPort {
			return result[left].Endpoint.ListenPort < result[right].Endpoint.ListenPort
		}
		return result[left].ID < result[right].ID
	})
	return result
}

func ListenerPresetID(agentID string, endpoint Endpoint) string {
	key, _, err := listenerKeys(agentID, endpoint)
	if err != nil {
		return ""
	}
	return "listener-" + shortDigest(key)
}

// listenerRef identifies one logical inbound. Several refs may intentionally
// share one physical listener when their user-selected options are compatible.
type listenerRef struct {
	agentID  string
	endpoint *Endpoint
	node     *ProxyNode
	link     *Link
	entrance bool
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
	endpoint.TLS = normalizeTLSConfig(endpoint.TLS)
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
			refs = append(refs, listenerRef{
				agentID: agentID, endpoint: &node.Entrance.Endpoint, node: node, entrance: true,
			})
		}
		for linkIndex := range node.Links {
			link := &node.Links[linkIndex]
			if agentID := agents[link.ChildHopID]; agentID != "" {
				refs = append(refs, listenerRef{agentID: agentID, endpoint: &link.Endpoint, node: node, link: link})
			}
		}
	}
	return refs
}

// applySharedListenerEdit updates one physical listener as an indivisible
// operation across every logical reference. Family and the basic outbound mux
// choice are per Link; every other endpoint field describes the child-side
// listener and therefore propagates to the whole compatible group.
func applySharedListenerEdit(state *State, target *Endpoint, replacement Endpoint, now time.Time) error {
	refs := stateListenerRefs(state)
	var targetRef *listenerRef
	for index := range refs {
		if refs[index].endpoint == target {
			targetRef = &refs[index]
			break
		}
	}
	if targetRef == nil {
		return ErrNotFound
	}
	oldKey, _, err := listenerKeys(targetRef.agentID, *targetRef.endpoint)
	if err != nil {
		return err
	}
	preserveEndpointSecrets(*targetRef.endpoint, &replacement)
	if err := generateEndpointSecrets(&replacement); err != nil {
		return err
	}
	for index := range refs {
		ref := &refs[index]
		key, _, keyErr := listenerKeys(ref.agentID, *ref.endpoint)
		if keyErr != nil {
			return keyErr
		}
		if key != oldKey {
			continue
		}
		old := *ref.endpoint
		next := replacement
		if ref.endpoint != target {
			next.Family = old.Family
			next.Multiplex = mergeListenerMultiplex(replacement.Multiplex, old.Multiplex)
		}
		if ref.link != nil && credentialShapeChanged(old, next) {
			credential, credentialErr := generateCredential(next)
			if credentialErr != nil {
				return credentialErr
			}
			ref.link.Credential = credential
			ref.link.UpdatedAt = now
		}
		if ref.entrance {
			activeEndpoint, applied := appliedEntranceEndpoint(*state, ref.node.ID)
			for membershipIndex := range ref.node.Memberships {
				membership := &ref.node.Memberships[membershipIndex]
				if !applied {
					if credentialShapeChanged(old, next) {
						credential, credentialErr := generateCredential(next)
						if credentialErr != nil {
							return credentialErr
						}
						membership.Credential = credential
					}
					membership.PendingCredential = nil
					continue
				}
				if credentialShapeChanged(activeEndpoint, next) {
					credential, credentialErr := generateCredential(next)
					if credentialErr != nil {
						return credentialErr
					}
					membership.PendingCredential = &credential
				} else {
					membership.PendingCredential = nil
				}
			}
		}
		*ref.endpoint = next
	}
	return validateListenerLayout(state)
}

func mergeListenerMultiplex(listenerWide, perLink *MultiplexConfig) *MultiplexConfig {
	enabled := perLink != nil && perLink.Enabled
	padding := listenerWide != nil && listenerWide.Padding
	var brutal *TCPBrutalConfig
	if listenerWide != nil && listenerWide.Brutal != nil {
		copy := *listenerWide.Brutal
		brutal = &copy
	}
	if !enabled && !padding && brutal == nil {
		return nil
	}
	return &MultiplexConfig{Enabled: enabled, Padding: padding, Brutal: brutal}
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
