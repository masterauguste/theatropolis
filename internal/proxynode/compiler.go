package proxynode

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/masterauguste/theatropolis/internal/pool"
)

type AddressResolver interface {
	AgentAddressForFamily(agentID string, family pool.Family) (string, bool)
	DefaultTLSAddress(agentID string) string
}

type CompileResult struct {
	Configs    map[string][]byte
	AgentDepth map[string]int
}

type renderUser struct {
	Name   string
	Secret string
}

type ingressCandidate struct {
	node       *ProxyNode
	hop        *Hop
	endpoint   Endpoint
	users      []renderUser
	link       *Link
	inboundTag string
}

type listenerGroup struct {
	agentID    string
	key        string
	socket     string
	endpoint   Endpoint
	tag        string
	candidates []*ingressCandidate
}

type agentRender struct {
	agentID              string
	groups               []*listenerGroup
	outbounds            []map[string]any
	rules                []map[string]any
	ruleSets             map[string]map[string]any
	certificateProviders []map[string]any
	needsSniff           bool
}

func Compile(state State, resolver AddressResolver) (CompileResult, error) {
	if resolver == nil {
		return CompileResult{}, errors.New("Proxy Node compiler requires an address resolver")
	}
	if err := validateState(state); err != nil {
		return CompileResult{}, err
	}
	users := make(map[string]User, len(state.Users))
	for _, user := range state.Users {
		users[user.ID] = user
	}
	byAgent := make(map[string]*agentRender)
	depths := make(map[string]int)
	allCandidates := make([]*ingressCandidate, 0)

	for nodeIndex := range state.ProxyNodes {
		node := &state.ProxyNodes[nodeIndex]
		hops := make(map[string]*Hop, len(node.Hops))
		for hopIndex := range node.Hops {
			hop := &node.Hops[hopIndex]
			hops[hop.ID] = hop
			ensureAgentRender(byAgent, hop.AgentID)
		}
		depthByHop := topologyDepths(*node)
		for hopID, depth := range depthByHop {
			hop := hops[hopID]
			if depth > depths[hop.AgentID] {
				depths[hop.AgentID] = depth
			}
		}

		root := hops[node.Entrance.HopID]
		rootUsers := make([]renderUser, 0, len(node.Memberships))
		for _, membership := range node.Memberships {
			user := users[membership.UserID]
			label := endUserLabel(node.Name, user.Name)
			rootUsers = append(rootUsers, renderUser{Name: label, Secret: membership.Credential.Secret})
		}
		if len(rootUsers) > 0 {
			allCandidates = append(allCandidates, &ingressCandidate{
				node: node, hop: root, endpoint: node.Entrance.Endpoint,
				users: rootUsers,
			})
		}
		for linkIndex := range node.Links {
			link := &node.Links[linkIndex]
			child := hops[link.ChildHopID]
			label := linkUserLabel(node.Name, link.ID)
			allCandidates = append(allCandidates, &ingressCandidate{
				node: node, hop: child, endpoint: link.Endpoint, link: link,
				users: []renderUser{{Name: label, Secret: link.Credential.Secret}},
			})
		}
	}

	if err := groupListeners(byAgent, allCandidates); err != nil {
		return CompileResult{}, err
	}
	for _, candidate := range allCandidates {
		render := byAgent[candidate.hop.AgentID]
		if err := renderHopRules(render, candidate); err != nil {
			return CompileResult{}, err
		}
	}
	for nodeIndex := range state.ProxyNodes {
		node := &state.ProxyNodes[nodeIndex]
		hops := make(map[string]Hop, len(node.Hops))
		for _, hop := range node.Hops {
			hops[hop.ID] = hop
		}
		for _, link := range node.Links {
			parent := hops[link.ParentHopID]
			child := hops[link.ChildHopID]
			outbound, err := renderLinkOutbound(*node, link, child, resolver)
			if err != nil {
				return CompileResult{}, err
			}
			byAgent[parent.AgentID].outbounds = append(byAgent[parent.AgentID].outbounds, outbound)
		}
	}

	result := CompileResult{Configs: make(map[string][]byte, len(byAgent)), AgentDepth: depths}
	agents := make([]string, 0, len(byAgent))
	for agentID := range byAgent {
		agents = append(agents, agentID)
	}
	sort.Strings(agents)
	for _, agentID := range agents {
		config, err := renderAgentConfig(byAgent[agentID])
		if err != nil {
			return CompileResult{}, fmt.Errorf("render Agent %q: %w", agentID, err)
		}
		result.Configs[agentID] = config
	}
	return result, nil
}

func ensureAgentRender(rendered map[string]*agentRender, agentID string) *agentRender {
	if rendered[agentID] == nil {
		rendered[agentID] = &agentRender{
			agentID: agentID,
			outbounds: []map[string]any{
				{"type": "direct", "tag": "tp-direct"},
				{"type": "block", "tag": "tp-reject"},
			},
			ruleSets: make(map[string]map[string]any),
		}
	}
	return rendered[agentID]
}

func groupListeners(byAgent map[string]*agentRender, candidates []*ingressCandidate) error {
	groups := make(map[string]*listenerGroup)
	sockets := make(map[string]string)
	for _, candidate := range candidates {
		key, socket, err := listenerKeys(candidate.hop.AgentID, candidate.endpoint)
		if err != nil {
			return err
		}
		if existing, exists := sockets[socket]; exists && existing != key {
			return fmt.Errorf("Agent %q has incompatible logical inbounds on %s", candidate.hop.AgentID, socket)
		}
		sockets[socket] = key
		group := groups[key]
		if group == nil {
			group = &listenerGroup{
				agentID:  candidate.hop.AgentID,
				key:      key,
				socket:   socket,
				endpoint: candidate.endpoint,
				tag:      "tp-in-" + shortDigest(key),
			}
			groups[key] = group
			byAgent[candidate.hop.AgentID].groups = append(byAgent[candidate.hop.AgentID].groups, group)
		}
		for _, user := range candidate.users {
			for _, existingCandidate := range group.candidates {
				for _, existing := range existingCandidate.users {
					if existing.Name == user.Name || existing.Secret == user.Secret {
						return fmt.Errorf("combined listener %s has duplicate user identity or credential", socket)
					}
				}
			}
		}
		candidate.inboundTag = group.tag
		group.candidates = append(group.candidates, candidate)
	}
	for _, render := range byAgent {
		sort.Slice(render.groups, func(left, right int) bool { return render.groups[left].key < render.groups[right].key })
	}
	return nil
}

func listenerKeys(agentID string, endpoint Endpoint) (string, string, error) {
	compatible := struct {
		Protocol   Protocol         `json:"protocol"`
		Listen     string           `json:"listen"`
		ListenPort int              `json:"listen_port"`
		Method     string           `json:"method,omitempty"`
		ServerKey  string           `json:"server_key,omitempty"`
		Multiplex  *MultiplexConfig `json:"multiplex,omitempty"`
		TLS        TLSConfig        `json:"tls,omitempty"`
		UpMbps     int              `json:"up_mbps,omitempty"`
		DownMbps   int              `json:"down_mbps,omitempty"`
		ObfsType   string           `json:"obfs_type,omitempty"`
		ObfsSecret string           `json:"obfs_secret,omitempty"`
	}{endpoint.Protocol, endpoint.Listen, endpoint.ListenPort, endpoint.Method, endpoint.ServerKey, endpoint.Multiplex, endpoint.TLS, endpoint.UpMbps, endpoint.DownMbps, endpoint.ObfsType, endpoint.ObfsSecret}
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

func renderAgentConfig(render *agentRender) ([]byte, error) {
	inbounds := make([]map[string]any, 0, len(render.groups))
	for _, group := range render.groups {
		inbound, provider, err := renderListener(group)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, inbound)
		if provider != nil {
			render.certificateProviders = append(render.certificateProviders, provider)
		}
	}
	rules := render.rules
	if render.needsSniff {
		rules = append([]map[string]any{{"action": "sniff"}}, rules...)
	}
	ruleSetTags := make([]string, 0, len(render.ruleSets))
	for tag := range render.ruleSets {
		ruleSetTags = append(ruleSetTags, tag)
	}
	sort.Strings(ruleSetTags)
	ruleSets := make([]map[string]any, 0, len(ruleSetTags))
	for _, tag := range ruleSetTags {
		ruleSets = append(ruleSets, render.ruleSets[tag])
	}
	route := map[string]any{"rules": rules, "final": "tp-reject"}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	config := map[string]any{
		"inbounds":  inbounds,
		"outbounds": render.outbounds,
		"route":     route,
	}
	if len(render.certificateProviders) > 0 {
		config["certificate_providers"] = render.certificateProviders
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func renderListener(group *listenerGroup) (map[string]any, map[string]any, error) {
	users := make([]map[string]any, 0)
	for _, candidate := range group.candidates {
		for _, user := range candidate.users {
			users = append(users, map[string]any{"name": user.Name, "password": user.Secret})
		}
	}
	sort.Slice(users, func(left, right int) bool { return users[left]["name"].(string) < users[right]["name"].(string) })
	endpoint := group.endpoint
	inbound := map[string]any{
		"type":        endpoint.Protocol,
		"tag":         group.tag,
		"listen":      endpoint.Listen,
		"listen_port": endpoint.ListenPort,
		"users":       users,
	}
	var provider map[string]any
	switch endpoint.Protocol {
	case ProtocolShadowsocks:
		inbound["method"] = endpoint.Method
		inbound["password"] = endpoint.ServerKey
		if multiplex := renderMultiplex(endpoint.Multiplex); multiplex != nil {
			inbound["multiplex"] = multiplex
		}
	case ProtocolAnyTLS, ProtocolHysteria2:
		tls, certificateProvider := renderInboundTLS(group)
		inbound["tls"] = tls
		provider = certificateProvider
		if endpoint.Protocol == ProtocolHysteria2 {
			if endpoint.UpMbps > 0 {
				inbound["up_mbps"] = endpoint.UpMbps
			}
			if endpoint.DownMbps > 0 {
				inbound["down_mbps"] = endpoint.DownMbps
			}
			if endpoint.ObfsType != "" {
				inbound["obfs"] = map[string]any{"type": endpoint.ObfsType, "password": endpoint.ObfsSecret}
			}
		}
	default:
		return nil, nil, errors.New("unsupported listener protocol")
	}
	return inbound, provider, nil
}

func renderInboundTLS(group *listenerGroup) (map[string]any, map[string]any) {
	config := group.endpoint.TLS
	switch config.Mode {
	case TLSModeACME:
		tag := "tp-acme-" + shortDigest(group.key)
		return map[string]any{"enabled": true, "certificate_provider": tag}, map[string]any{
			"type": "acme", "tag": tag, "domain": []string{config.ServerName},
			"email": config.Email, "provider": "letsencrypt", "disable_tls_alpn_challenge": true,
		}
	case TLSModeSelfSigned:
		base := "certificates/theatropolis-self-signed/" + shortDigest(group.key)
		return map[string]any{
			"enabled": true, "server_name": config.ServerName,
			"certificate_path": base + "/certificate.pem", "key_path": base + "/private-key.pem",
		}, nil
	default:
		return map[string]any{
			"enabled": true, "certificate_path": config.CertificatePath, "key_path": config.KeyPath,
		}, nil
	}
}

func renderHopRules(render *agentRender, candidate *ingressCandidate) error {
	allLabels := make([]string, 0, len(candidate.users))
	for _, user := range candidate.users {
		allLabels = append(allLabels, user.Name)
	}
	links := make([]*Link, 0)
	for index := range candidate.node.Links {
		link := &candidate.node.Links[index]
		if link.ParentHopID == candidate.hop.ID {
			links = append(links, link)
		}
	}
	sort.Slice(links, func(left, right int) bool { return links[left].Order < links[right].Order })
	for _, link := range links {
		for _, rule := range link.Rules {
			if len(allLabels) == 0 {
				continue
			}
			rendered := map[string]any{"inbound": []string{candidate.inboundTag}, "auth_user": allLabels}
			if err := renderRuleMatch(render, candidate.node, rule, rendered); err != nil {
				return err
			}
			rendered["action"] = "route"
			rendered["outbound"] = linkOutboundTag(link.ID)
			render.rules = append(render.rules, rendered)
		}
		if link.Fallback && len(allLabels) > 0 {
			render.rules = append(render.rules, map[string]any{
				"inbound": []string{candidate.inboundTag}, "auth_user": allLabels,
				"action": "route", "outbound": linkOutboundTag(link.ID),
			})
		}
	}
	if len(allLabels) > 0 {
		final := map[string]any{"inbound": []string{candidate.inboundTag}, "auth_user": allLabels}
		applyTarget(final, candidate.hop.Final)
		render.rules = append(render.rules, final)
	}
	return nil
}

func renderRuleMatch(render *agentRender, node *ProxyNode, rule Rule, output map[string]any) error {
	switch rule.Match {
	case MatchNone:
		return nil
	case MatchGeosite, MatchGeoIP:
		prefix := string(rule.Match)
		tags := make([]string, 0, len(rule.Values))
		for _, value := range rule.Values {
			tag := prefix + "-" + value
			tags = append(tags, tag)
			render.ruleSets[tag] = map[string]any{
				"type": "remote", "format": "binary", "tag": tag,
				"url":             fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/sing-%s/rule-set/%s.srs", prefix, tag),
				"update_interval": "1d",
			}
		}
		output["rule_set"] = tags
		if rule.Match == MatchGeosite {
			render.needsSniff = true
		}
	case MatchRuleSet:
		tags := make([]string, 0, len(rule.Values))
		for _, value := range rule.Values {
			custom, exists := customRuleSet(*node, value)
			if !exists {
				return fmt.Errorf("Proxy Node %q references undefined custom Rule Set %q", node.Name, value)
			}
			tag := "tp-rs-" + shortID(node.ID) + "-" + custom.Tag
			tags = append(tags, tag)
			render.ruleSets[tag] = map[string]any{
				"type": "remote", "format": custom.Format, "tag": tag,
				"url": custom.URL, "update_interval": custom.UpdateInterval,
			}
		}
		output["rule_set"] = tags
		render.needsSniff = true
	default:
		output[string(rule.Match)] = rule.Values
		if rule.Match == MatchProtocol || rule.Match == MatchDomain || rule.Match == MatchDomainSuffix || rule.Match == MatchDomainKeyword || rule.Match == MatchDomainRegex {
			render.needsSniff = true
		}
	}
	return nil
}

func applyTarget(rule map[string]any, target Target) {
	if target.Type == TargetReject {
		rule["action"] = "reject"
		return
	}
	rule["action"] = "route"
	if target.Type == TargetLink {
		rule["outbound"] = linkOutboundTag(target.LinkID)
	} else {
		rule["outbound"] = "tp-direct"
	}
}

func renderLinkOutbound(node ProxyNode, link Link, child Hop, resolver AddressResolver) (map[string]any, error) {
	family, err := pool.ParseFamily(link.Endpoint.Family)
	if err != nil {
		return nil, err
	}
	address, ok := resolver.AgentAddressForFamily(child.AgentID, family)
	if !ok {
		return nil, fmt.Errorf("Link %q in Proxy Node %q has no routable %s address for Agent %q", link.ID, node.Name, family.String(), child.AgentID)
	}
	endpoint := link.Endpoint
	outbound := map[string]any{
		"type": endpoint.Protocol, "tag": linkOutboundTag(link.ID),
		"server": address, "server_port": endpoint.ListenPort,
	}
	switch endpoint.Protocol {
	case ProtocolShadowsocks:
		outbound["method"] = endpoint.Method
		outbound["password"] = endpoint.ServerKey + ":" + link.Credential.Secret
		if multiplex := renderMultiplex(endpoint.Multiplex); multiplex != nil {
			outbound["multiplex"] = multiplex
		}
	case ProtocolAnyTLS, ProtocolHysteria2:
		outbound["password"] = link.Credential.Secret
		insecure := endpoint.TLS.Mode != TLSModeACME
		outbound["tls"] = map[string]any{
			"enabled": true, "server_name": endpoint.TLS.ServerName, "insecure": insecure,
		}
		if endpoint.Protocol == ProtocolHysteria2 {
			if endpoint.UpMbps > 0 {
				outbound["up_mbps"] = endpoint.UpMbps
			}
			if endpoint.DownMbps > 0 {
				outbound["down_mbps"] = endpoint.DownMbps
			}
			if endpoint.ObfsType != "" {
				outbound["obfs"] = map[string]any{"type": endpoint.ObfsType, "password": endpoint.ObfsSecret}
			}
		}
	default:
		return nil, errors.New("unsupported Link protocol")
	}
	return outbound, nil
}

func renderMultiplex(config *MultiplexConfig) map[string]any {
	if config == nil {
		return nil
	}
	multiplex := map[string]any{"enabled": true}
	if config.Padding {
		multiplex["padding"] = true
	}
	if config.Brutal != nil {
		multiplex["brutal"] = map[string]any{
			"enabled": true, "up_mbps": config.Brutal.UpMbps, "down_mbps": config.Brutal.DownMbps,
		}
	}
	return multiplex
}

func topologyDepths(node ProxyNode) map[string]int {
	children := make(map[string][]string)
	for _, link := range node.Links {
		children[link.ParentHopID] = append(children[link.ParentHopID], link.ChildHopID)
	}
	depths := make(map[string]int, len(node.Hops))
	var visit func(string, int)
	visit = func(hopID string, depth int) {
		depths[hopID] = depth
		for _, child := range children[hopID] {
			visit(child, depth+1)
		}
	}
	visit(node.Entrance.HopID, 0)
	return depths
}

func customRuleSet(node ProxyNode, tag string) (CustomRuleSet, bool) {
	for _, ruleSet := range node.RuleSets {
		if ruleSet.Tag == tag {
			return ruleSet, true
		}
	}
	return CustomRuleSet{}, false
}

func endUserLabel(proxyName, userName string) string {
	return proxyName + "-" + userName
}

func linkUserLabel(proxyName, linkID string) string {
	return proxyName + "-link-" + shortID(linkID)
}

func linkOutboundTag(linkID string) string {
	return "tp-out-" + shortID(linkID)
}

func shortID(id string) string {
	if separator := strings.IndexByte(id, '_'); separator >= 0 {
		id = id[separator+1:]
	}
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func shortDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}
