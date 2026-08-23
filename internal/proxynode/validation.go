package proxynode

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	maxStateBytes = 16 << 20
	maxNameBytes  = 96
	maxValueBytes = 1024
)

var (
	ErrNotFound       = errors.New("proxy node resource not found")
	ErrConflict       = errors.New("proxy node resource conflicts with existing state")
	ErrInvalidState   = errors.New("invalid proxy node state")
	ErrNewerSchema    = errors.New("proxy node state uses a newer schema")
	ErrUnsafeStorage  = errors.New("unsafe proxy node storage")
	namePattern       = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._-]{0,95}\z`)
	agentIDPattern    = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z`)
	idPattern         = regexp.MustCompile(`\A[a-z]{2,4}_[A-Za-z0-9_-]{20,32}\z`)
	ruleSetTagPattern = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z`)
)

func validateState(state State) error {
	userIDs := make(map[string]User, len(state.Users))
	userNames := make(map[string]struct{}, len(state.Users))
	for _, user := range state.Users {
		if !validID(user.ID, "usr_") || !validName(user.Name) || user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() {
			return fmt.Errorf("%w: invalid end user", ErrInvalidState)
		}
		key := strings.ToLower(user.Name)
		if _, exists := userIDs[user.ID]; exists {
			return fmt.Errorf("%w: duplicate end user ID", ErrInvalidState)
		}
		if _, exists := userNames[key]; exists {
			return fmt.Errorf("%w: duplicate end user name", ErrInvalidState)
		}
		userIDs[user.ID] = user
		userNames[key] = struct{}{}
	}

	proxyIDs := make(map[string]struct{}, len(state.ProxyNodes))
	proxyNames := make(map[string]struct{}, len(state.ProxyNodes))
	globalIDs := make(map[string]struct{}, len(state.Users)+len(state.ProxyNodes))
	globalCredentials := make(map[string]struct{})
	for id := range userIDs {
		globalIDs[id] = struct{}{}
	}
	for index := range state.ProxyNodes {
		node := &state.ProxyNodes[index]
		if !validID(node.ID, "pn_") || !validName(node.Name) || node.CreatedAt.IsZero() || node.UpdatedAt.IsZero() {
			return fmt.Errorf("%w: invalid Proxy Node identity", ErrInvalidState)
		}
		key := strings.ToLower(node.Name)
		if _, exists := proxyIDs[node.ID]; exists {
			return fmt.Errorf("%w: duplicate Proxy Node ID", ErrInvalidState)
		}
		if _, exists := proxyNames[key]; exists {
			return fmt.Errorf("%w: duplicate Proxy Node name", ErrInvalidState)
		}
		proxyIDs[node.ID] = struct{}{}
		globalIDs[node.ID] = struct{}{}
		proxyNames[key] = struct{}{}
		if err := validateProxyNode(*node, userIDs); err != nil {
			return fmt.Errorf("%w %q: %v", ErrInvalidState, node.Name, err)
		}
		for _, hop := range node.Hops {
			if _, exists := globalIDs[hop.ID]; exists {
				return fmt.Errorf("%w: entity ID is reused", ErrInvalidState)
			}
			globalIDs[hop.ID] = struct{}{}
		}
		for _, link := range node.Links {
			if _, exists := globalIDs[link.ID]; exists {
				return fmt.Errorf("%w: entity ID is reused", ErrInvalidState)
			}
			globalIDs[link.ID] = struct{}{}
			for _, rule := range link.Rules {
				if _, exists := globalIDs[rule.ID]; exists {
					return fmt.Errorf("%w: entity ID is reused", ErrInvalidState)
				}
				globalIDs[rule.ID] = struct{}{}
			}
			if _, exists := globalCredentials[link.Credential.Secret]; exists {
				return fmt.Errorf("%w: generated credential is reused", ErrInvalidState)
			}
			globalCredentials[link.Credential.Secret] = struct{}{}
		}
		for _, membership := range node.Memberships {
			if _, exists := globalIDs[membership.ID]; exists {
				return fmt.Errorf("%w: entity ID is reused", ErrInvalidState)
			}
			globalIDs[membership.ID] = struct{}{}
			if _, exists := globalCredentials[membership.Credential.Secret]; exists {
				return fmt.Errorf("%w: generated credential is reused", ErrInvalidState)
			}
			globalCredentials[membership.Credential.Secret] = struct{}{}
		}
	}
	seenManaged := make(map[string]struct{}, len(state.ManagedAgents))
	for _, agentID := range state.ManagedAgents {
		if !validAgentID(agentID) {
			return fmt.Errorf("%w: invalid managed Agent ID", ErrInvalidState)
		}
		if _, exists := seenManaged[agentID]; exists {
			return fmt.Errorf("%w: duplicate managed Agent ID", ErrInvalidState)
		}
		seenManaged[agentID] = struct{}{}
	}
	return nil
}

func validateProxyNode(node ProxyNode, users map[string]User) error {
	if len(node.Hops) == 0 {
		return errors.New("Proxy Node has no entrance Hop")
	}
	if err := validateEndpoint(node.Entrance.Endpoint); err != nil {
		return fmt.Errorf("invalid entrance: %w", err)
	}
	hops := make(map[string]Hop, len(node.Hops))
	for _, hop := range node.Hops {
		if !validID(hop.ID, "hop_") || !validName(hop.Name) || !validAgentID(hop.AgentID) || hop.CreatedAt.IsZero() || hop.UpdatedAt.IsZero() {
			return errors.New("invalid Hop")
		}
		if _, exists := hops[hop.ID]; exists {
			return errors.New("duplicate Hop ID")
		}
		hops[hop.ID] = hop
	}
	if _, exists := hops[node.Entrance.HopID]; !exists {
		return errors.New("entrance references a missing Hop")
	}

	links := make(map[string]Link, len(node.Links))
	parentByChild := make(map[string]string, len(node.Links))
	outgoing := make(map[string][]Link, len(node.Hops))
	for _, link := range node.Links {
		if !validID(link.ID, "lnk_") || link.Order < 0 || link.CreatedAt.IsZero() || link.UpdatedAt.IsZero() {
			return errors.New("invalid Link")
		}
		if _, exists := links[link.ID]; exists {
			return errors.New("duplicate Link ID")
		}
		if link.ParentHopID == link.ChildHopID {
			return errors.New("Link cannot target its parent")
		}
		if _, exists := hops[link.ParentHopID]; !exists {
			return errors.New("Link parent does not exist")
		}
		if _, exists := hops[link.ChildHopID]; !exists {
			return errors.New("Link child does not exist")
		}
		if _, exists := parentByChild[link.ChildHopID]; exists {
			return errors.New("two Links merge into one Hop")
		}
		if link.ChildHopID == node.Entrance.HopID {
			return errors.New("entrance Hop cannot have a parent")
		}
		if err := validateEndpoint(link.Endpoint); err != nil {
			return fmt.Errorf("invalid Link endpoint: %w", err)
		}
		if err := validateCredential(link.Endpoint, link.Credential); err != nil {
			return fmt.Errorf("invalid Link credential: %w", err)
		}
		if link.Fallback && len(link.Rules) != 0 {
			return errors.New("fallback Link cannot contain match rules")
		}
		for _, rule := range link.Rules {
			if !validID(rule.ID, "rul_") || rule.LegacyTarget != nil {
				return errors.New("invalid Link Rule")
			}
			if err := validateRule(rule); err != nil {
				return err
			}
			if rule.Match == MatchNone {
				return errors.New("unconditional routing must use a fallback Link")
			}
		}
		links[link.ID] = link
		parentByChild[link.ChildHopID] = link.ParentHopID
		outgoing[link.ParentHopID] = append(outgoing[link.ParentHopID], link)
	}
	for parentID, siblings := range outgoing {
		sort.Slice(siblings, func(left, right int) bool { return siblings[left].Order < siblings[right].Order })
		fallbacks := 0
		for order, link := range siblings {
			if link.Order != order {
				return fmt.Errorf("child Link order for Hop %q is not contiguous", parentID)
			}
			if link.Fallback {
				fallbacks++
				if order != len(siblings)-1 {
					return errors.New("fallback Link must be last")
				}
			}
		}
		if fallbacks > 1 {
			return errors.New("Hop has more than one fallback Link")
		}
	}
	for hopID := range hops {
		if hopID == node.Entrance.HopID {
			continue
		}
		if _, exists := parentByChild[hopID]; !exists {
			return errors.New("non-entrance Hop has no parent")
		}
	}
	if err := validateReachability(node.Entrance.HopID, hops, node.Links); err != nil {
		return err
	}

	memberships := make(map[string]Membership, len(node.Memberships))
	membershipUsers := make(map[string]struct{}, len(node.Memberships))
	credentials := make(map[string]struct{}, len(node.Memberships)+len(node.Links))
	for _, membership := range node.Memberships {
		if !validID(membership.ID, "mem_") || membership.CreatedAt.IsZero() {
			return errors.New("invalid Membership")
		}
		if _, exists := memberships[membership.ID]; exists {
			return errors.New("duplicate Membership ID")
		}
		if _, exists := users[membership.UserID]; !exists {
			return errors.New("Membership references a missing End User")
		}
		if _, exists := membershipUsers[membership.UserID]; exists {
			return errors.New("End User has two Memberships in one Proxy Node")
		}
		if err := validateCredential(node.Entrance.Endpoint, membership.Credential); err != nil {
			return fmt.Errorf("invalid Membership credential: %w", err)
		}
		if _, exists := credentials[membership.Credential.Secret]; exists {
			return errors.New("Membership credential is reused")
		}
		memberships[membership.ID] = membership
		membershipUsers[membership.UserID] = struct{}{}
		credentials[membership.Credential.Secret] = struct{}{}
	}
	for _, link := range node.Links {
		if _, exists := credentials[link.Credential.Secret]; exists {
			return errors.New("Link credential is reused")
		}
		credentials[link.Credential.Secret] = struct{}{}
	}

	for _, hop := range node.Hops {
		if len(hop.LegacyRules) != 0 {
			return errors.New("Hop contains legacy routing Rules")
		}
		if err := validateTerminalTarget(hop.Final); err != nil {
			return fmt.Errorf("invalid final target: %w", err)
		}
	}

	ruleSetTags := make(map[string]struct{}, len(node.RuleSets))
	for _, ruleSet := range node.RuleSets {
		if !ruleSetTagPattern.MatchString(ruleSet.Tag) || ruleSet.Format != "binary" {
			return errors.New("invalid custom Rule Set")
		}
		if len(ruleSet.URL) > 2048 || len(ruleSet.UpdateInterval) > 32 {
			return errors.New("custom Rule Set field exceeds its size limit")
		}
		parsed, err := url.ParseRequestURI(ruleSet.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return errors.New("custom Rule Set URL must use HTTPS")
		}
		if _, exists := ruleSetTags[ruleSet.Tag]; exists {
			return errors.New("duplicate custom Rule Set tag")
		}
		ruleSetTags[ruleSet.Tag] = struct{}{}
	}
	return nil
}

func validateReachability(root string, hops map[string]Hop, links []Link) error {
	children := make(map[string][]string, len(hops))
	for _, link := range links {
		children[link.ParentHopID] = append(children[link.ParentHopID], link.ChildHopID)
	}
	seen := make(map[string]bool, len(hops))
	active := make(map[string]bool, len(hops))
	var visit func(string) error
	visit = func(id string) error {
		if active[id] {
			return errors.New("Proxy Node contains a cycle")
		}
		if seen[id] {
			return nil
		}
		active[id] = true
		for _, child := range children[id] {
			if err := visit(child); err != nil {
				return err
			}
		}
		active[id] = false
		seen[id] = true
		return nil
	}
	if err := visit(root); err != nil {
		return err
	}
	if len(seen) != len(hops) {
		return errors.New("Proxy Node contains an unreachable Hop")
	}
	return nil
}

func validateEndpoint(endpoint Endpoint) error {
	if endpoint.Listen == "" || net.ParseIP(endpoint.Listen) == nil {
		return errors.New("listen address must be a literal IP address")
	}
	if endpoint.ListenPort < 1 || endpoint.ListenPort > 65535 || endpoint.ListenPort == 80 {
		return errors.New("listen port is invalid or reserved")
	}
	if !slices.Contains([]string{"", "auto", "ipv4", "ipv6"}, endpoint.Family) {
		return errors.New("address family is invalid")
	}
	switch endpoint.Protocol {
	case ProtocolShadowsocks:
		length, err := shadowsocksKeyLength(endpoint.Method)
		if err != nil {
			return err
		}
		if !validBase64Length(endpoint.ServerKey, length) {
			return errors.New("Shadowsocks server key has the wrong size")
		}
		if endpoint.TLS.Mode != "" || endpoint.UpMbps != 0 || endpoint.DownMbps != 0 || endpoint.ObfsType != "" || endpoint.ObfsSecret != "" {
			return errors.New("Shadowsocks endpoint has incompatible options")
		}
		if err := validateMultiplex(endpoint.Multiplex); err != nil {
			return err
		}
	case ProtocolAnyTLS, ProtocolHysteria2:
		if endpoint.Multiplex != nil {
			return errors.New("multiplex is supported only by Shadowsocks endpoints")
		}
		if err := validateTLS(endpoint.TLS); err != nil {
			return err
		}
		if endpoint.Protocol == ProtocolAnyTLS && (endpoint.UpMbps != 0 || endpoint.DownMbps != 0 || endpoint.ObfsType != "") {
			return errors.New("AnyTLS endpoint has Hysteria2-only options")
		}
		if endpoint.Protocol == ProtocolHysteria2 {
			if endpoint.UpMbps < 0 || endpoint.DownMbps < 0 {
				return errors.New("Hysteria2 bandwidth cannot be negative")
			}
			if !slices.Contains([]string{"", "salamander", "gecko"}, endpoint.ObfsType) {
				return errors.New("unsupported Hysteria2 obfuscation")
			}
			if endpoint.ObfsType != "" && endpoint.ObfsSecret == "" {
				return errors.New("Hysteria2 obfuscation requires a secret")
			}
		}
	default:
		return errors.New("unsupported proxy protocol")
	}
	return nil
}

func validateMultiplex(config *MultiplexConfig) error {
	if config == nil {
		return nil
	}
	if !config.Enabled {
		return errors.New("multiplex configuration must be enabled or omitted")
	}
	if config.Brutal == nil {
		return nil
	}
	if !config.Brutal.Enabled || config.Brutal.UpMbps < 1 || config.Brutal.UpMbps > 1_000_000 || config.Brutal.DownMbps < 1 || config.Brutal.DownMbps > 1_000_000 {
		return errors.New("TCP Brutal requires valid upload and download bandwidth")
	}
	return nil
}

func validateTLS(config TLSConfig) error {
	switch config.Mode {
	case TLSModeACME:
		if !validServerName(config.ServerName) {
			return errors.New("ACME requires a valid server name")
		}
	case TLSModeSelfSigned:
		if !validServerName(config.ServerName) {
			return errors.New("self-signed TLS requires a valid server name or IP")
		}
	case TLSModeFiles:
		if strings.TrimSpace(config.CertificatePath) == "" || strings.TrimSpace(config.KeyPath) == "" {
			return errors.New("TLS certificate and key paths are required")
		}
	default:
		return errors.New("TLS mode is required")
	}
	return nil
}

func validateCredential(endpoint Endpoint, credential Credential) error {
	if endpoint.Protocol == ProtocolShadowsocks {
		length, err := shadowsocksKeyLength(endpoint.Method)
		if err != nil {
			return err
		}
		if !validBase64Length(credential.Secret, length) {
			return errors.New("Shadowsocks user key has the wrong size")
		}
		return nil
	}
	if len(credential.Secret) < 24 || len(credential.Secret) > 256 || strings.ContainsAny(credential.Secret, "\x00\r\n") {
		return errors.New("credential secret is invalid")
	}
	return nil
}

func validateRule(rule Rule) error {
	valid := []MatchType{MatchNone, MatchProtocol, MatchDomain, MatchDomainSuffix, MatchDomainKeyword, MatchDomainRegex, MatchIPCIDR, MatchGeosite, MatchGeoIP, MatchRuleSet, MatchNetwork}
	if !slices.Contains(valid, rule.Match) {
		return errors.New("unsupported routing match type")
	}
	if rule.Match == MatchNone && len(rule.Values) != 0 {
		return errors.New("all-traffic Rule cannot contain match values")
	}
	if rule.Match != MatchNone && len(rule.Values) == 0 {
		return errors.New("routing Rule requires match values")
	}
	if (rule.Match == MatchGeosite || rule.Match == MatchGeoIP) && len(rule.Values) != 1 {
		return errors.New("geosite and geoip Rules accept one value")
	}
	for _, value := range rule.Values {
		if value == "" || len(value) > maxValueBytes || strings.ContainsRune(value, '\x00') {
			return errors.New("routing Rule contains an invalid value")
		}
	}
	return nil
}

func validateTerminalTarget(target Target) error {
	switch target.Type {
	case TargetDirect, TargetReject:
		if target.LinkID != "" {
			return errors.New("terminal target cannot reference a Link")
		}
	default:
		return errors.New("terminal target must be Direct or Reject")
	}
	return nil
}

func validID(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && idPattern.MatchString(value)
}

func validName(value string) bool {
	return len(value) <= maxNameBytes && namePattern.MatchString(value)
}

func validAgentID(value string) bool {
	return agentIDPattern.MatchString(value)
}

func validServerName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\x00/\\") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validBase64Length(value string, length int) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == length
}

func normalizeEndpoint(endpoint Endpoint) Endpoint {
	endpoint.Listen = strings.TrimSpace(endpoint.Listen)
	if endpoint.Listen == "" {
		endpoint.Listen = "::"
	}
	endpoint.Family = strings.TrimSpace(endpoint.Family)
	if endpoint.Family == "" {
		endpoint.Family = "auto"
	}
	endpoint.Method = strings.TrimSpace(endpoint.Method)
	if endpoint.Protocol == ProtocolShadowsocks && endpoint.Method == "" {
		endpoint.Method = "2022-blake3-aes-128-gcm"
	}
	endpoint.TLS.ServerName = strings.TrimSpace(endpoint.TLS.ServerName)
	endpoint.TLS.Email = strings.TrimSpace(endpoint.TLS.Email)
	endpoint.TLS.CertificatePath = strings.TrimSpace(endpoint.TLS.CertificatePath)
	endpoint.TLS.KeyPath = strings.TrimSpace(endpoint.TLS.KeyPath)
	endpoint.ObfsType = strings.TrimSpace(endpoint.ObfsType)
	return endpoint
}

func normalizeBuild(build BuildInfo, now time.Time) BuildInfo {
	build.Component = strings.TrimSpace(build.Component)
	build.Version = strings.TrimSpace(build.Version)
	build.Commit = strings.TrimSpace(build.Commit)
	if build.Component == "" {
		build.Component = "master"
	}
	if build.Version == "" {
		build.Version = "development"
	}
	if build.Commit == "" {
		build.Commit = "unknown"
	}
	build.RecordedAt = now.UTC()
	return build
}
