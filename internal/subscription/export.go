// Package subscription renders end-user Proxy Node access as client profiles.
package subscription

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
)

type Format string

const (
	FormatClash   Format = "clash"
	FormatSurge   Format = "surge"
	FormatSingBox Format = "sing-box"
)

type Node struct {
	Name       string
	Protocol   proxynode.Protocol
	Server     string
	Port       int
	Password   string
	Method     string
	ServerKey  string
	ServerName string
	Insecure   bool
	UpMbps     int
	DownMbps   int
	ObfsType   string
	ObfsSecret string
}

type Profile struct {
	Name           string
	Nodes          []Node
	Default        proxynode.SubscriptionAction
	Rules          []proxynode.SubscriptionRule
	RuleSetBaseURL string
}

func Render(format Format, profile Profile) ([]byte, string, error) {
	profile = normalizeProfile(profile)
	for _, node := range profile.Nodes {
		if err := ValidateNode(node); err != nil {
			return nil, "", err
		}
	}
	switch format {
	case FormatClash:
		content, err := renderClash(profile)
		return content, "text/yaml; charset=utf-8", err
	case FormatSurge:
		content, err := renderSurge(profile)
		return content, "text/plain; charset=utf-8", err
	case FormatSingBox:
		content, err := renderSingBox(profile)
		return content, "application/json; charset=utf-8", err
	default:
		return nil, "", errors.New("unsupported subscription format")
	}
}

func normalizeProfile(profile Profile) Profile {
	if profile.Default == "" {
		profile.Default = proxynode.SubscriptionProxy
	}
	sort.SliceStable(profile.Rules, func(left, right int) bool { return profile.Rules[left].Order < profile.Rules[right].Order })
	seen := make(map[string]int)
	for index := range profile.Nodes {
		base := strings.TrimSpace(profile.Nodes[index].Name)
		if base == "" {
			base = "Node"
		}
		key := strings.ToLower(base)
		seen[key]++
		if seen[key] > 1 {
			base += " " + strconv.Itoa(seen[key])
		}
		profile.Nodes[index].Name = base
	}
	return profile
}

func renderClash(profile Profile) ([]byte, error) {
	var out strings.Builder
	out.WriteString("mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: info\n")
	if profileUsesGeoRules(profile) {
		out.WriteString("geodata-mode: true\ngeo-auto-update: true\ngeo-update-interval: 24\ngeox-url:\n")
		out.WriteString("  geoip: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat\n")
		out.WriteString("  geosite: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat\n")
	}
	out.WriteByte('\n')
	if len(profile.Nodes) == 0 {
		out.WriteString("proxies: []\n")
	} else {
		out.WriteString("proxies:\n")
	}
	for _, node := range profile.Nodes {
		out.WriteString("  - name: " + yamlString(node.Name) + "\n")
		out.WriteString("    type: " + clashProtocol(node.Protocol) + "\n")
		out.WriteString("    server: " + yamlString(node.Server) + "\n")
		out.WriteString("    port: " + strconv.Itoa(node.Port) + "\n")
		switch node.Protocol {
		case proxynode.ProtocolShadowsocks:
			out.WriteString("    cipher: " + yamlString(node.Method) + "\n")
			out.WriteString("    password: " + yamlString(node.ServerKey+":"+node.Password) + "\n")
			out.WriteString("    udp: true\n")
		case proxynode.ProtocolAnyTLS:
			out.WriteString("    password: " + yamlString(node.Password) + "\n")
			writeClashTLS(&out, node)
			out.WriteString("    udp: true\n")
		case proxynode.ProtocolHysteria2:
			out.WriteString("    password: " + yamlString(node.Password) + "\n")
			writeClashTLS(&out, node)
			if node.UpMbps > 0 {
				out.WriteString("    up: " + yamlString(strconv.Itoa(node.UpMbps)+" Mbps") + "\n")
			}
			if node.DownMbps > 0 {
				out.WriteString("    down: " + yamlString(strconv.Itoa(node.DownMbps)+" Mbps") + "\n")
			}
			if node.ObfsType != "" {
				out.WriteString("    obfs: " + yamlString(node.ObfsType) + "\n")
				out.WriteString("    obfs-password: " + yamlString(node.ObfsSecret) + "\n")
			}
		}
	}
	out.WriteString("\nproxy-groups:\n  - name: Proxy\n    type: select\n    proxies:\n")
	if len(profile.Nodes) == 0 {
		out.WriteString("      - DIRECT\n      - REJECT\n")
	} else {
		for _, node := range profile.Nodes {
			out.WriteString("      - " + yamlString(node.Name) + "\n")
		}
		out.WriteString("      - DIRECT\n      - REJECT\n")
	}
	out.WriteString("\nrules:\n")
	for _, rule := range profile.Rules {
		lines, err := clashRuleLines(rule)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			out.WriteString("  - " + yamlString(line) + "\n")
		}
	}
	out.WriteString("  - " + yamlString("MATCH,"+actionName(profile.Default)) + "\n")
	return []byte(out.String()), nil
}

func profileUsesGeoRules(profile Profile) bool {
	for _, rule := range profile.Rules {
		if rule.Match == proxynode.SubscriptionMatchGeosite || rule.Match == proxynode.SubscriptionMatchGeoIP {
			return true
		}
	}
	return false
}

func writeClashTLS(out *strings.Builder, node Node) {
	if node.ServerName != "" {
		out.WriteString("    sni: " + yamlString(node.ServerName) + "\n")
	}
	out.WriteString("    skip-cert-verify: " + strconv.FormatBool(node.Insecure) + "\n")
}

func clashRuleLines(rule proxynode.SubscriptionRule) ([]string, error) {
	target := actionName(rule.Action)
	kind := map[proxynode.SubscriptionMatch]string{
		proxynode.SubscriptionMatchDomain: "DOMAIN", proxynode.SubscriptionMatchDomainSuffix: "DOMAIN-SUFFIX",
		proxynode.SubscriptionMatchDomainKeyword: "DOMAIN-KEYWORD", proxynode.SubscriptionMatchDomainRegex: "DOMAIN-REGEX",
		proxynode.SubscriptionMatchIPCIDR: "IP-CIDR", proxynode.SubscriptionMatchSourceIPCIDR: "SRC-IP-CIDR",
		proxynode.SubscriptionMatchGeosite: "GEOSITE", proxynode.SubscriptionMatchGeoIP: "GEOIP", proxynode.SubscriptionMatchDestinationPort: "DST-PORT",
		proxynode.SubscriptionMatchSourcePort: "SRC-PORT", proxynode.SubscriptionMatchNetwork: "NETWORK",
		proxynode.SubscriptionMatchProcessName: "PROCESS-NAME",
	}[rule.Match]
	if kind == "" {
		return nil, errors.New("unsupported Clash rule type")
	}
	lines := make([]string, 0, len(rule.Values))
	for _, value := range rule.Values {
		currentKind := kind
		if rule.Match == proxynode.SubscriptionMatchIPCIDR && strings.Contains(value, ":") {
			currentKind = "IP-CIDR6"
		}
		line := currentKind + "," + csvField(value) + "," + target
		if rule.NoResolve {
			line += ",no-resolve"
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func renderSurge(profile Profile) ([]byte, error) {
	var out strings.Builder
	out.WriteString("[General]\nloglevel = notify\n\n[Proxy]\n")
	for _, node := range profile.Nodes {
		line, err := surgeNode(node)
		if err != nil {
			return nil, err
		}
		out.WriteString(surgeName(node.Name) + " = " + line + "\n")
	}
	out.WriteString("\n[Proxy Group]\nProxy = select")
	if len(profile.Nodes) == 0 {
		out.WriteString(", DIRECT, REJECT")
	} else {
		for _, node := range profile.Nodes {
			out.WriteString(", " + surgeName(node.Name))
		}
		out.WriteString(", DIRECT, REJECT")
	}
	out.WriteString("\n\n[Rule]\n")
	for _, rule := range profile.Rules {
		lines, err := surgeRuleLines(rule, profile.RuleSetBaseURL)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			out.WriteString(line + "\n")
		}
	}
	out.WriteString("FINAL," + actionName(profile.Default) + "\n")
	return []byte(out.String()), nil
}

func surgeNode(node Node) (string, error) {
	base := surgeField(node.Server) + ", " + strconv.Itoa(node.Port)
	tls := ""
	if node.ServerName != "" {
		tls += ", sni=" + surgeField(node.ServerName)
	}
	if node.Insecure {
		tls += ", skip-cert-verify=true"
	}
	switch node.Protocol {
	case proxynode.ProtocolShadowsocks:
		return "ss, " + base + ", encrypt-method=" + surgeField(node.Method) + ", password=" + surgeField(node.ServerKey+":"+node.Password) + ", udp-relay=true", nil
	case proxynode.ProtocolAnyTLS:
		return "anytls, " + base + ", password=" + surgeField(node.Password) + tls, nil
	case proxynode.ProtocolHysteria2:
		line := "hysteria2, " + base + ", password=" + surgeField(node.Password)
		if node.DownMbps > 0 {
			line += ", download-bandwidth=" + strconv.Itoa(node.DownMbps)
		}
		if node.ObfsType == "salamander" {
			line += ", salamander-password=" + surgeField(node.ObfsSecret)
		}
		if node.ObfsType == "gecko" {
			line += ", gecko-password=" + surgeField(node.ObfsSecret)
		}
		return line + tls, nil
	default:
		return "", errors.New("unsupported Surge proxy protocol")
	}
}

func surgeRuleLines(rule proxynode.SubscriptionRule, ruleSetBaseURL string) ([]string, error) {
	target := actionName(rule.Action)
	// Surge's URL-REGEX matches the full request URL and is not equivalent to
	// sing-box/Clash domain_regex. Silently emitting it would broaden or narrow
	// administrator intent, so this non-portable match is omitted for Surge.
	if rule.Match == proxynode.SubscriptionMatchDomainRegex {
		return nil, nil
	}
	if rule.Match == proxynode.SubscriptionMatchGeosite || rule.Match == proxynode.SubscriptionMatchGeoIP {
		base := strings.TrimRight(ruleSetBaseURL, "/")
		if base == "" {
			return nil, errors.New("Surge geo rules require a rule-set base URL")
		}
		lines := make([]string, 0, len(rule.Values))
		for _, value := range rule.Values {
			kind := "geosite"
			prefix := "DOMAIN-SET"
			if rule.Match == proxynode.SubscriptionMatchGeoIP {
				kind = "geoip"
				prefix = "RULE-SET"
			}
			setURL := base + "/" + kind + "/" + url.PathEscape(strings.ToLower(value))
			if rule.Match == proxynode.SubscriptionMatchGeoIP && rule.NoResolve {
				setURL += "?no-resolve=1"
			}
			lines = append(lines, prefix+","+surgeField(setURL)+","+target+",update-interval=86400")
		}
		return lines, nil
	}
	kind := map[proxynode.SubscriptionMatch]string{
		proxynode.SubscriptionMatchDomain: "DOMAIN", proxynode.SubscriptionMatchDomainSuffix: "DOMAIN-SUFFIX",
		proxynode.SubscriptionMatchDomainKeyword: "DOMAIN-KEYWORD",
		proxynode.SubscriptionMatchIPCIDR:        "IP-CIDR", proxynode.SubscriptionMatchSourceIPCIDR: "SRC-IP",
		proxynode.SubscriptionMatchGeoIP: "GEOIP", proxynode.SubscriptionMatchDestinationPort: "DEST-PORT",
		proxynode.SubscriptionMatchSourcePort: "SRC-PORT", proxynode.SubscriptionMatchNetwork: "PROTOCOL",
		proxynode.SubscriptionMatchProcessName: "PROCESS-NAME",
	}[rule.Match]
	if kind == "" {
		return nil, errors.New("unsupported Surge rule type")
	}
	lines := make([]string, 0, len(rule.Values))
	for _, value := range rule.Values {
		currentKind := kind
		currentValue := value
		if rule.Match == proxynode.SubscriptionMatchIPCIDR && strings.Contains(value, ":") {
			currentKind = "IP-CIDR6"
		}
		if rule.Match == proxynode.SubscriptionMatchNetwork {
			currentValue = strings.ToUpper(value)
		}
		line := currentKind + "," + surgeField(currentValue) + "," + target
		if rule.NoResolve {
			line += ",no-resolve"
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func renderSingBox(profile Profile) ([]byte, error) {
	outbounds := make([]any, 0, len(profile.Nodes)+3)
	nodeTags := make([]string, 0, len(profile.Nodes))
	for _, node := range profile.Nodes {
		outbound, err := singBoxNode(node)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, outbound)
		nodeTags = append(nodeTags, node.Name)
	}
	outbounds = append(outbounds,
		map[string]any{"type": "direct", "tag": "Direct"},
		map[string]any{"type": "block", "tag": "Reject"},
	)
	selectorMembers := slices.Clone(nodeTags)
	if len(selectorMembers) == 0 {
		selectorMembers = []string{"Direct", "Reject"}
	} else {
		selectorMembers = append(selectorMembers, "Direct", "Reject")
	}
	outbounds = append(outbounds, map[string]any{"type": "selector", "tag": "Proxy", "outbounds": selectorMembers})
	compiledRules := make([]singBoxRouteRule, 0, len(profile.Rules)+2)
	geoRuleSets := make(map[string]string)
	for _, rule := range profile.Rules {
		rendered, err := singBoxRule(rule)
		if err != nil {
			return nil, err
		}
		compiledRules = append(compiledRules, singBoxRouteRule{Rule: rendered, NoResolve: rule.NoResolve})
		if rule.Match == proxynode.SubscriptionMatchGeoIP {
			for _, value := range rule.Values {
				name := strings.ToLower(value)
				geoRuleSets["geoip-"+name] = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-" + name + ".srs"
			}
		}
		if rule.Match == proxynode.SubscriptionMatchGeosite {
			for _, value := range rule.Values {
				name := strings.ToLower(value)
				geoRuleSets["geosite-"+name] = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-" + name + ".srs"
			}
		}
	}
	ruleSets := make([]any, 0, len(geoRuleSets))
	geoTags := make([]string, 0, len(geoRuleSets))
	for tag := range geoRuleSets {
		geoTags = append(geoTags, tag)
	}
	sort.Strings(geoTags)
	for _, tag := range geoTags {
		ruleSets = append(ruleSets, map[string]any{
			"type": "remote", "tag": tag, "format": "binary",
			"url":             geoRuleSets[tag],
			"update_interval": "1d",
		})
	}
	rules := insertSingBoxRouteMetadataActions(compiledRules)
	route := map[string]any{
		"rules":                   rules,
		"final":                   actionName(profile.Default),
		"auto_detect_interface":   true,
		"default_http_client":     "rule-set-http",
		"default_domain_resolver": "local-dns",
	}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	dnsServers := []any{map[string]any{
		"type": "local", "tag": "local-dns",
	}}
	hasProxyDNS := len(profile.Nodes) > 0
	if hasProxyDNS {
		dnsServers = append(dnsServers, map[string]any{
			"type": "https", "tag": "proxy-dns",
			"server": "1.1.1.1", "server_port": 443, "path": "/dns-query",
			"tls":    map[string]any{"enabled": true, "server_name": "cloudflare-dns.com"},
			"detour": "Proxy",
		})
	}
	dns := map[string]any{
		"servers": dnsServers,
		"rules":   singBoxDNSRules(profile.Rules, hasProxyDNS),
		"final":   singBoxDNSServerForAction(profile.Default, hasProxyDNS),
	}
	root := map[string]any{
		"log": map[string]any{"level": "info"},
		"http_clients": []any{
			map[string]any{"tag": "rule-set-http", "detour": "Proxy"},
		},
		"dns": dns,
		"inbounds": []any{
			map[string]any{
				"type": "tun", "tag": "tun-in",
				"address":    []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
				"auto_route": true, "strict_route": true, "stack": "system",
			},
			map[string]any{
				"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890,
			},
		},
		"outbounds": outbounds, "route": route,
		"experimental": map[string]any{
			"clash_api":  map[string]any{"external_controller": "127.0.0.1:9090"},
			"cache_file": map[string]any{"enabled": true},
		},
	}
	content, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

type singBoxRouteRule struct {
	Rule      map[string]any
	NoResolve bool
}

func insertSingBoxRouteMetadataActions(rules []singBoxRouteRule) []map[string]any {
	normalized := make([]map[string]any, 0, len(rules)+3)
	normalized = append(normalized,
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	)
	seenSniff, seenResolve := true, false
	for _, compiled := range rules {
		rule := compiled.Rule
		needsSniff, needsResolve := false, false
		for _, field := range []string{"domain", "domain_suffix", "domain_keyword", "domain_regex"} {
			if _, exists := rule[field]; exists {
				needsSniff = true
			}
		}
		for _, field := range []string{"ip_cidr", "geoip"} {
			if _, exists := rule[field]; exists {
				needsResolve = true
			}
		}
		if tags, ok := rule["rule_set"].([]string); ok {
			for _, tag := range tags {
				if strings.HasPrefix(tag, "geoip-") {
					needsResolve = true
				} else if strings.HasPrefix(tag, "geosite-") {
					needsSniff = true
				}
			}
		}
		if compiled.NoResolve {
			needsResolve = false
		}
		if needsResolve && !seenResolve {
			normalized = append(normalized, map[string]any{"action": "resolve"})
			seenResolve = true
		}
		if needsSniff && !seenSniff {
			normalized = append(normalized, map[string]any{"action": "sniff"})
			seenSniff = true
		}
		normalized = append(normalized, rule)
	}
	return normalized
}

func singBoxDNSRules(rules []proxynode.SubscriptionRule, hasProxy bool) []map[string]any {
	dnsRules := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		server := singBoxDNSServerForAction(rule.Action, hasProxy)
		if rule.Action == proxynode.SubscriptionReject {
			continue
		}
		dnsRule := map[string]any{"action": "route", "server": server}
		switch rule.Match {
		case proxynode.SubscriptionMatchDomain:
			dnsRule["domain"] = slices.Clone(rule.Values)
		case proxynode.SubscriptionMatchDomainSuffix:
			dnsRule["domain_suffix"] = slices.Clone(rule.Values)
		case proxynode.SubscriptionMatchDomainKeyword:
			dnsRule["domain_keyword"] = slices.Clone(rule.Values)
		case proxynode.SubscriptionMatchDomainRegex:
			dnsRule["domain_regex"] = slices.Clone(rule.Values)
		case proxynode.SubscriptionMatchGeosite:
			tags := make([]string, 0, len(rule.Values))
			for _, value := range rule.Values {
				tags = append(tags, "geosite-"+strings.ToLower(value))
			}
			dnsRule["rule_set"] = tags
		default:
			continue
		}
		dnsRules = append(dnsRules, dnsRule)
	}
	return dnsRules
}

func singBoxDNSServerForAction(action proxynode.SubscriptionAction, hasProxy bool) string {
	if action == proxynode.SubscriptionProxy && hasProxy {
		return "proxy-dns"
	}
	return "local-dns"
}

func singBoxNode(node Node) (map[string]any, error) {
	outbound := map[string]any{"type": string(node.Protocol), "tag": node.Name, "server": node.Server, "server_port": node.Port}
	switch node.Protocol {
	case proxynode.ProtocolShadowsocks:
		outbound["method"] = node.Method
		outbound["password"] = node.ServerKey + ":" + node.Password
	case proxynode.ProtocolAnyTLS:
		outbound["password"] = node.Password
		outbound["tls"] = singBoxTLS(node)
	case proxynode.ProtocolHysteria2:
		outbound["password"] = node.Password
		outbound["tls"] = singBoxTLS(node)
		if node.UpMbps > 0 {
			outbound["up_mbps"] = node.UpMbps
		}
		if node.DownMbps > 0 {
			outbound["down_mbps"] = node.DownMbps
		}
		if node.ObfsType != "" {
			outbound["obfs"] = map[string]any{"type": node.ObfsType, "password": node.ObfsSecret}
		}
	default:
		return nil, errors.New("unsupported sing-box proxy protocol")
	}
	return outbound, nil
}

func singBoxTLS(node Node) map[string]any {
	tls := map[string]any{"enabled": true, "insecure": node.Insecure}
	if node.ServerName != "" {
		tls["server_name"] = node.ServerName
	}
	return tls
}

func singBoxRule(rule proxynode.SubscriptionRule) (map[string]any, error) {
	result := map[string]any{"action": "route", "outbound": actionName(rule.Action)}
	if rule.Match == proxynode.SubscriptionMatchGeoIP {
		tags := make([]string, 0, len(rule.Values))
		for _, value := range rule.Values {
			tags = append(tags, "geoip-"+strings.ToLower(value))
		}
		result["rule_set"] = tags
		return result, nil
	}
	if rule.Match == proxynode.SubscriptionMatchGeosite {
		tags := make([]string, 0, len(rule.Values))
		for _, value := range rule.Values {
			tags = append(tags, "geosite-"+strings.ToLower(value))
		}
		result["rule_set"] = tags
		return result, nil
	}
	field := map[proxynode.SubscriptionMatch]string{
		proxynode.SubscriptionMatchDomain: "domain", proxynode.SubscriptionMatchDomainSuffix: "domain_suffix",
		proxynode.SubscriptionMatchDomainKeyword: "domain_keyword", proxynode.SubscriptionMatchDomainRegex: "domain_regex",
		proxynode.SubscriptionMatchIPCIDR: "ip_cidr", proxynode.SubscriptionMatchSourceIPCIDR: "source_ip_cidr",
		proxynode.SubscriptionMatchDestinationPort: "port_range",
		proxynode.SubscriptionMatchSourcePort:      "source_port_range", proxynode.SubscriptionMatchNetwork: "network",
		proxynode.SubscriptionMatchProcessName: "process_name",
	}[rule.Match]
	if field == "" {
		return nil, errors.New("unsupported sing-box rule type")
	}
	result[field] = slices.Clone(rule.Values)
	return result, nil
}

func actionName(action proxynode.SubscriptionAction) string {
	switch action {
	case proxynode.SubscriptionDirect:
		return "Direct"
	case proxynode.SubscriptionReject:
		return "Reject"
	default:
		return "Proxy"
	}
}

func clashProtocol(protocol proxynode.Protocol) string {
	if protocol == proxynode.ProtocolShadowsocks {
		return "ss"
	}
	return string(protocol)
}

func yamlString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func csvField(value string) string {
	if !strings.ContainsAny(value, ",\"") {
		return value
	}
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func surgeField(value string) string {
	if !strings.ContainsAny(value, ",=\" \t") {
		return value
	}
	return `"` + strings.ReplaceAll(value, `"`, `\\"`) + `"`
}

func surgeName(value string) string {
	return surgeField(value)
}

func ValidateNode(node Node) error {
	serverValid := net.ParseIP(node.Server) != nil
	if !serverValid {
		normalized, err := pool.NormalizeSubscriptionDomain(node.Server)
		serverValid = err == nil && normalized != ""
	}
	if strings.TrimSpace(node.Name) == "" || !serverValid || node.Port < 1 || node.Port > 65535 || node.Password == "" {
		return fmt.Errorf("invalid subscription node %q", node.Name)
	}
	return nil
}
