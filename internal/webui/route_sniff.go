package webui

import (
	"bytes"
	"encoding/json"
	"errors"
)

var sniffDependentRouteFields = [...]string{
	"protocol",
	"client",
	"domain",
	"domain_suffix",
	"domain_keyword",
	"domain_regex",
}

var resolveDependentRouteFields = [...]string{
	"ip_version",
	"ip_is_private",
	"ip_cidr",
	"geoip",
}

type routeMetadataNeeds struct {
	sniff   bool
	resolve bool
}

// ensureRequiredRouteActions inserts sing-box metadata actions at their first
// point of use. Earlier final rules can therefore route without unnecessary
// sniffing or DNS resolution. Configurations that need no additional action
// are left byte-for-byte unchanged.
func ensureRequiredRouteActions(config []byte) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(config, &document); err != nil {
		return nil, err
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(document["route"], &route); err != nil || route == nil {
		return config, nil
	}
	var rules []json.RawMessage
	if err := json.Unmarshal(route["rules"], &rules); err != nil {
		return config, nil
	}
	normalized := make([]json.RawMessage, 0, len(rules)+2)
	seenSniff := false
	seenResolve := false
	futureSniff := firstGlobalRouteMetadataAction(rules, "sniff")
	futureResolve := firstGlobalRouteMetadataAction(rules, "resolve")
	relocatedSniff := -1
	relocatedResolve := -1
	changed := false
	for index, raw := range rules {
		if index == relocatedSniff || index == relocatedResolve {
			continue
		}
		if globalRouteMetadataAction(raw, "sniff") {
			seenSniff = true
		}
		if globalRouteMetadataAction(raw, "resolve") {
			seenResolve = true
		}
		needs := rawRouteMetadataNeeds(raw)
		if needs.resolve && !seenResolve {
			action := json.RawMessage(`{"action":"resolve"}`)
			if futureResolve > index {
				action = rules[futureResolve]
				relocatedResolve = futureResolve
			}
			normalized = append(normalized, action)
			seenResolve = true
			changed = true
		}
		if needs.sniff && !seenSniff {
			action := json.RawMessage(`{"action":"sniff"}`)
			if futureSniff > index {
				action = rules[futureSniff]
				relocatedSniff = futureSniff
			}
			normalized = append(normalized, action)
			seenSniff = true
			changed = true
		}
		normalized = append(normalized, raw)
	}
	if !changed {
		return config, nil
	}
	encodedRules, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	route["rules"] = encodedRules
	encodedRoute, err := json.Marshal(route)
	if err != nil {
		return nil, err
	}
	document["route"] = encodedRoute
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxConfigurationBytes {
		return nil, errors.New("The configuration is too large after adding required routing metadata actions.")
	}
	return encoded, nil
}

func firstGlobalRouteMetadataAction(rules []json.RawMessage, action string) int {
	for index, raw := range rules {
		if globalRouteMetadataAction(raw, action) {
			return index
		}
	}
	return -1
}

func rawRouteMetadataNeeds(raw json.RawMessage) routeMetadataNeeds {
	var rule map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rule); err != nil || rule == nil {
		return routeMetadataNeeds{}
	}
	var action string
	_ = json.Unmarshal(rule["action"], &action)
	if action != "" && action != "route" {
		return routeMetadataNeeds{}
	}
	needs := routeMetadataNeeds{}
	for _, field := range sniffDependentRouteFields {
		if value, exists := rule[field]; exists &&
			!bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			needs.sniff = true
		}
	}
	for _, field := range resolveDependentRouteFields {
		if value, exists := rule[field]; exists &&
			!bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			needs.resolve = true
		}
	}
	rawRuleSet, exists := rule["rule_set"]
	if !exists {
		return needs
	}
	var tags []string
	if err := json.Unmarshal(rawRuleSet, &tags); err != nil {
		var tag string
		if err := json.Unmarshal(rawRuleSet, &tag); err != nil {
			return needs
		}
		tags = []string{tag}
	}
	for _, tag := range tags {
		switch {
		case len(tag) >= len("geoip-") && tag[:len("geoip-")] == "geoip-":
			needs.resolve = true
		case len(tag) >= len("geosite-") && tag[:len("geosite-")] == "geosite-":
			needs.sniff = true
		default:
			needs.sniff = true
			needs.resolve = true
		}
	}
	return needs
}

func globalRouteMetadataAction(raw json.RawMessage, want string) bool {
	var rule map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rule); err != nil {
		return false
	}
	var action string
	if err := json.Unmarshal(rule["action"], &action); err != nil || action != want {
		return false
	}
	for _, field := range append([]string{
		"inbound", "auth_user", "network", "source_ip_cidr", "source_ip_is_private",
		"source_port", "source_port_range", "port", "port_range", "process_name",
		"process_path", "process_path_regex", "package_name", "user", "user_id",
		"clash_mode", "wifi_ssid", "wifi_bssid", "rule_set_ip_cidr_match_source", "invert",
	}, append(sniffDependentRouteFields[:], resolveDependentRouteFields[:]...)...) {
		if _, exists := rule[field]; exists {
			return false
		}
	}
	if _, exists := rule["rule_set"]; exists {
		return false
	}
	return true
}
