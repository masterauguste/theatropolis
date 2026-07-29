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

// ensureRequiredRouteSniff adds the sing-box 1.14 sniff action before rules
// whose domain or protocol metadata may not be present when a client sends an
// already-resolved destination IP. It leaves configurations that do not need
// sniffing byte-for-byte unchanged.
func ensureRequiredRouteSniff(config []byte) ([]byte, error) {
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
	needsSniff := false
	for _, raw := range rules {
		if routeRuleNeedsSniff(raw) {
			needsSniff = true
			break
		}
	}
	if !needsSniff || hasLeadingGlobalSniff(rules) {
		return config, nil
	}
	rules = append([]json.RawMessage{json.RawMessage(`{"action":"sniff"}`)}, rules...)
	encodedRules, err := json.Marshal(rules)
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
		return nil, errors.New("The configuration is too large after adding required protocol sniffing.")
	}
	return encoded, nil
}

func routeRuleNeedsSniff(raw json.RawMessage) bool {
	var rule map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rule); err != nil || rule == nil {
		return false
	}
	var action string
	_ = json.Unmarshal(rule["action"], &action)
	if action != "" && action != "route" {
		return false
	}
	for _, field := range sniffDependentRouteFields {
		if value, exists := rule[field]; exists &&
			!bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return true
		}
	}
	rawRuleSet, exists := rule["rule_set"]
	if !exists {
		return false
	}
	var tags []string
	if err := json.Unmarshal(rawRuleSet, &tags); err != nil {
		var tag string
		if err := json.Unmarshal(rawRuleSet, &tag); err != nil {
			return false
		}
		tags = []string{tag}
	}
	for _, tag := range tags {
		if len(tag) < len("geoip-") || tag[:len("geoip-")] != "geoip-" {
			return true
		}
	}
	return false
}

func hasLeadingGlobalSniff(rules []json.RawMessage) bool {
	if len(rules) == 0 {
		return false
	}
	var rule map[string]json.RawMessage
	if err := json.Unmarshal(rules[0], &rule); err != nil {
		return false
	}
	var action string
	if err := json.Unmarshal(rule["action"], &action); err != nil || action != "sniff" {
		return false
	}
	for field := range rule {
		switch field {
		case "action", "sniffer", "timeout":
		default:
			return false
		}
	}
	return true
}
