package webui

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEnsureRequiredRouteActionsAddsSniffAtFirstUse(t *testing.T) {
	t.Parallel()
	input := []byte(`{
		"inbounds": [],
		"route": {
			"rules": [{"network":"udp","action":"route","outbound":"early"},{
				"auth_user": ["alice"],
				"rule_set": ["geosite-youtube"],
				"action": "route",
				"outbound": "proxy"
			}]
		}
	}`)
	encoded, err := ensureRequiredRouteActions(input)
	if err != nil {
		t.Fatal(err)
	}
	rules := decodedRouteRules(t, encoded)
	if len(rules) != 3 || rules[0]["outbound"] != "early" ||
		rules[1]["action"] != "sniff" || rules[2]["outbound"] != "proxy" {
		t.Fatalf("normalized rules = %+v", rules)
	}
}

func TestEnsureRequiredRouteActionsAddsResolveForIPRules(t *testing.T) {
	t.Parallel()
	input := []byte(`{"route":{"rules":[
		{"ip_cidr":["203.0.113.0/24"],"action":"route","outbound":"proxy"},
		{"rule_set":["geoip-us"],"action":"route","outbound":"proxy"}
	]}}`)
	encoded, err := ensureRequiredRouteActions(input)
	if err != nil {
		t.Fatal(err)
	}
	rules := decodedRouteRules(t, encoded)
	if len(rules) != 3 || rules[0]["action"] != "resolve" || rules[1]["outbound"] != "proxy" {
		t.Fatalf("normalized rules = %+v", rules)
	}
}

func TestEnsureRequiredRouteActionsDoesNotDuplicateExistingActions(t *testing.T) {
	t.Parallel()
	input := []byte(`{"route":{"rules":[
		{"action":"sniff","sniffer":["tls","http"]},
		{"action":"resolve","strategy":"prefer_ipv4"},
		{"ip_cidr":["203.0.113.0/24"],"action":"route","outbound":"proxy"},
		{"domain_suffix":["youtube.com"],"action":"route","outbound":"proxy"}
	]}}`)
	encoded, err := ensureRequiredRouteActions(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, input) {
		t.Fatalf("existing sniff action changed:\n%s", encoded)
	}
}

func TestEnsureRequiredRouteActionsAddsBothForCustomRuleSet(t *testing.T) {
	t.Parallel()
	input := []byte(`{"route":{"rules":[
		{"rule_set":["private-custom"],"action":"route","outbound":"proxy"}
	]}}`)
	encoded, err := ensureRequiredRouteActions(input)
	if err != nil {
		t.Fatal(err)
	}
	rules := decodedRouteRules(t, encoded)
	if len(rules) != 3 || rules[0]["action"] != "resolve" ||
		rules[1]["action"] != "sniff" || rules[2]["outbound"] != "proxy" {
		t.Fatalf("normalized rules = %+v", rules)
	}
}

func TestEnsureRequiredRouteActionsMovesLaterConfiguredAction(t *testing.T) {
	t.Parallel()
	input := []byte(`{"route":{"rules":[
		{"ip_cidr":["203.0.113.0/24"],"action":"route","outbound":"proxy"},
		{"action":"resolve","strategy":"ipv4_only"}
	]}}`)
	encoded, err := ensureRequiredRouteActions(input)
	if err != nil {
		t.Fatal(err)
	}
	rules := decodedRouteRules(t, encoded)
	if len(rules) != 2 || rules[0]["action"] != "resolve" ||
		rules[0]["strategy"] != "ipv4_only" || rules[1]["outbound"] != "proxy" {
		t.Fatalf("normalized rules = %+v", rules)
	}
}

func TestEnsureRequiredRouteActionsLeavesMetadataFreeRulesUnchanged(t *testing.T) {
	t.Parallel()
	input := []byte(`{"route":{"rules":[{"network":"udp","action":"route","outbound":"proxy"}]}}`)
	encoded, err := ensureRequiredRouteActions(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, input) {
		t.Fatalf("metadata-free rules changed:\n%s", encoded)
	}
}

func decodedRouteRules(t *testing.T, encoded []byte) []map[string]any {
	t.Helper()
	var document struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	return document.Route.Rules
}
