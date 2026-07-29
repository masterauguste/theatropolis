package webui

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEnsureRequiredRouteSniffAddsLeadingActionForGeosite(t *testing.T) {
	t.Parallel()
	input := []byte(`{
		"inbounds": [],
		"route": {
			"rules": [{
				"auth_user": ["alice"],
				"rule_set": ["geosite-youtube"],
				"action": "route",
				"outbound": "proxy"
			}]
		}
	}`)
	encoded, err := ensureRequiredRouteSniff(input)
	if err != nil {
		t.Fatal(err)
	}
	rules := decodedRouteRules(t, encoded)
	if len(rules) != 2 || rules[0]["action"] != "sniff" ||
		rules[1]["outbound"] != "proxy" {
		t.Fatalf("normalized rules = %+v", rules)
	}
}

func TestEnsureRequiredRouteSniffLeavesIPOnlyRulesUnchanged(t *testing.T) {
	t.Parallel()
	input := []byte(`{"route":{"rules":[
		{"ip_cidr":["203.0.113.0/24"],"action":"route","outbound":"proxy"},
		{"rule_set":["geoip-us"],"action":"route","outbound":"proxy"}
	]}}`)
	encoded, err := ensureRequiredRouteSniff(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, input) {
		t.Fatalf("IP-only rules changed:\n%s", encoded)
	}
}

func TestEnsureRequiredRouteSniffDoesNotDuplicateExistingAction(t *testing.T) {
	t.Parallel()
	input := []byte(`{"route":{"rules":[
		{"action":"sniff","sniffer":["tls","http"]},
		{"domain_suffix":["youtube.com"],"action":"route","outbound":"proxy"}
	]}}`)
	encoded, err := ensureRequiredRouteSniff(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, input) {
		t.Fatalf("existing sniff action changed:\n%s", encoded)
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
