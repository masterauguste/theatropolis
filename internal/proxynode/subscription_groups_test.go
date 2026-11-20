package proxynode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestSchemaEighteenSubscriptionPolicyMigrationPreservesRouting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	policy := SubscriptionPolicy{DefaultAction: SubscriptionDirect, UpdatedAt: time.Now().UTC(), Rules: []SubscriptionRule{
		{ID: "sru_012345678901234567890123", Match: SubscriptionMatchDomain, Values: []string{"example.com"}, Action: SubscriptionProxy},
	}}
	build := testBuild()
	build.RecordedAt = policy.UpdatedAt
	legacy := envelope{Schema: SchemaID, SchemaVersion: 18, LastUsedBy: build, Data: State{UserRevision: 1, SubscriptionPolicy: policy}}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.SubscriptionPolicy(), policy) {
		t.Fatal("migration changed existing routing")
	}
	if _, err := s.SaveSubscriptionGroup(SubscriptionGroup{Name: "New", Type: "select", AllNodes: true}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved envelope
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.SchemaVersion != 19 || saved.Data.SubscriptionPolicy.DefaultAction != SubscriptionDirect {
		t.Fatal("new schema did not preserve existing default")
	}
}

func TestSubscriptionGroupLifecycleAndAtomicReferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	before := s.Snapshot()
	a, err := s.SaveSubscriptionGroup(SubscriptionGroup{Name: "Streaming", Type: "select", AllNodes: true})
	if err != nil {
		t.Fatal(err)
	}
	target := SubscriptionAction("group:" + a.ID)
	b, err := s.SaveSubscriptionGroup(SubscriptionGroup{Name: "Fastest", Type: "url-test", Members: []SubscriptionAction{target}, Interval: 300, Tolerance: 50})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := s.AddSubscriptionRule(SubscriptionRuleInput{Match: SubscriptionMatchDomainSuffix, Values: []string{"example.com"}, Action: target})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSubscriptionDefault(target); err != nil {
		t.Fatal(err)
	}
	a.Name = "Renamed"
	if _, err := s.SaveSubscriptionGroup(a); err != nil {
		t.Fatal(err)
	}
	if s.SubscriptionPolicy().Rules[0].Action != target {
		t.Fatal("rename changed target")
	}
	snapshot := s.Snapshot()
	a.Members = []SubscriptionAction{SubscriptionAction("group:" + b.ID)}
	if _, err := s.SaveSubscriptionGroup(a); err == nil {
		t.Fatal("accepted group cycle")
	}
	if !reflect.DeepEqual(s.Snapshot(), snapshot) {
		t.Fatal("invalid group mutation was persisted")
	}
	if err := s.DeleteSubscriptionGroup(a.ID, SubscriptionAction("group:"+b.ID)); err == nil {
		t.Fatal("delete replacement created self-reference")
	}
	if err := s.DeleteSubscriptionGroup(a.ID, SubscriptionReject); err != nil {
		t.Fatal(err)
	}
	policy := s.SubscriptionPolicy()
	if policy.DefaultAction != SubscriptionReject || policy.Rules[0].Action != SubscriptionReject || policy.Groups[0].Members[0] != SubscriptionReject {
		t.Fatalf("references not replaced: %+v", policy)
	}
	if err := s.SetSubscriptionRuleAction(rule.ID, SubscriptionDirect); err != nil {
		t.Fatal(err)
	}
	if got := s.SubscriptionPolicy().Rules[0]; got.Match != rule.Match || !reflect.DeepEqual(got.Values, rule.Values) {
		t.Fatal("target-only update changed match")
	}
	if s.Snapshot().Revision != before.Revision || s.Snapshot().AppliedRevision != before.AppliedRevision {
		t.Fatal("subscription mutation changed topology")
	}
	reopened, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopened.SubscriptionPolicy(), s.SubscriptionPolicy()) {
		t.Fatal("group policy was not durable")
	}
}

func TestSubscriptionGroupValidation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DIRECT", "Proxy", "reject", "bad,name", "bad\nname", "bad=name", "bad[section]"} {
		if _, err := s.SaveSubscriptionGroup(SubscriptionGroup{Name: name, Type: "select", AllNodes: true}); err == nil {
			t.Errorf("accepted unsafe name %q", name)
		}
	}
	group, err := s.SaveSubscriptionGroup(SubscriptionGroup{Name: "日本", Type: "select", AllNodes: true})
	if err != nil {
		t.Fatal(err)
	}
	group.ID = ""
	if _, err := s.SaveSubscriptionGroup(group); err == nil {
		t.Fatal("accepted duplicate name")
	}
	for _, target := range []SubscriptionAction{"group:sgp_012345678901234567890123", "node:bogus", "node:pn_012345678901234567890123:bogus", "resolved:unsafe"} {
		if err := s.SetSubscriptionDefault(target); err == nil {
			t.Errorf("accepted invalid target %q", target)
		}
	}
	for _, target := range []SubscriptionAction{"node:pn_012345678901234567890123", "node:pn_012345678901234567890123:ipv4", "node:pn_012345678901234567890123:ipv6"} {
		if err := s.SetSubscriptionDefault(target); err != nil {
			t.Errorf("rejected retained Node reference %q: %v", target, err)
		}
	}
}
