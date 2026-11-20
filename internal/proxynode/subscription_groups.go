package proxynode

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
)

func validateSubscriptionGroups(policy SubscriptionPolicy) error {
	if len(policy.Groups) > 64 {
		return fmt.Errorf("%w: too many proxy groups", ErrInvalidState)
	}
	groups := make(map[string]SubscriptionGroup, len(policy.Groups))
	names := map[string]bool{"proxy": true, "direct": true, "reject": true}
	for _, group := range policy.Groups {
		key := strings.ToLower(group.Name)
		if !validID(group.ID, "sgp_") || group.Name != strings.TrimSpace(group.Name) || group.Name == "" || len(group.Name) > 100 ||
			strings.ContainsAny(group.Name, ",=\"\\[]#;") || strings.ContainsFunc(group.Name, unicode.IsControl) || names[key] {
			return fmt.Errorf("%w: group names must be unique and cannot use reserved names or configuration punctuation", ErrInvalidState)
		}
		if _, exists := groups[group.ID]; exists {
			return fmt.Errorf("%w: duplicate proxy group", ErrInvalidState)
		}
		if group.Type != "select" && group.Type != "url-test" || len(group.Members) > 512 || !group.AllNodes && len(group.Members) == 0 {
			return fmt.Errorf("%w: choose a group type and at least one member", ErrInvalidState)
		}
		if group.Type == "url-test" && (group.Interval < 30 || group.Interval > 86400 || group.Tolerance < 1 || group.Tolerance > 10000) {
			return fmt.Errorf("%w: test interval must be 30–86400 seconds and tolerance 1–10000 ms", ErrInvalidState)
		}
		seen := make(map[SubscriptionAction]bool)
		for _, member := range group.Members {
			if !validSubscriptionAction(member) || seen[member] {
				return fmt.Errorf("%w: invalid or duplicate group member", ErrInvalidState)
			}
			seen[member] = true
		}
		groups[group.ID], names[key] = group, true
	}
	checkReference := func(action SubscriptionAction) error {
		if strings.HasPrefix(string(action), "group:") {
			if _, exists := groups[strings.TrimPrefix(string(action), "group:")]; !exists {
				return fmt.Errorf("%w: proxy group does not exist", ErrInvalidState)
			}
		}
		return nil
	}
	if err := checkReference(policy.DefaultAction); err != nil {
		return err
	}
	for _, rule := range policy.Rules {
		if err := checkReference(rule.Action); err != nil {
			return err
		}
	}
	visiting, visited := make(map[string]bool), make(map[string]bool)
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return fmt.Errorf("%w: proxy groups cannot contain a reference loop", ErrInvalidState)
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		for _, member := range groups[id].Members {
			if err := checkReference(member); err != nil {
				return err
			}
			if strings.HasPrefix(string(member), "group:") {
				if err := visit(strings.TrimPrefix(string(member), "group:")); err != nil {
					return err
				}
			}
		}
		visiting[id], visited[id] = false, true
		return nil
	}
	for id := range groups {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SaveSubscriptionGroup(group SubscriptionGroup) (SubscriptionGroup, error) {
	creating := group.ID == ""
	if creating {
		id, err := randomID("sgp")
		if err != nil {
			return SubscriptionGroup{}, err
		}
		group.ID = id
	}
	group.Name = strings.TrimSpace(group.Name)
	group.Members = slices.Clone(group.Members)
	if group.Type == "select" {
		group.Interval, group.Tolerance = 0, 0
	}
	err := s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		index := slices.IndexFunc(policy.Groups, func(existing SubscriptionGroup) bool { return existing.ID == group.ID })
		if creating {
			policy.Groups = append(policy.Groups, group)
		} else if index >= 0 {
			policy.Groups[index] = group
		} else {
			return ErrNotFound
		}
		return validateSubscriptionGroups(*policy)
	})
	group.Members = slices.Clone(group.Members)
	return group, err
}

// DeleteSubscriptionGroup replaces every incoming reference atomically. The
// caller chooses the replacement explicitly; no rule silently changes to Direct.
func (s *Store) DeleteSubscriptionGroup(id string, replacement SubscriptionAction) error {
	if !validSubscriptionAction(replacement) || replacement == SubscriptionAction("group:"+id) {
		return ErrInvalidState
	}
	return s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		index := slices.IndexFunc(policy.Groups, func(group SubscriptionGroup) bool { return group.ID == id })
		if index < 0 {
			return ErrNotFound
		}
		target := SubscriptionAction("group:" + id)
		policy.Groups = slices.Delete(policy.Groups, index, index+1)
		if policy.DefaultAction == target {
			policy.DefaultAction = replacement
		}
		for i := range policy.Rules {
			if policy.Rules[i].Action == target {
				policy.Rules[i].Action = replacement
			}
		}
		for i := range policy.Groups {
			members := make([]SubscriptionAction, 0, len(policy.Groups[i].Members))
			for _, member := range policy.Groups[i].Members {
				if member == target {
					member = replacement
				}
				if !slices.Contains(members, member) {
					members = append(members, member)
				}
			}
			policy.Groups[i].Members = members
		}
		return validateSubscriptionGroups(*policy)
	})
}

func (s *Store) SetSubscriptionRuleAction(id string, action SubscriptionAction) error {
	if !validSubscriptionAction(action) {
		return ErrInvalidState
	}
	return s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		for i := range policy.Rules {
			if policy.Rules[i].ID == id {
				policy.Rules[i].Action = action
				return nil
			}
		}
		return ErrNotFound
	})
}

func newProxyCopyGroup(name string) (SubscriptionGroup, error) {
	id, err := randomID("sgp")
	if err != nil {
		return SubscriptionGroup{}, err
	}
	return SubscriptionGroup{
		ID:       id,
		Name:     strings.TrimSpace(name),
		Type:     "select",
		AllNodes: true,
		Members:  []SubscriptionAction{SubscriptionProxy, SubscriptionDirect, SubscriptionReject},
	}, nil
}

// AddSubscriptionRuleWithNewGroup atomically creates a manual proxy group
// copied from PROXY (all available proxies plus Direct and Reject) and appends
// a rule targeting that group. If either the group or the rule fails validation
// nothing is persisted.
func (s *Store) AddSubscriptionRuleWithNewGroup(input SubscriptionRuleInput, groupName string) (SubscriptionRule, SubscriptionGroup, error) {
	input = normalizeSubscriptionRuleInput(input)
	group, err := newProxyCopyGroup(groupName)
	if err != nil {
		return SubscriptionRule{}, SubscriptionGroup{}, err
	}
	ruleID, err := randomID("sru")
	if err != nil {
		return SubscriptionRule{}, SubscriptionGroup{}, err
	}
	var createdRule SubscriptionRule
	err = s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		createdRule = SubscriptionRule{
			ID:        ruleID,
			Order:     len(policy.Rules),
			Match:     input.Match,
			Values:    input.Values,
			NoResolve: input.NoResolve,
			Action:    SubscriptionAction("group:" + group.ID),
		}
		candidate := *policy
		candidate.Groups = append(slices.Clone(policy.Groups), group)
		candidate.Rules = append(slices.Clone(policy.Rules), createdRule)
		if err := validateSubscriptionPolicy(candidate); err != nil {
			return err
		}
		policy.Groups = candidate.Groups
		policy.Rules = candidate.Rules
		return nil
	})
	if err != nil {
		return SubscriptionRule{}, SubscriptionGroup{}, err
	}
	group.Members = slices.Clone(group.Members)
	return createdRule, group, nil
}

// UpdateSubscriptionRuleWithNewGroup atomically creates a manual proxy group
// copied from PROXY and retargets an existing rule to it.
func (s *Store) UpdateSubscriptionRuleWithNewGroup(ruleID string, input SubscriptionRuleInput, groupName string) (SubscriptionGroup, error) {
	input = normalizeSubscriptionRuleInput(input)
	group, err := newProxyCopyGroup(groupName)
	if err != nil {
		return SubscriptionGroup{}, err
	}
	err = s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		index := slices.IndexFunc(policy.Rules, func(rule SubscriptionRule) bool { return rule.ID == ruleID })
		if index < 0 {
			return ErrNotFound
		}
		candidate := *policy
		candidate.Groups = append(slices.Clone(policy.Groups), group)
		candidate.Rules = slices.Clone(policy.Rules)
		candidate.Rules[index].Match = input.Match
		candidate.Rules[index].Values = input.Values
		candidate.Rules[index].NoResolve = input.NoResolve
		candidate.Rules[index].Action = SubscriptionAction("group:" + group.ID)
		if err := validateSubscriptionPolicy(candidate); err != nil {
			return err
		}
		policy.Groups = candidate.Groups
		policy.Rules = candidate.Rules
		return nil
	})
	if err != nil {
		return SubscriptionGroup{}, err
	}
	group.Members = slices.Clone(group.Members)
	return group, nil
}
