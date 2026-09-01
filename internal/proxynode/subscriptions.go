package proxynode

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

type SubscriptionRuleInput struct {
	Match     SubscriptionMatch
	Values    []string
	NoResolve bool
	Action    SubscriptionAction
}

func EffectiveSubscriptionAddressMode(mode SubscriptionAddressMode) SubscriptionAddressMode {
	if mode == "" {
		return SubscriptionAddressDual
	}
	return mode
}

// SetProxyNodeSubscriptionAddressMode changes only public configuration
// subscription rendering. It deliberately uses the user/subscription plane so
// no topology deployment or sing-box restart is scheduled.
func (s *Store) SetProxyNodeSubscriptionAddressMode(nodeID string, mode SubscriptionAddressMode) error {
	if mode != SubscriptionAddressDual && mode != SubscriptionAddressIPv4 && mode != SubscriptionAddressIPv6 {
		return fmt.Errorf("%w: invalid configuration subscription address mode", ErrInvalidState)
	}
	return s.mutateUserProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		node.SubscriptionAddressMode = mode
		return nil
	})
}

// SubscriptionProjection is the smallest consistent state snapshot needed to
// render one user's public subscription. It deliberately excludes unrelated
// users and Proxy Nodes so public polling cost scales with the caller's actual
// access rather than the full master state.
type SubscriptionProjection struct {
	User              User
	Policy            SubscriptionPolicy
	ProxyNodes        []ProxyNode
	AppliedProxyNodes map[string]ProxyNode
}

func (s *Store) SubscriptionProjection(userID string) (SubscriptionProjection, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userIndex, exists := s.userIndex[userID]
	if !exists || userIndex < 0 || userIndex >= len(s.state.Users) {
		return SubscriptionProjection{}, false
	}
	projection := SubscriptionProjection{
		User:              cloneState(State{Users: []User{s.state.Users[userIndex]}}).Users[0],
		Policy:            cloneState(State{SubscriptionPolicy: s.state.SubscriptionPolicy}).SubscriptionPolicy,
		AppliedProxyNodes: make(map[string]ProxyNode),
	}
	if projection.Policy.DefaultAction == "" {
		projection.Policy.DefaultAction = SubscriptionProxy
	}
	for _, node := range s.state.ProxyNodes {
		if !slices.ContainsFunc(node.Memberships, func(membership Membership) bool { return membership.UserID == userID }) {
			continue
		}
		projection.ProxyNodes = append(projection.ProxyNodes, cloneProxyNode(node))
	}
	for _, node := range s.state.AppliedProxyNodes {
		if slices.ContainsFunc(projection.ProxyNodes, func(candidate ProxyNode) bool { return candidate.ID == node.ID }) {
			projection.AppliedProxyNodes[node.ID] = cloneProxyNode(node)
		}
	}
	return projection, true
}

func (s *Store) UserBySubscriptionToken(token string) (User, bool) {
	token = strings.TrimSpace(token)
	if !validID(token, "sub_") {
		return User{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	index, exists := s.subscriptionIndex[token]
	if !exists || index < 0 || index >= len(s.state.Users) {
		return User{}, false
	}
	return cloneState(State{Users: []User{s.state.Users[index]}}).Users[0], true
}

func (s *Store) RotateUserSubscription(userID string) (UserSubscription, error) {
	if userID == SystemAdministratorUserID {
		return UserSubscription{}, fmt.Errorf("%w: administrator subscription is immutable", ErrConflict)
	}
	var updated UserSubscription
	err := s.mutateUser(func(state *State) error {
		var err error
		updated, err = s.rotateUserSubscriptionToken(state, userID)
		return err
	})
	return updated, err
}

// ResetUserSubscriptionAndCredentials rotates the subscription bearer token
// and every Proxy Node Membership credential atomically. The new token is
// never persisted unless every credential can also be generated and stored.
func (s *Store) ResetUserSubscriptionAndCredentials(userID string) (UserSubscription, int, error) {
	if userID == SystemAdministratorUserID {
		return UserSubscription{}, 0, fmt.Errorf("%w: administrator subscription is immutable", ErrConflict)
	}
	var updated UserSubscription
	rotated := 0
	err := s.mutateUser(func(state *State) error {
		var err error
		updated, err = s.rotateUserSubscriptionToken(state, userID)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		for nodeIndex := range state.ProxyNodes {
			node := &state.ProxyNodes[nodeIndex]
			if membershipForUser(node, userID) == nil {
				continue
			}
			if err := resetMembershipCredential(state, node, userID); err != nil {
				return err
			}
			node.UpdatedAt = now
			rotated++
		}
		return nil
	})
	return updated, rotated, err
}

func (s *Store) rotateUserSubscriptionToken(state *State, userID string) (UserSubscription, error) {
	index := slices.IndexFunc(state.Users, func(user User) bool { return user.ID == userID })
	if index < 0 {
		return UserSubscription{}, ErrNotFound
	}
	for attempts := 0; attempts < 3; attempts++ {
		token, err := randomID("sub")
		if err != nil {
			return UserSubscription{}, err
		}
		if slices.ContainsFunc(state.Users, func(user User) bool { return user.Subscription.Token == token }) {
			continue
		}
		now := s.now().UTC()
		state.Users[index].Subscription.Token = token
		state.Users[index].Subscription.UpdatedAt = now
		state.Users[index].UpdatedAt = now
		return state.Users[index].Subscription, nil
	}
	return UserSubscription{}, errors.New("could not allocate a unique subscription token")
}

func (s *Store) RevokeUserSubscription(userID string) error {
	if userID == SystemAdministratorUserID {
		return fmt.Errorf("%w: administrator subscription is immutable", ErrConflict)
	}
	return s.mutateUser(func(state *State) error {
		for index := range state.Users {
			if state.Users[index].ID != userID {
				continue
			}
			now := s.now().UTC()
			state.Users[index].Subscription.Token = ""
			state.Users[index].Subscription.UpdatedAt = now
			state.Users[index].UpdatedAt = now
			return nil
		}
		return ErrNotFound
	})
}

func (s *Store) SubscriptionPolicy() SubscriptionPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	policy := cloneState(State{SubscriptionPolicy: s.state.SubscriptionPolicy}).SubscriptionPolicy
	if policy.DefaultAction == "" {
		policy.DefaultAction = SubscriptionProxy
	}
	return policy
}

func (s *Store) SetSubscriptionDefault(action SubscriptionAction) error {
	if !validSubscriptionAction(action) {
		return ErrInvalidState
	}
	return s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		policy.DefaultAction = action
		return nil
	})
}

func (s *Store) AddSubscriptionRule(input SubscriptionRuleInput) (SubscriptionRule, error) {
	input = normalizeSubscriptionRuleInput(input)
	ruleID, err := randomID("sru")
	if err != nil {
		return SubscriptionRule{}, err
	}
	var created SubscriptionRule
	err = s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		created = SubscriptionRule{
			ID: ruleID, Order: len(policy.Rules), Match: input.Match,
			Values: input.Values, NoResolve: input.NoResolve, Action: input.Action,
		}
		candidate := *policy
		candidate.Rules = append(slices.Clone(policy.Rules), created)
		if err := validateSubscriptionPolicy(candidate); err != nil {
			return err
		}
		policy.Rules = candidate.Rules
		return nil
	})
	return created, err
}

func (s *Store) UpdateSubscriptionRule(ruleID string, input SubscriptionRuleInput) error {
	input = normalizeSubscriptionRuleInput(input)
	return s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		index := slices.IndexFunc(policy.Rules, func(rule SubscriptionRule) bool { return rule.ID == ruleID })
		if index < 0 {
			return ErrNotFound
		}
		candidate := *policy
		candidate.Rules = slices.Clone(policy.Rules)
		candidate.Rules[index].Match = input.Match
		candidate.Rules[index].Values = input.Values
		candidate.Rules[index].NoResolve = input.NoResolve
		candidate.Rules[index].Action = input.Action
		if err := validateSubscriptionPolicy(candidate); err != nil {
			return err
		}
		policy.Rules = candidate.Rules
		return nil
	})
}

func (s *Store) DeleteSubscriptionRule(ruleID string) error {
	return s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		before := len(policy.Rules)
		policy.Rules = slices.DeleteFunc(policy.Rules, func(rule SubscriptionRule) bool { return rule.ID == ruleID })
		if len(policy.Rules) == before {
			return ErrNotFound
		}
		reorderSubscriptionRules(policy.Rules)
		return nil
	})
}

func (s *Store) MoveSubscriptionRule(ruleID string, direction int) error {
	if direction != -1 && direction != 1 {
		return ErrInvalidState
	}
	return s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		sort.SliceStable(policy.Rules, func(left, right int) bool { return policy.Rules[left].Order < policy.Rules[right].Order })
		index := slices.IndexFunc(policy.Rules, func(rule SubscriptionRule) bool { return rule.ID == ruleID })
		target := index + direction
		if index < 0 {
			return ErrNotFound
		}
		if target < 0 || target >= len(policy.Rules) {
			return ErrConflict
		}
		policy.Rules[index], policy.Rules[target] = policy.Rules[target], policy.Rules[index]
		reorderSubscriptionRules(policy.Rules)
		return nil
	})
}

func (s *Store) ReorderSubscriptionRules(ruleIDs []string) error {
	return s.updateSubscriptionPolicy(func(policy *SubscriptionPolicy) error {
		if len(ruleIDs) != len(policy.Rules) {
			return ErrInvalidState
		}
		byID := make(map[string]SubscriptionRule, len(policy.Rules))
		for _, rule := range policy.Rules {
			byID[rule.ID] = rule
		}
		reordered := make([]SubscriptionRule, 0, len(ruleIDs))
		for _, ruleID := range ruleIDs {
			rule, exists := byID[ruleID]
			if !exists {
				return ErrInvalidState
			}
			delete(byID, ruleID)
			reordered = append(reordered, rule)
		}
		if len(byID) != 0 {
			return ErrInvalidState
		}
		reorderSubscriptionRules(reordered)
		policy.Rules = reordered
		return nil
	})
}

func (s *Store) updateSubscriptionPolicy(mutation func(*SubscriptionPolicy) error) error {
	return s.mutateUser(func(state *State) error {
		if state.SubscriptionPolicy.DefaultAction == "" {
			state.SubscriptionPolicy.DefaultAction = SubscriptionProxy
		}
		state.SubscriptionPolicy.UpdatedAt = s.now().UTC()
		if err := mutation(&state.SubscriptionPolicy); err != nil {
			return err
		}
		return nil
	})
}

func normalizeSubscriptionRuleInput(input SubscriptionRuleInput) SubscriptionRuleInput {
	values := make([]string, 0, len(input.Values))
	for _, value := range input.Values {
		value = strings.TrimSpace(value)
		if value != "" {
			values = append(values, value)
		}
	}
	input.Values = values
	return input
}

func reorderSubscriptionRules(rules []SubscriptionRule) {
	for index := range rules {
		rules[index].Order = index
	}
}
