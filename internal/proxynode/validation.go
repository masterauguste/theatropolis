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
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	maxStateBytes = 16 << 20
	maxValueBytes = 1024
	// Proxy Node and end-user management names are display names rather than
	// resource or login identifiers. The public mutation contract matches the
	// browser editor; four bytes per rune is the maximum UTF-8 representation.
	maxDisplayNameRunes = 60
	maxDisplayNameBytes = maxDisplayNameRunes * utf8.UTFMax
	// Before display names were introduced the backend accepted as many as 96
	// ASCII identifier characters. Keep that exact persisted-state allowance so
	// an older Master can still start, without letting a crafted mutation create
	// a name that its UI cannot subsequently edit.
	maxLegacyDisplayNameBytes = 96
	// Branch duplication and the schema-v4 migration clone downstream trees.
	// Keep malformed or pathological state from causing unbounded expansion.
	maxTopologyEntities = 10_000
)

var (
	ErrNotFound            = errors.New("proxy node resource not found")
	ErrConflict            = errors.New("proxy node resource conflicts with existing state")
	ErrAgentReferenced     = fmt.Errorf("%w: Agent is referenced by Proxy Node topology", ErrConflict)
	ErrInvalidState        = errors.New("invalid proxy node state")
	ErrNewerSchema         = errors.New("proxy node state uses a newer schema")
	ErrUnsafeStorage       = errors.New("unsafe proxy node storage")
	legacyNamePattern      = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._-]{0,95}\z`)
	agentIDPattern         = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z`)
	idPattern              = regexp.MustCompile(`\A[a-z]{2,4}_[A-Za-z0-9_-]{20,32}\z`)
	ruleSetTagPattern      = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z`)
	subscriptionGeoPattern = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._@!-]{0,127}\z`)
)

func validateState(state State) error {
	if state.UserRevision == 0 || state.AppliedRevision > state.Revision {
		return fmt.Errorf("%w: invalid configuration-plane revisions", ErrInvalidState)
	}
	if err := validateStateCore(state); err != nil {
		return err
	}
	if err := validateSubscriptionPolicy(state.SubscriptionPolicy); err != nil {
		return fmt.Errorf("%w: invalid universal subscription policy: %v", ErrInvalidState, err)
	}
	applied := State{
		Revision: state.AppliedRevision, UserRevision: state.UserRevision,
		AppliedRevision: state.AppliedRevision, Users: state.Users,
		ProxyNodes: state.AppliedProxyNodes,
	}
	if err := validateStateCore(applied); err != nil {
		return fmt.Errorf("%w: invalid applied topology: %v", ErrInvalidState, err)
	}
	for _, node := range state.AppliedProxyNodes {
		if len(node.Memberships) != 0 {
			return fmt.Errorf("%w: applied topology contains memberships", ErrInvalidState)
		}
	}
	return nil
}

// validateStoredState adds invariants that belong to the persisted product
// model but are intentionally absent from user-agnostic topology projections.
func validateStoredState(state State) error {
	if err := validateState(state); err != nil {
		return err
	}
	administrators := 0
	for _, user := range state.Users {
		if IsSystemAdministrator(user) && user.Name == SystemAdministratorUserName && user.Subscription.Token != "" {
			administrators++
		}
	}
	if !state.AdministratorProxyAccessEnabled {
		if administrators != 0 || slices.ContainsFunc(state.Users, func(user User) bool {
			return user.ID == SystemAdministratorUserID || user.Role == UserRoleAdministrator
		}) {
			return fmt.Errorf("%w: disabled administrator access retains a system administrator", ErrInvalidState)
		}
		for _, node := range state.ProxyNodes {
			if slices.ContainsFunc(node.Memberships, func(membership Membership) bool {
				return membership.UserID == SystemAdministratorUserID
			}) {
				return fmt.Errorf("%w: disabled administrator access retains a Membership", ErrInvalidState)
			}
		}
		return nil
	}
	if administrators != 1 {
		return fmt.Errorf("%w: enabled administrator access must contain exactly one system administrator", ErrInvalidState)
	}
	for _, node := range state.ProxyNodes {
		membership := slices.IndexFunc(node.Memberships, func(membership Membership) bool {
			return membership.UserID == SystemAdministratorUserID
		})
		if membership < 0 {
			return fmt.Errorf("%w: Proxy Node %q has no administrator Membership", ErrInvalidState, node.Name)
		}
		administrator := node.Memberships[membership]
		if administrator.MonthlyQuotaBytes != 0 || !administrator.SubscriptionEndsAfter.IsZero() ||
			administrator.SubscriptionValue != 0 || administrator.SubscriptionUnit != "" ||
			administrator.DisabledReason != MembershipEnabled {
			return fmt.Errorf("%w: Proxy Node %q has an invalid administrator Membership", ErrInvalidState, node.Name)
		}
	}
	return nil
}

func validateStateCore(state State) error {
	userIDs := make(map[string]User, len(state.Users))
	userNames := make(map[string]UserRole, len(state.Users))
	subscriptionTokens := make(map[string]struct{}, len(state.Users))
	for _, user := range state.Users {
		if !validID(user.ID, "usr_") || !validStoredDisplayName(user.Name) || user.Name != normalizeDisplayName(user.Name) || user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() {
			return fmt.Errorf("%w: invalid end user", ErrInvalidState)
		}
		if err := validateUserSubscription(user.Subscription); err != nil {
			return fmt.Errorf("%w: invalid subscription for end user %q: %v", ErrInvalidState, user.Name, err)
		}
		switch user.Role {
		case UserRoleEndUser:
		case UserRoleAdministrator:
			if !IsSystemAdministrator(user) || user.Name != SystemAdministratorUserName {
				return fmt.Errorf("%w: invalid system administrator", ErrInvalidState)
			}
			if user.Subscription.Token == "" {
				return fmt.Errorf("%w: system administrator has no configuration subscription", ErrInvalidState)
			}
		default:
			return fmt.Errorf("%w: invalid end user role", ErrInvalidState)
		}
		if user.Subscription.Token != "" {
			if _, exists := subscriptionTokens[user.Subscription.Token]; exists {
				return fmt.Errorf("%w: duplicate user subscription token", ErrInvalidState)
			}
			subscriptionTokens[user.Subscription.Token] = struct{}{}
		}
		key := displayNameKey(user.Name)
		if _, exists := userIDs[user.ID]; exists {
			return fmt.Errorf("%w: duplicate end user ID", ErrInvalidState)
		}
		if existingRole, exists := userNames[key]; exists && existingRole != UserRoleAdministrator && user.Role != UserRoleAdministrator {
			return fmt.Errorf("%w: duplicate end user name", ErrInvalidState)
		}
		userIDs[user.ID] = user
		userNames[key] = user.Role
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
		if !validID(node.ID, "pn_") || !validStoredDisplayName(node.Name) || node.Name != normalizeDisplayName(node.Name) || node.CreatedAt.IsZero() || node.UpdatedAt.IsZero() {
			return fmt.Errorf("%w: invalid Proxy Node identity", ErrInvalidState)
		}
		key := displayNameKey(node.Name)
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
		for _, branch := range node.BlockBranches {
			if _, exists := globalIDs[branch.Rule.ID]; exists {
				return fmt.Errorf("%w: entity ID is reused", ErrInvalidState)
			}
			globalIDs[branch.Rule.ID] = struct{}{}
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
			if membership.PendingCredential != nil {
				if _, exists := globalCredentials[membership.PendingCredential.Secret]; exists {
					return fmt.Errorf("%w: generated pending credential is reused", ErrInvalidState)
				}
				globalCredentials[membership.PendingCredential.Secret] = struct{}{}
			}
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
	if len(state.TrafficObservations) > maxTrafficReportUsers {
		return fmt.Errorf("%w: too many traffic observations", ErrInvalidState)
	}
	seenObservations := make(map[string]struct{}, len(state.TrafficObservations))
	for _, observation := range state.TrafficObservations {
		key := observation.AgentID + "\x00" + observation.InboundPath + "\x00" + observation.Username
		if !validAgentID(observation.AgentID) || !validManagedTrafficPath(observation.InboundPath) ||
			strings.TrimSpace(observation.Username) == "" || len(observation.Username) > 128 ||
			strings.TrimSpace(observation.Epoch) == "" || len(observation.Epoch) > 128 ||
			observation.ObservedAt.IsZero() || strings.ContainsRune(observation.Username, '\x00') ||
			strings.ContainsRune(observation.Epoch, '\x00') {
			return fmt.Errorf("%w: invalid traffic observation", ErrInvalidState)
		}
		if _, exists := seenObservations[key]; exists {
			return fmt.Errorf("%w: duplicate traffic observation", ErrInvalidState)
		}
		seenObservations[key] = struct{}{}
	}
	if len(state.AccountingFailures) > maxAccountingFailures {
		return fmt.Errorf("%w: too many accounting failures", ErrInvalidState)
	}
	for _, failure := range state.AccountingFailures {
		if !validAgentID(failure.AgentID) || !validAccountingFailureReason(failure.Reason) || failure.OccurredAt.IsZero() {
			return fmt.Errorf("%w: invalid accounting failure", ErrInvalidState)
		}
	}
	return nil
}

func validateUserSubscription(subscription UserSubscription) error {
	if subscription.DefaultAction != "" || len(subscription.Rules) != 0 || len(subscription.Providers) != 0 {
		return errors.New("user contains a legacy per-user policy")
	}
	if subscription.Token == "" {
		return nil
	}
	if !validID(subscription.Token, "sub_") {
		return errors.New("invalid bearer token")
	}
	if subscription.UpdatedAt.IsZero() {
		return errors.New("missing update time")
	}
	return nil
}

func validateSubscriptionPolicy(policy SubscriptionPolicy) error {
	if policy.DefaultAction == "" && len(policy.Rules) == 0 && len(policy.Providers) == 0 && policy.UpdatedAt.IsZero() {
		return nil
	}
	if policy.DefaultAction == "" {
		policy.DefaultAction = SubscriptionProxy
	}
	if policy.UpdatedAt.IsZero() {
		return errors.New("missing update time")
	}
	if !validSubscriptionAction(policy.DefaultAction) {
		return errors.New("invalid default action")
	}
	if len(policy.Providers) != 0 {
		return errors.New("subscription policy contains legacy rule providers")
	}
	if len(policy.Rules) > 512 {
		return errors.New("subscription is too large")
	}
	ruleIDs := make(map[string]struct{}, len(policy.Rules))
	orders := make(map[int]struct{}, len(policy.Rules))
	for _, rule := range policy.Rules {
		if !validID(rule.ID, "sru_") || rule.Order < 0 || rule.Order >= len(policy.Rules) ||
			!validSubscriptionAction(rule.Action) || !validSubscriptionMatch(rule.Match) {
			return errors.New("invalid subscription rule")
		}
		if _, exists := ruleIDs[rule.ID]; exists {
			return errors.New("duplicate subscription rule ID")
		}
		if _, exists := orders[rule.Order]; exists {
			return errors.New("duplicate subscription rule order")
		}
		ruleIDs[rule.ID] = struct{}{}
		orders[rule.Order] = struct{}{}
		if rule.Provider != "" || len(rule.Values) == 0 || len(rule.Values) > 256 {
			return errors.New("subscription rule values are invalid")
		}
		if rule.NoResolve && rule.Match != SubscriptionMatchIPCIDR && rule.Match != SubscriptionMatchGeoIP {
			return errors.New("subscription no-resolve is only valid for destination IP/CIDR and GeoIP rules")
		}
		for _, value := range rule.Values {
			if strings.TrimSpace(value) != value || value == "" || len(value) > maxValueBytes || strings.ContainsRune(value, '\x00') {
				return errors.New("subscription rule value is invalid")
			}
			if err := validateSubscriptionRuleValue(rule.Match, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSubscriptionRuleValue(match SubscriptionMatch, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return errors.New("subscription rule value contains a line break")
	}
	switch match {
	case SubscriptionMatchIPCIDR, SubscriptionMatchSourceIPCIDR:
		if net.ParseIP(value) == nil {
			if _, _, err := net.ParseCIDR(value); err != nil {
				return errors.New("subscription IP/CIDR value is invalid")
			}
		}
	case SubscriptionMatchDestinationPort, SubscriptionMatchSourcePort:
		parts := strings.Split(value, "-")
		if len(parts) > 2 {
			return errors.New("subscription port value is invalid")
		}
		for _, part := range parts {
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 {
				return errors.New("subscription port value is invalid")
			}
		}
	case SubscriptionMatchNetwork:
		if !strings.EqualFold(value, "tcp") && !strings.EqualFold(value, "udp") {
			return errors.New("subscription network must be TCP or UDP")
		}
	case SubscriptionMatchGeosite, SubscriptionMatchGeoIP:
		if !subscriptionGeoPattern.MatchString(value) {
			return errors.New("subscription geo rule-set value is invalid")
		}
	}
	return nil
}

func validSubscriptionAction(action SubscriptionAction) bool {
	return action == SubscriptionProxy || action == SubscriptionDirect || action == SubscriptionReject
}

func validSubscriptionMatch(match SubscriptionMatch) bool {
	switch match {
	case SubscriptionMatchDomain, SubscriptionMatchDomainSuffix, SubscriptionMatchDomainKeyword,
		SubscriptionMatchDomainRegex, SubscriptionMatchIPCIDR, SubscriptionMatchSourceIPCIDR,
		SubscriptionMatchGeosite, SubscriptionMatchGeoIP, SubscriptionMatchDestinationPort, SubscriptionMatchSourcePort,
		SubscriptionMatchNetwork, SubscriptionMatchProcessName:
		return true
	default:
		return false
	}
}

func validateProxyNode(node ProxyNode, users map[string]User) error {
	if len(node.Hops) == 0 {
		return errors.New("Proxy Node has no entrance Hop")
	}
	if !validSubscriptionAddressMode(node.SubscriptionAddressMode) {
		return errors.New("invalid configuration subscription address mode")
	}
	if len(node.Hops)+len(node.Links)+len(node.BlockBranches) > maxTopologyEntities {
		return errors.New("Proxy Node exceeds topology entity limit")
	}
	if err := validateEndpoint(node.Entrance.Endpoint); err != nil {
		return fmt.Errorf("invalid entrance: %w", err)
	}
	hops := make(map[string]Hop, len(node.Hops))
	for _, hop := range node.Hops {
		if !validID(hop.ID, "hop_") || !validAgentID(hop.AgentID) || hop.CreatedAt.IsZero() || hop.UpdatedAt.IsZero() {
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
	ruleOrders := make(map[string][]int, len(node.Hops))
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
		if len(link.Rules) > 1 {
			return errors.New("Link cannot contain more than one routing Rule")
		}
		for _, rule := range link.Rules {
			if !validID(rule.ID, "rul_") || rule.Order < 0 || rule.LegacyTarget != nil {
				return errors.New("invalid Link Rule")
			}
			if err := validateRule(rule); err != nil {
				return err
			}
			if rule.Match == MatchNone {
				return errors.New("unconditional routing must use a fallback Link")
			}
			ruleOrders[link.ParentHopID] = append(ruleOrders[link.ParentHopID], rule.Order)
		}
		links[link.ID] = link
		parentByChild[link.ChildHopID] = link.ParentHopID
		outgoing[link.ParentHopID] = append(outgoing[link.ParentHopID], link)
	}
	for _, branch := range node.BlockBranches {
		if _, exists := hops[branch.ParentHopID]; !exists {
			return errors.New("BLOCK branch parent does not exist")
		}
		if branch.CreatedAt.IsZero() || branch.UpdatedAt.IsZero() || !validID(branch.Rule.ID, "rul_") ||
			branch.Rule.Order < 0 || branch.Rule.LegacyTarget != nil {
			return errors.New("invalid BLOCK branch")
		}
		if branch.Rule.Match == MatchNone {
			return errors.New("BLOCK branch requires a conditional match")
		}
		if err := validateRule(branch.Rule); err != nil {
			return err
		}
		ruleOrders[branch.ParentHopID] = append(ruleOrders[branch.ParentHopID], branch.Rule.Order)
	}
	for hopID, orders := range ruleOrders {
		sort.Ints(orders)
		for expected, order := range orders {
			if order != expected {
				return fmt.Errorf("route Rule order for Hop %q is not contiguous", hopID)
			}
		}
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
		if !validID(membership.ID, "mem_") || membership.CreatedAt.IsZero() ||
			membership.QuotaAnchorDay < 1 || membership.QuotaAnchorDay > 31 ||
			membership.QuotaPeriodStartedOn.IsZero() || membership.QuotaResetsAfter.IsZero() ||
			!membership.QuotaPeriodStartedOn.Equal(billingDate(membership.QuotaPeriodStartedOn)) ||
			!membership.QuotaResetsAfter.Equal(billingDate(membership.QuotaResetsAfter)) ||
			!membership.QuotaResetsAfter.After(membership.QuotaPeriodStartedOn) {
			return errors.New("invalid Membership")
		}
		if !membership.SubscriptionEndsAfter.IsZero() &&
			(membership.SubscriptionStartedAt.IsZero() || membership.SubscriptionStartedAt.Nanosecond() != 0 ||
				membership.SubscriptionEndsAfter.Nanosecond() != 0 ||
				!membership.SubscriptionEndsAfter.After(membership.SubscriptionStartedAt) ||
				!membership.SubscriptionEndsAfter.After(membership.CreatedAt.UTC().Truncate(time.Second))) {
			return errors.New("invalid Membership subscription")
		}
		if membership.LegacySubscriptionMonths != 0 ||
			(membership.SubscriptionValue == 0) != membership.SubscriptionEndsAfter.IsZero() ||
			(membership.SubscriptionValue > 0 &&
				(membership.SubscriptionValue > maxSubscriptionValue(membership.SubscriptionUnit) || maxSubscriptionValue(membership.SubscriptionUnit) == 0)) ||
			(membership.SubscriptionValue == 0 && (membership.SubscriptionUnit != "" || !membership.SubscriptionStartedAt.IsZero())) {
			return errors.New("invalid Membership subscription length")
		}
		if membership.DisabledReason != MembershipEnabled &&
			membership.DisabledReason != MembershipQuotaReached &&
			membership.DisabledReason != MembershipExpired {
			return errors.New("invalid Membership status")
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
		credential := membership.Credential
		if membership.PendingCredential != nil {
			credential = *membership.PendingCredential
		}
		if err := validateCredential(node.Entrance.Endpoint, credential); err != nil {
			return fmt.Errorf("invalid Membership credential: %w", err)
		}
		if _, exists := credentials[membership.Credential.Secret]; exists {
			return errors.New("Membership credential is reused")
		}
		memberships[membership.ID] = membership
		membershipUsers[membership.UserID] = struct{}{}
		credentials[membership.Credential.Secret] = struct{}{}
		if membership.PendingCredential != nil {
			if membership.PendingCredential.Secret == membership.Credential.Secret {
				return errors.New("pending Membership credential is unchanged")
			}
			if _, exists := credentials[membership.PendingCredential.Secret]; exists {
				return errors.New("pending Membership credential is reused")
			}
			credentials[membership.PendingCredential.Secret] = struct{}{}
		}
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

func validSubscriptionAddressMode(mode SubscriptionAddressMode) bool {
	return mode == "" || mode == SubscriptionAddressDual || mode == SubscriptionAddressIPv4 || mode == SubscriptionAddressIPv6
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
	if !config.Enabled && !config.Padding && config.Brutal == nil {
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

func normalizeDisplayName(value string) string {
	return norm.NFC.String(strings.TrimSpace(value))
}

func displayNameKey(value string) string {
	return norm.NFC.String(cases.Fold().String(normalizeDisplayName(value)))
}

func validDisplayName(value string) bool {
	if !utf8.ValidString(value) || value == "" || len(value) > maxDisplayNameBytes || utf8.RuneCountInString(value) > maxDisplayNameRunes {
		return false
	}
	for index, character := range value {
		if index == 0 {
			if !unicode.IsLetter(character) && !unicode.IsDigit(character) {
				return false
			}
			continue
		}
		if unicode.IsLetter(character) || unicode.IsDigit(character) || unicode.IsMark(character) {
			continue
		}
		switch character {
		case ' ', '.', '_', '-':
			continue
		default:
			return false
		}
	}
	return true
}

func validStoredDisplayName(value string) bool {
	return validDisplayName(value) ||
		(len(value) <= maxLegacyDisplayNameBytes && legacyNamePattern.MatchString(value))
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
	endpoint.TLS = normalizeTLSConfig(endpoint.TLS)
	endpoint.ObfsType = strings.TrimSpace(endpoint.ObfsType)
	return endpoint
}

// normalizeTLSConfig removes values belonging to an inactive certificate mode.
// Hidden form fields and older clients may still submit those values; retaining
// them would make otherwise identical physical listeners appear incompatible.
func normalizeTLSConfig(config TLSConfig) TLSConfig {
	config.ServerName = strings.TrimSpace(config.ServerName)
	config.Email = strings.TrimSpace(config.Email)
	config.CertificatePath = strings.TrimSpace(config.CertificatePath)
	config.KeyPath = strings.TrimSpace(config.KeyPath)
	switch config.Mode {
	case TLSModeACME:
		config.CertificatePath = ""
		config.KeyPath = ""
	case TLSModeSelfSigned:
		config.Email = ""
		config.CertificatePath = ""
		config.KeyPath = ""
	case TLSModeFiles:
		config.Email = ""
	}
	return config
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
