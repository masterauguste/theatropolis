package proxynode

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	maxSubscriptionMinutes = 52_560_000
	maxSubscriptionHours   = 876_000
	maxSubscriptionDays    = 36_500
	maxSubscriptionMonths  = 1200
	maxTrafficReportUsers  = 100000
	maxAccountingFailures  = 256
	maxDailyUsageDays      = 366
)

var billingLocation = time.FixedZone("UTC+8", 8*60*60)

// BillingLocation is the fixed product clock used for subscription, quota,
// compensation, and other administrator-facing billing references.
func BillingLocation() *time.Location { return billingLocation }

// MembershipQuotaResetAt returns the scheduled instant when the current
// inclusive quota period is cleared. QuotaResetsAfter stores the last valid
// UTC+8 billing date; enforcement runs at the following midnight.
func MembershipQuotaResetAt(membership Membership) time.Time {
	return membership.QuotaResetsAfter.AddDate(0, 0, 1)
}

const (
	AccountingFailureCollection  = "collection_failed"
	AccountingFailurePersistence = "persistence_failed"
)

func validateMembershipPlan(plan MembershipPlan) error {
	if plan.SubscriptionValue == 0 && plan.SubscriptionUnit == "" {
		return nil
	}
	if plan.SubscriptionValue <= 0 || plan.SubscriptionValue > maxSubscriptionValue(plan.SubscriptionUnit) {
		return fmt.Errorf("%w: invalid subscription duration", ErrInvalidState)
	}
	return nil
}

func maxSubscriptionValue(unit SubscriptionUnit) int {
	switch unit {
	case SubscriptionMinutes:
		return maxSubscriptionMinutes
	case SubscriptionHours:
		return maxSubscriptionHours
	case SubscriptionDays:
		return maxSubscriptionDays
	case SubscriptionMonths:
		return maxSubscriptionMonths
	default:
		return 0
	}
}

func subscriptionDeadline(now time.Time, value int, unit SubscriptionUnit) time.Time {
	now = now.UTC().Truncate(time.Second)
	switch unit {
	case SubscriptionMinutes:
		return now.Add(time.Duration(value) * time.Minute)
	case SubscriptionHours:
		return now.Add(time.Duration(value) * time.Hour)
	case SubscriptionDays:
		return now.Add(time.Duration(value) * 24 * time.Hour)
	case SubscriptionMonths:
		// Preserve the original natural-month contract: a grant made on
		// March 4 remains valid through April 4 and expires April 5 00:00 UTC+8.
		return addCalendarMonths(billingDate(now), value).AddDate(0, 0, 1)
	default:
		return time.Time{}
	}
}

func extendSubscriptionDeadline(deadline time.Time, value int, unit SubscriptionUnit) time.Time {
	base := deadline.UTC()
	if unit == SubscriptionMonths {
		return addCalendarMonths(base, value)
	}
	return subscriptionDeadline(base, value, unit)
}

// RecordAccountingFailure appends one bounded, non-sensitive accounting audit
// entry only when the authenticated Agent currently owns an applied entrance
// with an enabled Membership. It never changes either configuration-plane
// revision.
func (s *Store) RecordAccountingFailure(agentID, reason string, occurredAt time.Time) error {
	agentID = strings.TrimSpace(agentID)
	reason = strings.TrimSpace(reason)
	if !validAgentID(agentID) || !validAccountingFailureReason(reason) || occurredAt.IsZero() {
		return fmt.Errorf("%w: invalid accounting failure", ErrInvalidState)
	}
	return s.mutateBilling(func(state *State) (bool, error) {
		if !agentHasActiveEntranceMembership(*state, agentID) {
			return false, nil
		}
		state.AccountingFailures = append(state.AccountingFailures, AccountingFailure{
			AgentID: agentID, Reason: reason, OccurredAt: occurredAt.UTC(),
		})
		if len(state.AccountingFailures) > maxAccountingFailures {
			state.AccountingFailures = slices.Clone(state.AccountingFailures[len(state.AccountingFailures)-maxAccountingFailures:])
		}
		return false, nil
	})
}

// ClearAccountingFailures removes the complete bounded accounting error log.
// It does not change topology, user authority, or traffic usage.
func (s *Store) ClearAccountingFailures() error {
	return s.mutateBilling(func(state *State) (bool, error) {
		state.AccountingFailures = nil
		return false, nil
	})
}

// DailyUsage is one UTC+8 calendar day's traffic for one Proxy Node grant.
type DailyUsage struct {
	Date          time.Time
	ProxyNodeID   string
	ProxyNodeName string
	UsedBytes     uint64
}

type dailyUsageDelta struct {
	Date              string
	BytesByMembership map[string]uint64
}

// UserDailyUsage returns up to maxDailyUsageDays of durable per-Membership
// traffic history. Days are calendar days in the product's fixed UTC+8 clock.
func (s *Store) UserDailyUsage(userID string, days int) ([]DailyUsage, error) {
	userID = strings.TrimSpace(userID)
	if !validID(userID, "usr_") || days <= 0 || days > maxDailyUsageDays {
		return nil, fmt.Errorf("%w: invalid daily usage query", ErrInvalidState)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.userIndex[userID]; !exists {
		return nil, ErrNotFound
	}
	if s.accounting == nil {
		return nil, errors.New("accounting database is unavailable")
	}
	type membershipNode struct{ id, name string }
	memberships := make(map[string]membershipNode)
	for _, node := range s.state.ProxyNodes {
		for _, membership := range node.Memberships {
			if membership.UserID == userID {
				memberships[membership.ID] = membershipNode{id: node.ID, name: node.Name}
			}
		}
	}
	if len(memberships) == 0 {
		return nil, nil
	}
	start := billingDate(s.now()).AddDate(0, 0, -(days - 1)).Format("2006-01-02")
	end := billingDate(s.now()).Format("2006-01-02")
	rows, err := s.accounting.db.Query(
		`SELECT membership_id, usage_date, used_bytes
		 FROM daily_membership_usage WHERE usage_date >= ? AND usage_date <= ?
		 ORDER BY usage_date DESC, membership_id`, start, end,
	)
	if err != nil {
		return nil, fmt.Errorf("read daily usage: %w", err)
	}
	defer rows.Close()
	var result []DailyUsage
	for rows.Next() {
		var membershipID, dateText, usedText string
		if err := rows.Scan(&membershipID, &dateText, &usedText); err != nil {
			return nil, fmt.Errorf("decode daily usage: %w", err)
		}
		node, exists := memberships[membershipID]
		if !exists {
			continue
		}
		date, dateErr := time.ParseInLocation("2006-01-02", dateText, billingLocation)
		used, usedErr := strconv.ParseUint(usedText, 10, 64)
		if dateErr != nil || usedErr != nil {
			return nil, fmt.Errorf("%w: invalid daily usage row", ErrInvalidState)
		}
		result = append(result, DailyUsage{
			Date: date, ProxyNodeID: node.id, ProxyNodeName: node.name, UsedBytes: used,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read daily usage rows: %w", err)
	}
	return result, nil
}

func agentHasActiveEntranceMembership(state State, agentID string) bool {
	liveNodes := make(map[string]ProxyNode, len(state.ProxyNodes))
	for _, node := range state.ProxyNodes {
		liveNodes[node.ID] = node
	}
	for _, appliedNode := range state.AppliedProxyNodes {
		liveNode, exists := liveNodes[appliedNode.ID]
		if !exists {
			continue
		}
		rootIndex := slices.IndexFunc(appliedNode.Hops, func(hop Hop) bool {
			return hop.ID == appliedNode.Entrance.HopID
		})
		if rootIndex < 0 || appliedNode.Hops[rootIndex].AgentID != agentID {
			continue
		}
		for _, membership := range liveNode.Memberships {
			if membership.DisabledReason == MembershipEnabled {
				return true
			}
		}
	}
	return false
}

func validAccountingFailureReason(reason string) bool {
	return reason == AccountingFailureCollection || reason == AccountingFailurePersistence
}

// UpdateMembershipPlan replaces a grant's monthly allowance and remaining
// subscription term. A finite term starts on the current UTC+8 date. Existing
// period usage is retained, so reducing a quota can disable access immediately.
func (s *Store) UpdateMembershipPlan(nodeID, userID string, plan MembershipPlan) error {
	if err := validateMembershipPlan(plan); err != nil {
		return err
	}
	return s.mutateUserProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		membership := membershipForUser(node, userID)
		if membership == nil {
			return ErrNotFound
		}
		now := s.now().UTC()
		if !membership.SubscriptionEndsAfter.IsZero() && !now.Before(membership.SubscriptionEndsAfter) {
			return ErrNotFound
		}
		membership.MonthlyQuotaBytes = plan.MonthlyQuotaBytes
		membership.SubscriptionStartedAt = time.Time{}
		membership.SubscriptionEndsAfter = time.Time{}
		membership.SubscriptionValue = plan.SubscriptionValue
		membership.SubscriptionUnit = plan.SubscriptionUnit
		membership.LegacySubscriptionMonths = 0
		if plan.SubscriptionValue > 0 {
			membership.SubscriptionStartedAt = now.Truncate(time.Second)
			membership.SubscriptionEndsAfter = subscriptionDeadline(now, plan.SubscriptionValue, plan.SubscriptionUnit)
		}
		recomputeMembershipStatus(membership, now)
		return nil
	})
}

// ExtendMembershipSubscription adds time to an existing finite subscription
// without changing its traffic period, reset date, or quota. Expired grants are
// removed by the billing enforcer and must be granted again.
func (s *Store) ExtendMembershipSubscription(nodeID, userID string, value int, unit SubscriptionUnit) error {
	if err := validateMembershipPlan(MembershipPlan{SubscriptionValue: value, SubscriptionUnit: unit}); err != nil {
		return err
	}
	return s.mutateUserProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		membership := membershipForUser(node, userID)
		if membership == nil {
			return ErrNotFound
		}
		if membership.SubscriptionEndsAfter.IsZero() {
			return fmt.Errorf("%w: subscription has no expiration", ErrConflict)
		}
		now := s.now().UTC()
		if !now.Before(membership.SubscriptionEndsAfter) {
			return ErrNotFound
		}
		membership.SubscriptionEndsAfter = extendSubscriptionDeadline(membership.SubscriptionEndsAfter, value, unit)
		recomputeMembershipStatus(membership, now)
		return nil
	})
}

// ExtendProxyNodeSubscriptions applies one compensation duration to an
// explicit set of finite Memberships. Quota periods and reset timing are never
// changed.
func (s *Store) ExtendProxyNodeSubscriptions(nodeID string, membershipIDs []string, value int, unit SubscriptionUnit) (int, error) {
	if err := validateMembershipPlan(MembershipPlan{SubscriptionValue: value, SubscriptionUnit: unit}); err != nil {
		return 0, err
	}
	selected := make(map[string]struct{}, len(membershipIDs))
	for _, membershipID := range membershipIDs {
		membershipID = strings.TrimSpace(membershipID)
		if !validID(membershipID, "mem_") {
			return 0, fmt.Errorf("%w: invalid Membership selection", ErrInvalidState)
		}
		selected[membershipID] = struct{}{}
	}
	if len(selected) == 0 {
		return 0, fmt.Errorf("%w: no Memberships selected", ErrInvalidState)
	}
	extended := 0
	err := s.mutateUserProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		now := s.now().UTC()
		for membershipIndex := range node.Memberships {
			membership := &node.Memberships[membershipIndex]
			if _, exists := selected[membership.ID]; !exists {
				continue
			}
			if membership.SubscriptionEndsAfter.IsZero() {
				return fmt.Errorf("%w: selected Membership has no expiration", ErrConflict)
			}
			if !now.Before(membership.SubscriptionEndsAfter) {
				return ErrNotFound
			}
			membership.SubscriptionEndsAfter = extendSubscriptionDeadline(membership.SubscriptionEndsAfter, value, unit)
			recomputeMembershipStatus(membership, now)
			extended++
		}
		if extended != len(selected) {
			return ErrNotFound
		}
		return nil
	})
	return extended, err
}

// ResetMembershipTraffic clears only the current-period usage. Billing anchor,
// period boundaries, quota, and subscription deadline are preserved.
func (s *Store) ResetMembershipTraffic(nodeID, userID string) (bool, error) {
	configurationChanged := false
	err := s.mutateBilling(func(state *State) (bool, error) {
		nodeIndex := slices.IndexFunc(state.ProxyNodes, func(node ProxyNode) bool { return node.ID == nodeID })
		if nodeIndex < 0 {
			return false, ErrNotFound
		}
		membership := membershipForUser(&state.ProxyNodes[nodeIndex], userID)
		if membership == nil {
			return false, ErrNotFound
		}
		before := membership.DisabledReason
		membership.UsedBytes = 0
		recomputeMembershipStatus(membership, s.now().UTC())
		configurationChanged = before != membership.DisabledReason
		return configurationChanged, nil
	})
	return configurationChanged, err
}

func membershipForUser(node *ProxyNode, userID string) *Membership {
	for index := range node.Memberships {
		if node.Memberships[index].UserID == userID {
			return &node.Memberships[index]
		}
	}
	return nil
}

// ApplyTrafficDeltaReport adds one destructive-read sing-box interval directly
// to the master-owned Membership totals. Delta Agents retain no local ledger;
// a successfully handled control frame is therefore applied exactly once.
func (s *Store) ApplyTrafficDeltaReport(agentID string, observedAt time.Time, users []UserTraffic) (bool, error) {
	agentID = strings.TrimSpace(agentID)
	if !validAgentID(agentID) || observedAt.IsZero() || len(users) > maxTrafficReportUsers {
		return false, fmt.Errorf("%w: invalid traffic delta report", ErrInvalidState)
	}
	for _, usage := range users {
		if !validManagedTrafficPath(usage.InboundPath) || strings.TrimSpace(usage.Username) == "" ||
			len(usage.Username) > 128 || strings.ContainsRune(usage.Username, '\x00') {
			return false, fmt.Errorf("%w: invalid traffic delta report user", ErrInvalidState)
		}
	}

	configurationChanged := false
	daily := &dailyUsageDelta{Date: observedAt.In(billingLocation).Format("2006-01-02"), BytesByMembership: make(map[string]uint64)}
	err := s.mutateBillingWithDaily(daily, func(state *State) (bool, error) {
		targets, aliases, err := trafficMemberships(state, agentID)
		if err != nil {
			return false, err
		}
		// Once an Agent advertises reset deltas, its former cumulative
		// observations are obsolete and must not influence a later report.
		observations := state.TrafficObservations[:0]
		for _, observation := range state.TrafficObservations {
			if observation.AgentID != agentID {
				observations = append(observations, observation)
			}
		}
		state.TrafficObservations = observations
		for _, usage := range users {
			membership := targets[trafficKey(usage.InboundPath, usage.Username)]
			if membership == nil {
				membership = aliases[trafficAliasKey(usage.InboundPath, usage.Username)]
			}
			if membership == nil {
				continue
			}
			delta := saturatingAdd(usage.UplinkBytes, usage.DownlinkBytes)
			membership.UsedBytes = saturatingAdd(membership.UsedBytes, delta)
			daily.BytesByMembership[membership.ID] = saturatingAdd(daily.BytesByMembership[membership.ID], delta)
			if membership.DisabledReason == MembershipEnabled && membership.MonthlyQuotaBytes > 0 &&
				membership.UsedBytes >= membership.MonthlyQuotaBytes {
				membership.DisabledReason = MembershipQuotaReached
				configurationChanged = true
			}
		}
		return configurationChanged, nil
	})
	return configurationChanged, err
}

// ApplyTrafficReport folds a legacy Agent's cumulative counters into
// per-membership usage during the rolling transition to reset deltas. It
// returns true only when quota enforcement requires user synchronization.
func (s *Store) ApplyTrafficReport(agentID, epoch string, observedAt time.Time, users []UserTraffic) (bool, error) {
	agentID = strings.TrimSpace(agentID)
	epoch = strings.TrimSpace(epoch)
	if !validAgentID(agentID) || epoch == "" || len(epoch) > 128 || strings.ContainsRune(epoch, '\x00') ||
		observedAt.IsZero() || len(users) > maxTrafficReportUsers {
		return false, fmt.Errorf("%w: invalid traffic report", ErrInvalidState)
	}
	for _, usage := range users {
		if !validManagedTrafficPath(usage.InboundPath) || strings.TrimSpace(usage.Username) == "" ||
			len(usage.Username) > 128 || strings.ContainsRune(usage.Username, '\x00') {
			return false, fmt.Errorf("%w: invalid traffic report user", ErrInvalidState)
		}
	}

	configurationChanged := false
	daily := &dailyUsageDelta{Date: observedAt.In(billingLocation).Format("2006-01-02"), BytesByMembership: make(map[string]uint64)}
	err := s.mutateBillingWithDaily(daily, func(state *State) (bool, error) {
		targets, aliases, err := trafficMemberships(state, agentID)
		if err != nil {
			return false, err
		}
		reported := make(map[string]struct{}, len(users))
		for _, usage := range users {
			reported[trafficKey(usage.InboundPath, usage.Username)] = struct{}{}
		}
		// An identity that no longer maps to a current membership can never become
		// authoritative again: re-granting creates a new Membership ID and thus a
		// new generated auth_user. Prune its baseline before folding this report so
		// the state cannot grow forever as users and listeners are retired.
		observations := state.TrafficObservations[:0]
		for _, observation := range state.TrafficObservations {
			_, stillReported := reported[trafficKey(observation.InboundPath, observation.Username)]
			if observation.AgentID != agentID || stillReported ||
				trafficObservationMembership(targets, aliases, observation) != nil {
				observations = append(observations, observation)
			}
		}
		state.TrafficObservations = observations
		for _, usage := range users {
			key := trafficKey(usage.InboundPath, usage.Username)
			membership := targets[key]
			if membership == nil {
				membership = aliases[trafficAliasKey(usage.InboundPath, usage.Username)]
			}
			if membership == nil {
				continue
			}
			observation := observationFor(state, agentID, usage.InboundPath, usage.Username)
			delta := saturatingAdd(usage.UplinkBytes, usage.DownlinkBytes)
			dailyDelta := delta
			if observation != nil && observation.Epoch == epoch {
				uplink := counterDelta(observation.UplinkBytes, usage.UplinkBytes)
				downlink := counterDelta(observation.DownlinkBytes, usage.DownlinkBytes)
				delta = saturatingAdd(uplink, downlink)
				dailyDelta = delta
				delta = trafficInsideCurrentPeriod(
					delta, observation.ObservedAt, observedAt, membership.QuotaPeriodStartedOn,
				)
			}
			if observation == nil {
				state.TrafficObservations = append(state.TrafficObservations, TrafficObservation{
					AgentID: agentID, InboundPath: usage.InboundPath, Username: usage.Username,
				})
				observation = &state.TrafficObservations[len(state.TrafficObservations)-1]
			}
			observation.Epoch = epoch
			observation.UplinkBytes = usage.UplinkBytes
			observation.DownlinkBytes = usage.DownlinkBytes
			observation.ObservedAt = observedAt.UTC()
			membership.UsedBytes = saturatingAdd(membership.UsedBytes, delta)
			daily.BytesByMembership[membership.ID] = saturatingAdd(daily.BytesByMembership[membership.ID], dailyDelta)
			if membership.DisabledReason == MembershipEnabled && membership.MonthlyQuotaBytes > 0 &&
				membership.UsedBytes >= membership.MonthlyQuotaBytes {
				membership.DisabledReason = MembershipQuotaReached
				configurationChanged = true
			}
		}
		return configurationChanged, nil
	})
	return configurationChanged, err
}

func trafficObservationMembership(
	targets, aliases map[string]*Membership,
	observation TrafficObservation,
) *Membership {
	if membership := targets[trafficKey(observation.InboundPath, observation.Username)]; membership != nil {
		return membership
	}
	return aliases[trafficAliasKey(observation.InboundPath, observation.Username)]
}

// AdvanceBilling applies quota period and subscription transitions in UTC+8.
func (s *Store) AdvanceBilling(now time.Time) (bool, error) {
	return s.advanceBilling(now, true, true)
}

func (s *Store) advanceSubscriptions(now time.Time) (bool, error) {
	return s.advanceBilling(now, false, true)
}

func (s *Store) advanceBilling(now time.Time, resetTraffic, expireSubscriptions bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now = now.UTC()
	today := billingDate(now)
	next := cloneState(s.state)
	identityChanged := false
	accountingChanged := false
	authorityChanged := false

	if expireSubscriptions {
		for nodeIndex := range next.ProxyNodes {
			memberships := next.ProxyNodes[nodeIndex].Memberships
			retained := memberships[:0]
			for membershipIndex := range memberships {
				membership := memberships[membershipIndex]
				if !membership.SubscriptionEndsAfter.IsZero() && !now.Before(membership.SubscriptionEndsAfter) {
					identityChanged = true
					authorityChanged = true
					continue
				}
				retained = append(retained, membership)
			}
			clear(memberships[len(retained):])
			next.ProxyNodes[nodeIndex].Memberships = retained
		}
	}

	if resetTraffic {
		for nodeIndex := range next.ProxyNodes {
			for membershipIndex := range next.ProxyNodes[nodeIndex].Memberships {
				membership := &next.ProxyNodes[nodeIndex].Memberships[membershipIndex]
				for today.After(membership.QuotaResetsAfter) {
					accountingChanged = true
					membership.UsedBytes = 0
					membership.QuotaPeriodStartedOn = membership.QuotaResetsAfter.AddDate(0, 0, 1)
					membership.QuotaResetsAfter = addCalendarMonthsAnchored(
						membership.QuotaResetsAfter, 1, membership.QuotaAnchorDay,
					)
					if membership.DisabledReason == MembershipQuotaReached {
						membership.DisabledReason = MembershipEnabled
						authorityChanged = true
					}
				}
			}
		}
	}

	if !identityChanged && !accountingChanged {
		return false, nil
	}
	if authorityChanged {
		next.UserRevision++
	}
	if err := validateState(next); err != nil {
		return false, err
	}
	if identityChanged {
		build := normalizeBuild(s.build, s.now())
		if err := s.persistStateAndAccountingLocked(next, build); err != nil {
			return false, err
		}
		return authorityChanged, nil
	}
	if s.accounting == nil {
		return false, errors.New("accounting database is unavailable")
	}
	if err := s.accounting.persistChanges(s.state, next, nil); err != nil {
		return false, err
	}
	s.state = next
	return authorityChanged, nil
}

func (s *Store) mutateBilling(mutation func(*State) (bool, error)) error {
	return s.mutateBillingWithDaily(nil, mutation)
}

func (s *Store) mutateBillingWithDaily(daily *dailyUsageDelta, mutation func(*State) (bool, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	configurationChanged, err := mutation(&next)
	if err != nil {
		return err
	}
	if configurationChanged {
		next.UserRevision++
	}
	if err := validateState(next); err != nil {
		return err
	}
	if s.accounting == nil {
		return errors.New("accounting database is unavailable")
	}
	if err := s.accounting.persistChanges(s.state, next, daily); err != nil {
		return err
	}
	s.state = next
	return nil
}

func trafficMemberships(state *State, agentID string) (map[string]*Membership, map[string]*Membership, error) {
	users := make(map[string]string, len(state.Users))
	for _, user := range state.Users {
		users[user.ID] = user.Name
	}
	targets := make(map[string]*Membership)
	aliases := make(map[string]*Membership)
	liveNodes := make(map[string]*ProxyNode, len(state.ProxyNodes))
	for nodeIndex := range state.ProxyNodes {
		liveNodes[state.ProxyNodes[nodeIndex].ID] = &state.ProxyNodes[nodeIndex]
	}
	for appliedIndex := range state.AppliedProxyNodes {
		appliedNode := &state.AppliedProxyNodes[appliedIndex]
		node := liveNodes[appliedNode.ID]
		if node == nil {
			continue
		}
		rootIndex := slices.IndexFunc(appliedNode.Hops, func(hop Hop) bool { return hop.ID == appliedNode.Entrance.HopID })
		if rootIndex < 0 || appliedNode.Hops[rootIndex].AgentID != agentID {
			continue
		}
		listenerKey, _, err := listenerKeys(agentID, appliedNode.Entrance.Endpoint)
		if err != nil {
			return nil, nil, err
		}
		path := "/tp-in-" + shortDigest(listenerKey)
		for membershipIndex := range node.Memberships {
			membership := &node.Memberships[membershipIndex]
			userName := users[membership.UserID]
			label := AuthenticatedUserLabel(appliedNode.Name, userName, membership.ID)
			key := trafficKey(path, label)
			if targets[key] != nil {
				return nil, nil, errors.New("ambiguous managed-user traffic identity")
			}
			targets[key] = membership
			aliases[trafficAliasKey(path, label)] = membership
			// Accept the pre-stable-membership-suffix label until every existing Agent has
			// received its first user synchronization after upgrade.
			legacyKey := trafficKey(path, appliedNode.Name+"-"+userName)
			if existing := targets[legacyKey]; existing == nil || existing == membership {
				targets[legacyKey] = membership
			}
		}
	}
	return targets, aliases, nil
}

func trafficAliasKey(path, username string) string {
	separator := strings.LastIndexByte(username, '-')
	if separator < 0 {
		return ""
	}
	return path + "\x00" + username[separator+1:]
}

func observationFor(state *State, agentID, path, username string) *TrafficObservation {
	for index := range state.TrafficObservations {
		observation := &state.TrafficObservations[index]
		if observation.AgentID == agentID && observation.InboundPath == path && observation.Username == username {
			return observation
		}
	}
	return nil
}

func trafficKey(path, username string) string { return path + "\x00" + username }

func counterDelta(previous, current uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	// A counter can reset without the agent process restarting (for example,
	// after a sing-box crash). Treat the new cumulative value as fresh usage.
	return current
}

func saturatingAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}

func trafficInsideCurrentPeriod(value uint64, previous, current, periodStart time.Time) uint64 {
	previous = previous.UTC()
	current = current.UTC()
	periodStart = periodStart.UTC()
	if value == 0 || periodStart.IsZero() || !previous.Before(periodStart) || !current.After(periodStart) {
		if !current.After(periodStart) && previous.Before(periodStart) {
			return 0
		}
		return value
	}
	whole := current.Sub(previous)
	inside := current.Sub(periodStart)
	if whole <= 0 || inside <= 0 || inside >= whole {
		return value
	}
	// Counters do not include packet timestamps. Pro-rate the interval at the
	// period boundary instead of charging the entire offline/polling interval
	// to the new month. float64 is sufficiently precise at byte-scale quotas
	// and avoids overflowing a value*duration integer multiplication.
	return uint64(float64(value) * float64(inside) / float64(whole))
}

func validManagedTrafficPath(path string) bool {
	if !strings.HasPrefix(path, "/tp-in-") || len(path) > 80 {
		return false
	}
	for _, character := range path[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func billingDate(value time.Time) time.Time {
	value = value.In(billingLocation)
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, billingLocation)
}

func addCalendarMonths(date time.Time, months int) time.Time {
	date = billingDate(date)
	return addCalendarMonthsAnchored(date, months, date.Day())
}

func addCalendarMonthsAnchored(date time.Time, months, anchorDay int) time.Time {
	date = billingDate(date)
	first := time.Date(date.Year(), date.Month(), 1, 0, 0, 0, 0, billingLocation).AddDate(0, months, 0)
	lastDay := first.AddDate(0, 1, -1).Day()
	day := min(anchorDay, lastDay)
	return time.Date(first.Year(), first.Month(), day, 0, 0, 0, 0, billingLocation)
}
