package proxynode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

type envelope struct {
	Schema        string    `json:"schema"`
	SchemaVersion int       `json:"schema_version"`
	LastUsedBy    BuildInfo `json:"last_used_by"`
	Data          State     `json:"data"`
}

type Store struct {
	mu                sync.RWMutex
	path              string
	state             State
	build             BuildInfo
	now               func() time.Time
	accounting        *accountingDB
	userIndex         map[string]int
	subscriptionIndex map[string]int
}

func Open(path string, build BuildInfo) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("proxy node storage path is required")
	}
	clean := filepath.Clean(path)
	store := &Store{path: clean, build: build, now: time.Now}
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		store.state = State{UserRevision: 1, Users: []User{}, ProxyNodes: []ProxyNode{}, AppliedProxyNodes: []ProxyNode{}}
		store.build = normalizeBuild(build, store.now())
		if err := store.persistLocked(store.state, store.build); err != nil {
			return nil, err
		}
		accounting, err := openAccountingDB(clean, &store.state)
		if err != nil {
			return nil, err
		}
		store.accounting = accounting
		store.rebuildIndexesLocked()
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect proxy node state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: state path is not a regular file", ErrUnsafeStorage)
	}
	if info.Size() <= 0 || info.Size() > maxStateBytes {
		return nil, fmt.Errorf("%w: state file size is invalid", ErrInvalidState)
	}
	if err := os.Chmod(clean, 0o600); err != nil {
		return nil, fmt.Errorf("secure proxy node state: %w", err)
	}
	file, err := os.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("open proxy node state: %w", err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read proxy node state: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close proxy node state: %w", closeErr)
	}
	if len(contents) > maxStateBytes {
		return nil, fmt.Errorf("%w: state exceeds size limit", ErrInvalidState)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var stored envelope
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("%w: decode state: %v", ErrInvalidState, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing state data", ErrInvalidState)
	}
	if stored.Schema != SchemaID {
		return nil, fmt.Errorf("%w: unexpected schema", ErrInvalidState)
	}
	if stored.SchemaVersion > SchemaVersion {
		return nil, ErrNewerSchema
	}
	if stored.SchemaVersion == 1 {
		if err := migrateSchemaV1(&stored.Data); err != nil {
			return nil, fmt.Errorf("%w: migrate schema version 1: %v", ErrInvalidState, err)
		}
		stored.SchemaVersion = 2
	}
	if stored.SchemaVersion == 2 {
		migrateSchemaV2(&stored.Data)
		stored.SchemaVersion = 3
	}
	if stored.SchemaVersion == 3 {
		if err := migrateSchemaV3(&stored.Data); err != nil {
			return nil, fmt.Errorf("%w: migrate schema version 3: %v", ErrInvalidState, err)
		}
		stored.SchemaVersion = 4
	}
	if stored.SchemaVersion == 4 {
		migrateSchemaV4(&stored.Data)
		stored.SchemaVersion = 5
	}
	if stored.SchemaVersion == 5 {
		migrateSchemaV5(&stored.Data)
		stored.SchemaVersion = 6
	}
	if stored.SchemaVersion == 6 {
		stored.SchemaVersion = 7
	}
	if stored.SchemaVersion == 7 {
		stored.SchemaVersion = 8
	}
	if stored.SchemaVersion == 8 {
		migrateSchemaV8(&stored.Data)
		stored.SchemaVersion = 9
	}
	if stored.SchemaVersion == 9 {
		stored.SchemaVersion = 10
	}
	if stored.SchemaVersion == 10 {
		stored.SchemaVersion = 11
	}
	if stored.SchemaVersion == 11 {
		if err := migrateSchemaV11(&stored.Data); err != nil {
			return nil, fmt.Errorf("%w: migrate schema version 11: %v", ErrInvalidState, err)
		}
		stored.SchemaVersion = 12
	}
	if stored.SchemaVersion == 12 {
		migrateSchemaV12(&stored.Data)
		stored.SchemaVersion = 13
	}
	if stored.SchemaVersion == 13 {
		stored.SchemaVersion = 14
	}
	if stored.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported schema version %d", ErrInvalidState, stored.SchemaVersion)
	}
	if err := validateBuildInfo(stored.LastUsedBy); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	if err := validateState(stored.Data); err != nil {
		return nil, err
	}
	if changed, err := reconcileSharedListenerSecrets(&stored.Data, nil); err != nil {
		return nil, fmt.Errorf("%w: reconcile shared listeners: %v", ErrInvalidState, err)
	} else if changed {
		stored.Data.Revision++
	}
	if err := validateState(stored.Data); err != nil {
		return nil, err
	}
	store.state = stored.Data
	store.build = build
	accounting, err := openAccountingDB(clean, &store.state)
	if err != nil {
		return nil, err
	}
	store.accounting = accounting
	store.rebuildIndexesLocked()
	if err := validateState(store.state); err != nil {
		_ = accounting.db.Close()
		return nil, err
	}
	return store, nil
}

// migrateSchemaV12 removes the unreleased remote-provider experiment. Rules
// that depended on a provider cannot be represented after its source is
// removed, so they are discarded while ordinary rules retain their order.
func migrateSchemaV12(state *State) {
	state.SubscriptionPolicy.Rules = slices.DeleteFunc(state.SubscriptionPolicy.Rules, func(rule SubscriptionRule) bool {
		return rule.Match == SubscriptionMatchProvider
	})
	for index := range state.SubscriptionPolicy.Rules {
		state.SubscriptionPolicy.Rules[index].Provider = ""
	}
	reorderSubscriptionRules(state.SubscriptionPolicy.Rules)
	state.SubscriptionPolicy.Providers = nil
}

// migrateSchemaV11 promotes the most recently edited legacy per-user policy
// into the universal policy. Tokens remain user-bound. Version 11 was never a
// released schema, but this keeps local previews and reinstallations usable.
func migrateSchemaV11(state *State) error {
	var selected *UserSubscription
	selectedUserUpdatedAt := time.Time{}
	for index := range state.Users {
		subscription := &state.Users[index].Subscription
		if subscription.DefaultAction != "" || len(subscription.Rules) != 0 || len(subscription.Providers) != 0 {
			if selected == nil || subscription.UpdatedAt.After(selected.UpdatedAt) {
				selected = subscription
				selectedUserUpdatedAt = state.Users[index].UpdatedAt
			}
		}
	}
	if selected != nil {
		updatedAt := selected.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = selectedUserUpdatedAt.UTC()
		}
		state.SubscriptionPolicy = SubscriptionPolicy{
			DefaultAction: selected.DefaultAction,
			Rules:         append([]SubscriptionRule(nil), selected.Rules...),
			Providers:     append([]SubscriptionProvider(nil), selected.Providers...),
			UpdatedAt:     updatedAt,
		}
	}
	for index := range state.Users {
		if state.Users[index].Subscription.Token == "" {
			token, err := randomID("sub")
			if err != nil {
				return err
			}
			state.Users[index].Subscription.Token = token
			state.Users[index].Subscription.UpdatedAt = state.Users[index].UpdatedAt.UTC()
		}
		state.Users[index].Subscription.DefaultAction = ""
		state.Users[index].Subscription.Rules = nil
		state.Users[index].Subscription.Providers = nil
	}
	return nil
}

func (s *Store) MarkReady() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := normalizeBuild(s.build, s.now())
	if err := s.persistLocked(s.state, next); err != nil {
		return err
	}
	s.build = next
	return nil
}

func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

func (s *Store) User(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	index, exists := s.userIndex[id]
	if !exists || index < 0 || index >= len(s.state.Users) {
		return User{}, false
	}
	return cloneState(State{Users: []User{s.state.Users[index]}}).Users[0], true
}

func (s *Store) ProxyNode(id string) (ProxyNode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, node := range s.state.ProxyNodes {
		if node.ID == id {
			return cloneProxyNode(node), true
		}
	}
	return ProxyNode{}, false
}

func (s *Store) AppliedProxyNode(id string) (ProxyNode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, node := range s.state.AppliedProxyNodes {
		if node.ID == id {
			return cloneProxyNode(node), true
		}
	}
	return ProxyNode{}, false
}

func (s *Store) CreateUser(name string) (User, error) {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return User{}, fmt.Errorf("%w: invalid end user name", ErrInvalidState)
	}
	id, err := randomID("usr")
	if err != nil {
		return User{}, err
	}
	token, err := randomID("sub")
	if err != nil {
		return User{}, err
	}
	now := s.now().UTC()
	created := User{ID: id, Name: name, Subscription: UserSubscription{Token: token, UpdatedAt: now}, CreatedAt: now, UpdatedAt: now}
	err = s.mutateUser(func(state *State) error {
		for _, user := range state.Users {
			if strings.EqualFold(user.Name, name) {
				return ErrConflict
			}
		}
		state.Users = append(state.Users, created)
		return nil
	})
	return created, err
}

func (s *Store) RenameUser(id, name string) error {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return fmt.Errorf("%w: invalid end user name", ErrInvalidState)
	}
	return s.mutateUser(func(state *State) error {
		for _, user := range state.Users {
			if user.ID != id && strings.EqualFold(user.Name, name) {
				return ErrConflict
			}
		}
		for index := range state.Users {
			if state.Users[index].ID == id {
				state.Users[index].Name = name
				state.Users[index].UpdatedAt = s.now().UTC()
				return nil
			}
		}
		return ErrNotFound
	})
}

func (s *Store) DeleteUser(id string) error {
	return s.mutateUser(func(state *State) error {
		index := slices.IndexFunc(state.Users, func(user User) bool { return user.ID == id })
		if index < 0 {
			return ErrNotFound
		}
		state.Users = append(state.Users[:index], state.Users[index+1:]...)
		for nodeIndex := range state.ProxyNodes {
			node := &state.ProxyNodes[nodeIndex]
			node.Memberships = slices.DeleteFunc(node.Memberships, func(membership Membership) bool {
				return membership.UserID == id
			})
			node.UpdatedAt = s.now().UTC()
		}
		return nil
	})
}

func (s *Store) CreateProxyNode(input CreateProxyNodeInput) (ProxyNode, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.RootAgent = strings.TrimSpace(input.RootAgent)
	input.Entrance = normalizeEndpoint(input.Entrance)
	if input.Final.Type == "" {
		input.Final = Target{Type: TargetDirect}
	}
	if !validName(input.Name) || !validAgentID(input.RootAgent) {
		return ProxyNode{}, fmt.Errorf("%w: invalid Proxy Node fields", ErrInvalidState)
	}
	if (input.Final.Type != TargetDirect && input.Final.Type != TargetReject) || input.Final.LinkID != "" {
		return ProxyNode{}, fmt.Errorf("%w: initial terminal exit must be Direct or Reject", ErrInvalidState)
	}
	if err := generateEndpointSecrets(&input.Entrance); err != nil {
		return ProxyNode{}, err
	}
	proxyID, err := randomID("pn")
	if err != nil {
		return ProxyNode{}, err
	}
	hopID, err := randomID("hop")
	if err != nil {
		return ProxyNode{}, err
	}
	now := s.now().UTC()
	created := ProxyNode{
		ID:       proxyID,
		Name:     input.Name,
		Entrance: Entrance{HopID: hopID, Endpoint: input.Entrance},
		Hops: []Hop{{
			ID: hopID, Name: input.RootAgent, AgentID: input.RootAgent,
			Final: input.Final, CreatedAt: now, UpdatedAt: now,
		}},
		Links: []Link{}, Memberships: []Membership{}, RuleSets: []CustomRuleSet{},
		CreatedAt: now, UpdatedAt: now,
	}
	err = s.mutate(func(state *State) error {
		for _, node := range state.ProxyNodes {
			if strings.EqualFold(node.Name, created.Name) {
				return ErrConflict
			}
		}
		state.ProxyNodes = append(state.ProxyNodes, created)
		return validateListenerLayout(state)
	})
	return created, err
}

func (s *Store) RenameProxyNode(id, name string) error {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return fmt.Errorf("%w: invalid Proxy Node name", ErrInvalidState)
	}
	return s.mutateProxyNode(id, func(state *State, node *ProxyNode) error {
		for _, candidate := range state.ProxyNodes {
			if candidate.ID != id && strings.EqualFold(candidate.Name, name) {
				return ErrConflict
			}
		}
		node.Name = name
		return nil
	})
}

func (s *Store) DeleteProxyNode(id string) error {
	return s.mutate(func(state *State) error {
		index := slices.IndexFunc(state.ProxyNodes, func(node ProxyNode) bool { return node.ID == id })
		if index < 0 {
			return ErrNotFound
		}
		state.ProxyNodes = append(state.ProxyNodes[:index], state.ProxyNodes[index+1:]...)
		state.UserRevision++
		return nil
	})
}

func (s *Store) UpdateEntrance(nodeID string, endpoint Endpoint) error {
	endpoint = normalizeEndpoint(endpoint)
	return s.mutateProxyNode(nodeID, func(state *State, node *ProxyNode) error {
		return applySharedListenerEdit(state, &node.Entrance.Endpoint, endpoint, s.now().UTC())
	})
}

func (s *Store) AddMembership(nodeID, userID string) (Membership, error) {
	return s.AddMembershipWithPlan(nodeID, userID, MembershipPlan{})
}

func (s *Store) AddMembershipWithPlan(nodeID, userID string, plan MembershipPlan) (Membership, error) {
	if err := validateMembershipPlan(plan); err != nil {
		return Membership{}, err
	}
	membershipID, err := randomID("mem")
	if err != nil {
		return Membership{}, err
	}
	var created Membership
	err = s.mutateUserProxyNode(nodeID, func(state *State, node *ProxyNode) error {
		if !slices.ContainsFunc(state.Users, func(user User) bool { return user.ID == userID }) {
			return ErrNotFound
		}
		if slices.ContainsFunc(node.Memberships, func(membership Membership) bool { return membership.UserID == userID }) {
			return ErrConflict
		}
		activeEndpoint := node.Entrance.Endpoint
		if appliedEndpoint, exists := appliedEntranceEndpoint(*state, node.ID); exists {
			activeEndpoint = appliedEndpoint
		}
		credential, err := generateCredential(activeEndpoint)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		today := billingDate(now)
		created = Membership{
			ID: membershipID, UserID: userID, Credential: credential,
			MonthlyQuotaBytes:    plan.MonthlyQuotaBytes,
			QuotaAnchorDay:       today.Day(),
			QuotaPeriodStartedOn: today,
			QuotaResetsAfter:     addCalendarMonths(today, 1),
			CreatedAt:            now,
		}
		if credentialShapeChanged(activeEndpoint, node.Entrance.Endpoint) {
			pending, pendingErr := generateCredential(node.Entrance.Endpoint)
			if pendingErr != nil {
				return pendingErr
			}
			created.PendingCredential = &pending
		}
		if plan.SubscriptionValue > 0 {
			created.SubscriptionStartedAt = now.Truncate(time.Second)
			created.SubscriptionEndsAfter = subscriptionDeadline(now, plan.SubscriptionValue, plan.SubscriptionUnit)
			created.SubscriptionValue = plan.SubscriptionValue
			created.SubscriptionUnit = plan.SubscriptionUnit
		}
		node.Memberships = append(node.Memberships, created)
		return nil
	})
	return created, err
}

func migrateSchemaV4(state *State) {
	for nodeIndex := range state.ProxyNodes {
		for membershipIndex := range state.ProxyNodes[nodeIndex].Memberships {
			membership := &state.ProxyNodes[nodeIndex].Memberships[membershipIndex]
			start := billingDate(membership.CreatedAt)
			membership.QuotaAnchorDay = start.Day()
			membership.QuotaPeriodStartedOn = start
			membership.QuotaResetsAfter = addCalendarMonths(start, 1)
		}
	}
}

func migrateSchemaV5(state *State) {
	state.UserRevision = 1
	state.AppliedRevision = state.Revision
	state.AppliedProxyNodes = topologySnapshot(state.ProxyNodes)
}

func migrateSchemaV8(state *State) {
	for nodeIndex := range state.ProxyNodes {
		for membershipIndex := range state.ProxyNodes[nodeIndex].Memberships {
			membership := &state.ProxyNodes[nodeIndex].Memberships[membershipIndex]
			// Schema v8 stored UTC calendar dates. Schema v9 uses the same
			// calendar labels in the product's fixed UTC+8 billing clock.
			membership.QuotaPeriodStartedOn = legacyUTCDateToBillingDate(membership.QuotaPeriodStartedOn)
			membership.QuotaResetsAfter = legacyUTCDateToBillingDate(membership.QuotaResetsAfter)
			if membership.LegacySubscriptionMonths == 0 {
				continue
			}
			membership.SubscriptionValue = membership.LegacySubscriptionMonths
			membership.SubscriptionUnit = SubscriptionMonths
			membership.SubscriptionStartedAt = membership.CreatedAt.UTC().Truncate(time.Second)
			lastValidDate := legacyUTCDateToBillingDate(membership.SubscriptionEndsAfter)
			membership.SubscriptionEndsAfter = lastValidDate.AddDate(0, 0, 1)
			membership.LegacySubscriptionMonths = 0
		}
	}
}

func legacyUTCDateToBillingDate(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, billingLocation)
}

func (s *Store) RemoveMembership(nodeID, userID string) error {
	return s.mutateUserProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		before := len(node.Memberships)
		node.Memberships = slices.DeleteFunc(node.Memberships, func(membership Membership) bool {
			return membership.UserID == userID
		})
		if len(node.Memberships) == before {
			return ErrNotFound
		}
		return nil
	})
}

// ResetMembershipCredential rotates the active entrance secret immediately.
// If a topology draft changes the entrance credential shape, a distinct
// candidate secret is staged for activation with that topology.
func (s *Store) ResetMembershipCredential(nodeID, userID string) error {
	return s.mutateUserProxyNode(nodeID, func(state *State, node *ProxyNode) error {
		return resetMembershipCredential(state, node, userID)
	})
}

// ResetUserCredentials rotates every Membership secret owned by one End User
// in a single user-plane mutation. Disabled and expired Memberships are also
// rotated so restoring them later cannot revive an old credential.
func (s *Store) ResetUserCredentials(userID string) (int, error) {
	rotated := 0
	err := s.mutateUser(func(state *State) error {
		if !slices.ContainsFunc(state.Users, func(user User) bool { return user.ID == userID }) {
			return ErrNotFound
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
	return rotated, err
}

func resetMembershipCredential(state *State, node *ProxyNode, userID string) error {
	membership := membershipForUser(node, userID)
	if membership == nil {
		return ErrNotFound
	}
	activeEndpoint := node.Entrance.Endpoint
	if appliedEndpoint, exists := appliedEntranceEndpoint(*state, node.ID); exists {
		activeEndpoint = appliedEndpoint
	}
	credential, err := generateCredential(activeEndpoint)
	if err != nil {
		return err
	}
	membership.Credential = credential
	membership.PendingCredential = nil
	if credentialShapeChanged(activeEndpoint, node.Entrance.Endpoint) {
		pending, pendingErr := generateCredential(node.Entrance.Endpoint)
		if pendingErr != nil {
			return pendingErr
		}
		membership.PendingCredential = &pending
	}
	return nil
}

func (s *Store) AddLink(nodeID string, input AddLinkInput) (Link, Hop, error) {
	link, child, _, err := s.addLink(nodeID, input, nil, false)
	return link, child, err
}

// AddBranch atomically creates a conditional Rule or ALL fallback, its Link,
// and the Link's child Hop. A non-entrance Hop is therefore never exposed as a
// standalone editor artifact or left behind when validation fails.
func (s *Store) AddBranch(nodeID string, input AddBranchInput) (Link, Hop, Rule, error) {
	values := normalizeValues(input.Values)
	if err := validateRule(Rule{Match: input.Match, Values: values}); err != nil {
		return Link{}, Hop{}, Rule{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	if input.Match == MatchNone {
		return s.addLink(nodeID, input.AddLinkInput, nil, true)
	}
	ruleID, err := randomID("rul")
	if err != nil {
		return Link{}, Hop{}, Rule{}, err
	}
	rule := &Rule{ID: ruleID, Match: input.Match, Values: values}
	return s.addLink(nodeID, input.AddLinkInput, rule, false)
}

// AddBlockBranch creates a conditional terminal branch that rejects matching
// traffic on its parent Hop. It deliberately creates no Link, credential, or
// child Hop.
func (s *Store) AddBlockBranch(nodeID string, input AddBlockBranchInput) (BlockBranch, error) {
	input.ParentHopID = strings.TrimSpace(input.ParentHopID)
	values := normalizeValues(input.Values)
	if input.Match == MatchNone {
		return BlockBranch{}, fmt.Errorf("%w: BLOCK requires a conditional match", ErrInvalidState)
	}
	if err := validateRule(Rule{Match: input.Match, Values: values}); err != nil {
		return BlockBranch{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	ruleID, err := randomID("rul")
	if err != nil {
		return BlockBranch{}, err
	}
	now := s.now().UTC()
	created := BlockBranch{
		ParentHopID: input.ParentHopID,
		Rule:        Rule{ID: ruleID, Match: input.Match, Values: values},
		CreatedAt:   now, UpdatedAt: now,
	}
	err = s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		if !slices.ContainsFunc(node.Hops, func(hop Hop) bool { return hop.ID == input.ParentHopID }) {
			return ErrNotFound
		}
		created.Rule.Order = ruleCountForHop(*node, input.ParentHopID)
		node.BlockBranches = append(node.BlockBranches, created)
		return nil
	})
	return created, err
}

func (s *Store) addLink(nodeID string, input AddLinkInput, rule *Rule, fallback bool) (Link, Hop, Rule, error) {
	input.ParentHopID = strings.TrimSpace(input.ParentHopID)
	input.ChildAgent = strings.TrimSpace(input.ChildAgent)
	input.Endpoint = normalizeEndpoint(input.Endpoint)
	if input.Final.Type == "" {
		input.Final = Target{Type: TargetDirect}
	}
	if !validAgentID(input.ChildAgent) {
		return Link{}, Hop{}, Rule{}, fmt.Errorf("%w: invalid child Hop", ErrInvalidState)
	}
	if (input.Final.Type != TargetDirect && input.Final.Type != TargetReject) || input.Final.LinkID != "" {
		return Link{}, Hop{}, Rule{}, fmt.Errorf("%w: initial terminal exit must be Direct or Reject", ErrInvalidState)
	}
	if err := generateEndpointSecrets(&input.Endpoint); err != nil {
		return Link{}, Hop{}, Rule{}, err
	}
	linkID, err := randomID("lnk")
	if err != nil {
		return Link{}, Hop{}, Rule{}, err
	}
	hopID, err := randomID("hop")
	if err != nil {
		return Link{}, Hop{}, Rule{}, err
	}
	credential, err := generateCredential(input.Endpoint)
	if err != nil {
		return Link{}, Hop{}, Rule{}, err
	}
	now := s.now().UTC()
	child := Hop{ID: hopID, Name: input.ChildAgent, AgentID: input.ChildAgent, Final: input.Final, CreatedAt: now, UpdatedAt: now}
	link := Link{ID: linkID, ParentHopID: input.ParentHopID, ChildHopID: hopID, Fallback: fallback, Endpoint: input.Endpoint, Credential: credential, CreatedAt: now, UpdatedAt: now}
	createdRule := Rule{}
	if rule != nil {
		createdRule = *rule
		link.Rules = []Rule{createdRule}
	}
	err = s.mutateProxyNode(nodeID, func(state *State, node *ProxyNode) error {
		if !slices.ContainsFunc(node.Hops, func(hop Hop) bool { return hop.ID == input.ParentHopID }) {
			return ErrNotFound
		}
		link.Order = len(orderedSiblingLinkIndexes(*node, input.ParentHopID))
		for siblingIndex := range node.Links {
			sibling := &node.Links[siblingIndex]
			if sibling.ParentHopID != input.ParentHopID || !sibling.Fallback {
				continue
			}
			if fallback {
				return fmt.Errorf("%w: Hop already has an ALL fallback branch", ErrConflict)
			}
			link.Order = sibling.Order
			sibling.Order++
			break
		}
		if rule != nil {
			createdRule.Order = ruleCountForHop(*node, input.ParentHopID)
			link.Rules[0] = createdRule
		}
		node.Hops = append(node.Hops, child)
		node.Links = append(node.Links, link)
		return validateListenerLayout(state)
	})
	return link, child, createdRule, err
}

func (s *Store) UpdateLink(nodeID, linkID string, endpoint Endpoint) error {
	endpoint = normalizeEndpoint(endpoint)
	return s.mutateProxyNode(nodeID, func(state *State, node *ProxyNode) error {
		for index := range node.Links {
			if node.Links[index].ID != linkID {
				continue
			}
			return applySharedListenerEdit(state, &node.Links[index].Endpoint, endpoint, s.now().UTC())
		}
		return ErrNotFound
	})
}

// MoveHop changes the Agent hosting a Hop while preserving the Hop identity,
// terminal, incoming Link, and complete downstream subtree.
func (s *Store) MoveHop(nodeID, hopID, agentID string) error {
	agentID = strings.TrimSpace(agentID)
	if !validAgentID(agentID) {
		return fmt.Errorf("%w: invalid Hop", ErrInvalidState)
	}
	return s.mutateProxyNode(nodeID, func(state *State, node *ProxyNode) error {
		for index := range node.Hops {
			if node.Hops[index].ID == hopID {
				node.Hops[index].Name = agentID
				node.Hops[index].AgentID = agentID
				node.Hops[index].UpdatedAt = s.now().UTC()
				return validateListenerLayout(state)
			}
		}
		return ErrNotFound
	})
}

// UpdateHop is retained for callers compiled against the previous API. Hop
// names are no longer independently mutable.
func (s *Store) UpdateHop(nodeID, hopID, _ string, agentID string) error {
	return s.MoveHop(nodeID, hopID, agentID)
}

// ReplaceLinkDestination retains a Link's routing identity and priority while
// replacing everything downstream of it with one fresh terminal Hop. The Link
// credential is rotated because the removed destination knew the old secret.
func (s *Store) ReplaceLinkDestination(nodeID, linkID, agentID string, endpoint Endpoint, final Target) (Hop, error) {
	agentID = strings.TrimSpace(agentID)
	endpoint = normalizeEndpoint(endpoint)
	if final.Type == "" {
		final = Target{Type: TargetDirect}
	}
	if !validAgentID(agentID) {
		return Hop{}, fmt.Errorf("%w: invalid destination Agent", ErrInvalidState)
	}
	if (final.Type != TargetDirect && final.Type != TargetReject) || final.LinkID != "" {
		return Hop{}, fmt.Errorf("%w: replacement terminal exit must be Direct or Reject", ErrInvalidState)
	}
	if err := generateEndpointSecrets(&endpoint); err != nil {
		return Hop{}, err
	}
	hopID, err := randomID("hop")
	if err != nil {
		return Hop{}, err
	}
	credential, err := generateCredential(endpoint)
	if err != nil {
		return Hop{}, err
	}
	now := s.now().UTC()
	created := Hop{ID: hopID, Name: agentID, AgentID: agentID, Final: final, CreatedAt: now, UpdatedAt: now}
	err = s.mutateProxyNode(nodeID, func(state *State, node *ProxyNode) error {
		rootIndex := slices.IndexFunc(node.Links, func(link Link) bool { return link.ID == linkID })
		if rootIndex < 0 {
			return ErrNotFound
		}
		removeHops := descendantHops(*node, node.Links[rootIndex].ChildHopID)
		node.Hops = slices.DeleteFunc(node.Hops, func(hop Hop) bool { return removeHops[hop.ID] })
		node.Links = slices.DeleteFunc(node.Links, func(link Link) bool {
			return link.ID != linkID && (removeHops[link.ParentHopID] || removeHops[link.ChildHopID])
		})
		node.BlockBranches = slices.DeleteFunc(node.BlockBranches, func(branch BlockBranch) bool {
			return removeHops[branch.ParentHopID]
		})
		node.Hops = append(node.Hops, created)
		rootIndex = slices.IndexFunc(node.Links, func(link Link) bool { return link.ID == linkID })
		root := &node.Links[rootIndex]
		root.ChildHopID = created.ID
		root.Endpoint = endpoint
		root.Credential = credential
		root.UpdatedAt = now
		normalizeLinkOrders(node)
		normalizeRuleOrders(node)
		return validateListenerLayout(state)
	})
	return created, err
}

func descendantHops(node ProxyNode, rootHopID string) map[string]bool {
	result := map[string]bool{rootHopID: true}
	changed := true
	for changed {
		changed = false
		for _, link := range node.Links {
			if result[link.ParentHopID] && !result[link.ChildHopID] {
				result[link.ChildHopID] = true
				changed = true
			}
		}
	}
	return result
}

func (s *Store) DeleteLink(nodeID, linkID string) error {
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		rootIndex := slices.IndexFunc(node.Links, func(link Link) bool { return link.ID == linkID })
		if rootIndex < 0 {
			return ErrNotFound
		}
		removeHops := descendantHops(*node, node.Links[rootIndex].ChildHopID)
		removeLinks := make(map[string]bool)
		for _, link := range node.Links {
			if link.ID == linkID || removeHops[link.ParentHopID] || removeHops[link.ChildHopID] {
				removeLinks[link.ID] = true
			}
		}
		node.Hops = slices.DeleteFunc(node.Hops, func(hop Hop) bool { return removeHops[hop.ID] })
		node.Links = slices.DeleteFunc(node.Links, func(link Link) bool { return removeLinks[link.ID] })
		node.BlockBranches = slices.DeleteFunc(node.BlockBranches, func(branch BlockBranch) bool { return removeHops[branch.ParentHopID] })
		normalizeLinkOrders(node)
		normalizeRuleOrders(node)
		return nil
	})
}

func (s *Store) AddRule(nodeID string, input AddRuleInput) (Rule, error) {
	values := normalizeValues(input.Values)
	if err := validateRule(Rule{Match: input.Match, Values: values}); err != nil {
		return Rule{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	fallback := input.Match == MatchNone
	created := Rule{Match: input.Match, Values: values}
	if !fallback {
		ruleID, err := randomID("rul")
		if err != nil {
			return Rule{}, err
		}
		created.ID = ruleID
	}
	err := s.mutateProxyNode(nodeID, func(state *State, node *ProxyNode) error {
		index := slices.IndexFunc(node.Links, func(link Link) bool { return link.ID == input.LinkID })
		if index < 0 {
			return ErrNotFound
		}
		link := &node.Links[index]
		if link.Fallback {
			return fmt.Errorf("%w: fallback Link cannot contain match rules", ErrConflict)
		}
		if fallback {
			for siblingIndex := range node.Links {
				sibling := node.Links[siblingIndex]
				if sibling.ID != link.ID && sibling.ParentHopID == link.ParentHopID && sibling.Fallback {
					return fmt.Errorf("%w: Hop already has an ALL fallback branch", ErrConflict)
				}
			}
			if len(link.Rules) == 0 {
				link.Fallback = true
				link.UpdatedAt = s.now().UTC()
				normalizeLinkOrders(node)
				return nil
			}
			if len(link.Rules) != 1 {
				return fmt.Errorf("%w: Link has more than one routing Rule", ErrInvalidState)
			}
			clonedLink, clonedHops, clonedLinks, clonedBlocks, err := cloneLinkBranch(*node, *link, s.now().UTC())
			if err != nil {
				return err
			}
			clonedLink.Rules = nil
			clonedLink.Fallback = true
			clonedLink.Order = len(orderedSiblingLinkIndexes(*node, link.ParentHopID))
			node.Hops = append(node.Hops, clonedHops...)
			node.Links = append(node.Links, clonedLink)
			node.Links = append(node.Links, clonedLinks...)
			node.BlockBranches = append(node.BlockBranches, clonedBlocks...)
			normalizeLinkOrders(node)
			return validateListenerLayout(state)
		}
		created.Order = ruleCountForHop(*node, link.ParentHopID)
		if len(link.Rules) == 0 {
			link.Rules = []Rule{created}
			link.UpdatedAt = s.now().UTC()
			return nil
		}
		if len(link.Rules) != 1 {
			return fmt.Errorf("%w: Link has more than one routing Rule", ErrInvalidState)
		}
		clonedLink, clonedHops, clonedLinks, clonedBlocks, err := cloneLinkBranch(*node, *link, s.now().UTC())
		if err != nil {
			return err
		}
		clonedLink.Rules = []Rule{created}
		clonedLink.Order = len(orderedSiblingLinkIndexes(*node, link.ParentHopID))
		for siblingIndex := range node.Links {
			if node.Links[siblingIndex].ParentHopID == link.ParentHopID && node.Links[siblingIndex].Fallback {
				clonedLink.Order = node.Links[siblingIndex].Order
				node.Links[siblingIndex].Order++
				break
			}
		}
		node.Hops = append(node.Hops, clonedHops...)
		node.Links = append(node.Links, clonedLink)
		node.Links = append(node.Links, clonedLinks...)
		node.BlockBranches = append(node.BlockBranches, clonedBlocks...)
		return validateListenerLayout(state)
	})
	return created, err
}

func (s *Store) UpdateRule(nodeID, ruleID string, input UpdateRuleInput) error {
	values := normalizeValues(input.Values)
	if err := validateRule(Rule{Match: input.Match, Values: values}); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		linkIndex := slices.IndexFunc(node.Links, func(link Link) bool { return link.ID == input.LinkID })
		if linkIndex < 0 {
			return ErrNotFound
		}
		link := &node.Links[linkIndex]
		ruleIndex := slices.IndexFunc(link.Rules, func(rule Rule) bool { return rule.ID == ruleID })
		if ruleIndex < 0 {
			return ErrNotFound
		}
		if input.Match == MatchNone {
			for siblingIndex := range node.Links {
				sibling := node.Links[siblingIndex]
				if sibling.ID != link.ID && sibling.ParentHopID == link.ParentHopID && sibling.Fallback {
					return fmt.Errorf("%w: Hop already has an ALL fallback branch", ErrConflict)
				}
			}
			link.Rules = nil
			link.Fallback = true
			link.UpdatedAt = s.now().UTC()
			normalizeLinkOrders(node)
			normalizeRuleOrders(node)
			return nil
		}
		updated := link.Rules[ruleIndex]
		updated.Match = input.Match
		updated.Values = values
		link.Rules[ruleIndex] = updated
		link.UpdatedAt = s.now().UTC()
		return nil
	})
}

func (s *Store) DeleteRule(nodeID, linkID, ruleID string) error {
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		for index := range node.Links {
			if node.Links[index].ID != linkID {
				continue
			}
			before := len(node.Links[index].Rules)
			node.Links[index].Rules = slices.DeleteFunc(node.Links[index].Rules, func(rule Rule) bool { return rule.ID == ruleID })
			if len(node.Links[index].Rules) == before {
				return ErrNotFound
			}
			normalizeRuleOrders(node)
			return nil
		}
		return ErrNotFound
	})
}

func (s *Store) MoveRule(nodeID, linkID, ruleID string, delta int) error {
	if delta != -1 && delta != 1 {
		return fmt.Errorf("%w: invalid Rule movement", ErrInvalidState)
	}
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		linkIndex := slices.IndexFunc(node.Links, func(link Link) bool { return link.ID == linkID })
		if linkIndex < 0 || !slices.ContainsFunc(node.Links[linkIndex].Rules, func(rule Rule) bool { return rule.ID == ruleID }) {
			return ErrNotFound
		}
		ordered := orderedRulesForHop(*node, node.Links[linkIndex].ParentHopID)
		index := slices.IndexFunc(ordered, func(entry orderedRule) bool { return entry.rule.ID == ruleID })
		target := index + delta
		if target < 0 || target >= len(ordered) {
			return nil
		}
		ordered[index], ordered[target] = ordered[target], ordered[index]
		applyRuleOrder(node, ordered)
		return nil
	})
}

func (s *Store) UpdateBlockBranch(nodeID, ruleID string, input UpdateRuleInput) error {
	values := normalizeValues(input.Values)
	if input.Match == MatchNone {
		return fmt.Errorf("%w: BLOCK requires a conditional match", ErrInvalidState)
	}
	if err := validateRule(Rule{Match: input.Match, Values: values}); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		for index := range node.BlockBranches {
			if node.BlockBranches[index].Rule.ID != ruleID {
				continue
			}
			node.BlockBranches[index].Rule.Match = input.Match
			node.BlockBranches[index].Rule.Values = values
			node.BlockBranches[index].UpdatedAt = s.now().UTC()
			return nil
		}
		return ErrNotFound
	})
}

func (s *Store) DeleteBlockBranch(nodeID, ruleID string) error {
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		before := len(node.BlockBranches)
		node.BlockBranches = slices.DeleteFunc(node.BlockBranches, func(branch BlockBranch) bool { return branch.Rule.ID == ruleID })
		if len(node.BlockBranches) == before {
			return ErrNotFound
		}
		normalizeRuleOrders(node)
		return nil
	})
}

func (s *Store) MoveBlockBranch(nodeID, ruleID string, delta int) error {
	if delta != -1 && delta != 1 {
		return fmt.Errorf("%w: invalid Rule movement", ErrInvalidState)
	}
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		branchIndex := slices.IndexFunc(node.BlockBranches, func(branch BlockBranch) bool { return branch.Rule.ID == ruleID })
		if branchIndex < 0 {
			return ErrNotFound
		}
		ordered := orderedRulesForHop(*node, node.BlockBranches[branchIndex].ParentHopID)
		index := slices.IndexFunc(ordered, func(entry orderedRule) bool { return entry.rule.ID == ruleID })
		target := index + delta
		if target < 0 || target >= len(ordered) {
			return nil
		}
		ordered[index], ordered[target] = ordered[target], ordered[index]
		applyRuleOrder(node, ordered)
		return nil
	})
}

func (s *Store) ReorderRules(nodeID, hopID string, ruleIDs []string) error {
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		if !slices.ContainsFunc(node.Hops, func(hop Hop) bool { return hop.ID == hopID }) {
			return ErrNotFound
		}
		ordered := orderedRulesForHop(*node, hopID)
		if len(ruleIDs) != len(ordered) {
			return fmt.Errorf("%w: reordered Rule set is incomplete", ErrConflict)
		}
		byID := make(map[string]orderedRule, len(ordered))
		for _, entry := range ordered {
			byID[entry.rule.ID] = entry
		}
		next := make([]orderedRule, 0, len(ordered))
		for _, id := range ruleIDs {
			entry, exists := byID[id]
			if !exists {
				return fmt.Errorf("%w: reordered Rule does not belong to this Hop", ErrConflict)
			}
			delete(byID, id)
			next = append(next, entry)
		}
		if len(byID) != 0 {
			return fmt.Errorf("%w: reordered Rule set contains duplicates", ErrConflict)
		}
		applyRuleOrder(node, next)
		return nil
	})
}

func (s *Store) MoveLink(nodeID, linkID string, delta int) error {
	if delta != -1 && delta != 1 {
		return fmt.Errorf("%w: invalid Link movement", ErrInvalidState)
	}
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		index := slices.IndexFunc(node.Links, func(link Link) bool { return link.ID == linkID })
		if index < 0 {
			return ErrNotFound
		}
		link := &node.Links[index]
		siblings := orderedSiblingLinkIndexes(*node, link.ParentHopID)
		position := slices.Index(siblings, index)
		target := position + delta
		if target < 0 || target >= len(siblings) {
			return nil
		}
		if (link.Fallback && delta < 0) || (node.Links[siblings[target]].Fallback && delta > 0) {
			return fmt.Errorf("%w: fallback Link must remain last", ErrConflict)
		}
		other := &node.Links[siblings[target]]
		link.Order, other.Order = other.Order, link.Order
		return nil
	})
}

func (s *Store) SetLinkFallback(nodeID, linkID string, fallback bool) error {
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		index := slices.IndexFunc(node.Links, func(link Link) bool { return link.ID == linkID })
		if index < 0 {
			return ErrNotFound
		}
		parentID := node.Links[index].ParentHopID
		if fallback {
			for siblingIndex := range node.Links {
				if node.Links[siblingIndex].ParentHopID == parentID {
					node.Links[siblingIndex].Fallback = false
				}
			}
			node.Links[index].Rules = nil
			node.Links[index].Fallback = true
			normalizeLinkOrders(node)
			normalizeRuleOrders(node)
			return nil
		}
		node.Links[index].Fallback = false
		return nil
	})
}

func (s *Store) SetFinal(nodeID, hopID string, target Target) error {
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		for index := range node.Hops {
			if node.Hops[index].ID == hopID {
				node.Hops[index].Final = target
				node.Hops[index].UpdatedAt = s.now().UTC()
				return nil
			}
		}
		return ErrNotFound
	})
}

func (s *Store) UpsertRuleSet(nodeID string, ruleSet CustomRuleSet) error {
	ruleSet.Tag = strings.TrimSpace(ruleSet.Tag)
	ruleSet.URL = strings.TrimSpace(ruleSet.URL)
	ruleSet.Format = "binary"
	if strings.TrimSpace(ruleSet.UpdateInterval) == "" {
		ruleSet.UpdateInterval = "1d"
	}
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		for index := range node.RuleSets {
			if node.RuleSets[index].Tag == ruleSet.Tag {
				node.RuleSets[index] = ruleSet
				return nil
			}
		}
		node.RuleSets = append(node.RuleSets, ruleSet)
		return nil
	})
}

func (s *Store) DeleteRuleSet(nodeID, tag string) error {
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		before := len(node.RuleSets)
		node.RuleSets = slices.DeleteFunc(node.RuleSets, func(ruleSet CustomRuleSet) bool { return ruleSet.Tag == tag })
		if len(node.RuleSets) == before {
			return ErrNotFound
		}
		for _, link := range node.Links {
			for _, rule := range link.Rules {
				if rule.Match == MatchRuleSet && slices.Contains(rule.Values, tag) {
					return fmt.Errorf("%w: Rule Set is still referenced", ErrConflict)
				}
			}
		}
		return nil
	})
}

func (s *Store) SetManagedAgents(agentIDs []string) error {
	agentIDs = append([]string(nil), agentIDs...)
	sort.Strings(agentIDs)
	agentIDs = slices.Compact(agentIDs)
	return s.mutate(func(state *State) error {
		state.ManagedAgents = agentIDs
		return nil
	})
}

// MarkTopologyApplied atomically records the topology that is actually active
// on the fleet. Memberships are deliberately excluded: they form an
// independently revisioned live plane. Pending entrance credentials become
// active only after the matching listener shape has been deployed.
func (s *Store) MarkTopologyApplied(expectedRevision uint64, agentIDs []string) error {
	agentIDs = append([]string(nil), agentIDs...)
	sort.Strings(agentIDs)
	agentIDs = slices.Compact(agentIDs)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Revision != expectedRevision {
		return ErrConflict
	}
	next := cloneState(s.state)
	credentialsChanged := false
	for nodeIndex := range next.ProxyNodes {
		for membershipIndex := range next.ProxyNodes[nodeIndex].Memberships {
			membership := &next.ProxyNodes[nodeIndex].Memberships[membershipIndex]
			if membership.PendingCredential == nil {
				continue
			}
			membership.Credential = *membership.PendingCredential
			membership.PendingCredential = nil
			credentialsChanged = true
		}
	}
	next.AppliedProxyNodes = topologySnapshot(next.ProxyNodes)
	next.AppliedRevision = next.Revision
	next.ManagedAgents = agentIDs
	if credentialsChanged {
		next.UserRevision++
	}
	if err := validateState(next); err != nil {
		return err
	}
	build := normalizeBuild(s.build, s.now())
	if err := s.persistStateAndAccountingLocked(next, build); err != nil {
		return err
	}
	return nil
}

// RestoreTopology rolls the desired topology back to the snapshot captured
// before an immediate topology operation. User-plane mutations are allowed to
// continue while the fleet transaction is running, so their membership plan,
// usage, subscription, and add/remove decisions are merged into the restored
// topology instead of being overwritten.
func (s *Store) RestoreTopology(expectedRevision uint64, previous State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Revision != expectedRevision {
		return ErrConflict
	}
	next := cloneState(s.state)
	currentByNode := make(map[string]ProxyNode, len(next.ProxyNodes))
	for _, node := range next.ProxyNodes {
		currentByNode[node.ID] = node
	}
	restored := make([]ProxyNode, 0, len(previous.ProxyNodes))
	liveUsers := make(map[string]struct{}, len(next.Users))
	for _, user := range next.Users {
		liveUsers[user.ID] = struct{}{}
	}
	for _, oldNode := range previous.ProxyNodes {
		node := cloneProxyNode(oldNode)
		if current, exists := currentByNode[node.ID]; exists {
			node.Memberships = mergeRestoredMemberships(oldNode.Memberships, current.Memberships)
		}
		node.Memberships = slices.DeleteFunc(node.Memberships, func(membership Membership) bool {
			_, exists := liveUsers[membership.UserID]
			return !exists
		})
		restored = append(restored, node)
	}
	next.ProxyNodes = restored
	next.Revision++
	// A failed create/delete or credential-shape edit can change the user
	// authority projection. Force a fresh reconciliation of the restored view.
	next.UserRevision++
	if err := validateState(next); err != nil {
		return err
	}
	build := normalizeBuild(s.build, s.now())
	if err := s.persistStateAndAccountingLocked(next, build); err != nil {
		return err
	}
	return nil
}

func mergeRestoredMemberships(previous, current []Membership) []Membership {
	previousByID := make(map[string]Membership, len(previous))
	for _, membership := range previous {
		previousByID[membership.ID] = membership
	}
	result := make([]Membership, 0, len(current))
	for _, live := range current {
		old, existed := previousByID[live.ID]
		if !existed {
			// This membership was added while the topology operation was in
			// flight. Its active credential was generated from the applied
			// entrance, while any candidate-only credential must be discarded.
			live.PendingCredential = nil
			result = append(result, live)
			continue
		}
		old.MonthlyQuotaBytes = live.MonthlyQuotaBytes
		old.UsedBytes = live.UsedBytes
		old.QuotaAnchorDay = live.QuotaAnchorDay
		old.QuotaPeriodStartedOn = live.QuotaPeriodStartedOn
		old.QuotaResetsAfter = live.QuotaResetsAfter
		old.SubscriptionStartedAt = live.SubscriptionStartedAt
		old.SubscriptionEndsAfter = live.SubscriptionEndsAfter
		old.SubscriptionValue = live.SubscriptionValue
		old.SubscriptionUnit = live.SubscriptionUnit
		old.LegacySubscriptionMonths = 0
		old.Credential = live.Credential
		old.DisabledReason = live.DisabledReason
		result = append(result, old)
	}
	return result
}

func (s *Store) mutateUserProxyNode(id string, mutation func(*State, *ProxyNode) error) error {
	return s.mutateUser(func(state *State) error {
		for index := range state.ProxyNodes {
			if state.ProxyNodes[index].ID == id {
				if err := mutation(state, &state.ProxyNodes[index]); err != nil {
					return err
				}
				state.ProxyNodes[index].UpdatedAt = s.now().UTC()
				return nil
			}
		}
		return ErrNotFound
	})
}

func (s *Store) mutateProxyNode(id string, mutation func(*State, *ProxyNode) error) error {
	return s.mutate(func(state *State) error {
		for index := range state.ProxyNodes {
			if state.ProxyNodes[index].ID == id {
				if err := mutation(state, &state.ProxyNodes[index]); err != nil {
					return err
				}
				state.ProxyNodes[index].UpdatedAt = s.now().UTC()
				return nil
			}
		}
		return ErrNotFound
	})
}

func (s *Store) mutate(mutation func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if err := mutation(&next); err != nil {
		return err
	}
	if _, err := reconcileSharedListenerSecrets(&next, &s.state); err != nil {
		return fmt.Errorf("reconcile shared listeners: %w", err)
	}
	next.Revision++
	if err := validateState(next); err != nil {
		return err
	}
	build := normalizeBuild(s.build, s.now())
	if err := s.persistStateAndAccountingLocked(next, build); err != nil {
		return err
	}
	return nil
}

func (s *Store) mutateUser(mutation func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if err := mutation(&next); err != nil {
		return err
	}
	next.UserRevision++
	if err := validateState(next); err != nil {
		return err
	}
	build := normalizeBuild(s.build, s.now())
	if err := s.persistStateAndAccountingLocked(next, build); err != nil {
		return err
	}
	return nil
}

// persistStateAndAccountingLocked commits low-frequency membership identity and
// policy changes across the JSON authority and SQLite accounting ledger. The
// SQLite transaction remains open while the JSON file is atomically replaced.
// A crash before SQLite commit rolls that transaction back; startup then
// reconciles the old database to the already-durable JSON state. A JSON write
// failure rolls the still-open SQL transaction back, so callers never observe
// a reported failure after only one authority changed.
func (s *Store) persistStateAndAccountingLocked(next State, build BuildInfo) error {
	if s.accounting == nil {
		return errors.New("accounting database is unavailable")
	}
	if err := s.accounting.secureFiles(); err != nil {
		return err
	}
	transaction, err := s.accounting.prepareMembershipReconciliation(next)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := s.persistLocked(next, build); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		// The JSON rename has completed. Reconcile immediately to the new JSON
		// authority so this process does not need a restart to converge. If the
		// retry also fails, restore the previous JSON while its in-memory state
		// is still available and report the mutation as failed.
		commitErr := fmt.Errorf("commit membership accounting reconciliation: %w", err)
		if retryErr := s.accounting.reconcileMemberships(next); retryErr == nil {
			s.state = next
			s.build = build
			s.rebuildIndexesLocked()
			return nil
		} else if restoreErr := s.persistLocked(s.state, s.build); restoreErr != nil {
			return errors.Join(commitErr, fmt.Errorf("retry accounting reconciliation: %w", retryErr), fmt.Errorf("restore proxy node state: %w", restoreErr))
		} else if rollbackErr := s.accounting.reconcileMemberships(s.state); rollbackErr != nil {
			return errors.Join(commitErr, fmt.Errorf("retry accounting reconciliation: %w", retryErr), fmt.Errorf("restore membership accounting: %w", rollbackErr))
		}
		return commitErr
	}
	s.state = next
	s.build = build
	s.rebuildIndexesLocked()
	return nil
}

func (s *Store) rebuildIndexesLocked() {
	s.userIndex = make(map[string]int, len(s.state.Users))
	s.subscriptionIndex = make(map[string]int, len(s.state.Users))
	for index := range s.state.Users {
		user := &s.state.Users[index]
		s.userIndex[user.ID] = index
		if user.Subscription.Token != "" {
			s.subscriptionIndex[user.Subscription.Token] = index
		}
	}
}

func (s *Store) persistLocked(state State, build BuildInfo) error {
	stored := envelope{Schema: SchemaID, SchemaVersion: SchemaVersion, LastUsedBy: build, Data: state}
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("encode proxy node state: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxStateBytes {
		return errors.New("proxy node state exceeds size limit")
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create proxy node state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".proxy-node-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary proxy node state: %w", err)
	}
	temporaryPath := temporary.Name()
	installed := false
	defer func() {
		_ = temporary.Close()
		if !installed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary proxy node state: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		return fmt.Errorf("write temporary proxy node state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("flush temporary proxy node state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary proxy node state: %w", err)
	}
	if err := replaceStateFile(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace proxy node state: %w", err)
	}
	installed = true
	return nil
}

func cloneState(state State) State {
	encoded, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	var cloned State
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		panic(err)
	}
	return cloned
}

func cloneProxyNode(node ProxyNode) ProxyNode {
	return cloneState(State{ProxyNodes: []ProxyNode{node}}).ProxyNodes[0]
}

func topologySnapshot(nodes []ProxyNode) []ProxyNode {
	result := make([]ProxyNode, len(nodes))
	for index, node := range nodes {
		result[index] = cloneProxyNode(node)
		result[index].Memberships = []Membership{}
		// Subscription address selection is master-side presentation metadata,
		// not part of the sing-box topology applied to Agents.
		result[index].SubscriptionAddressMode = ""
	}
	return result
}

func appliedEntranceEndpoint(state State, nodeID string) (Endpoint, bool) {
	for _, node := range state.AppliedProxyNodes {
		if node.ID == nodeID {
			return node.Entrance.Endpoint, true
		}
	}
	return Endpoint{}, false
}

func credentialShapeChanged(left, right Endpoint) bool {
	return left.Protocol != right.Protocol ||
		(left.Protocol == ProtocolShadowsocks && left.Method != right.Method)
}

func validateBuildInfo(build BuildInfo) error {
	if build.Component != "master" && build.Component != "agent" {
		return errors.New("last-used component is invalid")
	}
	if strings.TrimSpace(build.Version) == "" || len(build.Version) > 128 || strings.ContainsRune(build.Version, '\x00') {
		return errors.New("last-used version is invalid")
	}
	if strings.TrimSpace(build.Commit) == "" || len(build.Commit) > 128 || strings.ContainsRune(build.Commit, '\x00') {
		return errors.New("last-used commit is invalid")
	}
	if build.RecordedAt.IsZero() {
		return errors.New("last-used time is invalid")
	}
	return nil
}

func preserveEndpointSecrets(old Endpoint, next *Endpoint) {
	if old.Protocol == next.Protocol && old.Method == next.Method {
		next.ServerKey = old.ServerKey
	}
	if old.Protocol == next.Protocol && old.ObfsType == next.ObfsType {
		next.ObfsSecret = old.ObfsSecret
	}
}

func normalizeValues(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// cloneLinkBranch creates an independent logical routing context while
// preserving the branch's physical listener settings. Every cloned Link gets
// a fresh credential and every cloned Hop/Rule gets a fresh opaque identity.
// This lets compatible branches share one sing-box listener without sharing
// the auth_user that selects their downstream routing policy.
func cloneLinkBranch(node ProxyNode, root Link, now time.Time) (Link, []Hop, []Link, []BlockBranch, error) {
	children := make(map[string][]Link, len(node.Hops))
	hops := make(map[string]Hop, len(node.Hops))
	for _, hop := range node.Hops {
		hops[hop.ID] = hop
	}
	for _, link := range node.Links {
		children[link.ParentHopID] = append(children[link.ParentHopID], link)
	}
	for parent := range children {
		sort.SliceStable(children[parent], func(left, right int) bool {
			return children[parent][left].Order < children[parent][right].Order
		})
	}

	clonedHops := make([]Hop, 0)
	clonedLinks := make([]Link, 0)
	clonedBlocks := make([]BlockBranch, 0)
	active := make(map[string]bool, len(node.Hops))
	var cloneHop func(string) (string, error)
	cloneHop = func(oldHopID string) (string, error) {
		if len(clonedHops)+len(clonedLinks)+len(clonedBlocks) >= maxTopologyEntities {
			return "", fmt.Errorf("%w: cloned topology exceeds entity limit", ErrInvalidState)
		}
		if active[oldHopID] {
			return "", fmt.Errorf("%w: cannot clone a cyclic topology", ErrInvalidState)
		}
		oldHop, exists := hops[oldHopID]
		if !exists {
			return "", fmt.Errorf("%w: cloned Link references a missing Hop", ErrInvalidState)
		}
		newHopID, err := randomID("hop")
		if err != nil {
			return "", err
		}
		clonedHop := oldHop
		clonedHop.ID = newHopID
		clonedHop.LegacyRules = nil
		clonedHop.CreatedAt = now
		clonedHop.UpdatedAt = now
		clonedHops = append(clonedHops, clonedHop)
		for _, oldBranch := range node.BlockBranches {
			if oldBranch.ParentHopID != oldHopID {
				continue
			}
			clonedBranch := oldBranch
			clonedBranch.ParentHopID = newHopID
			clonedBranch.Rule.ID, err = randomID("rul")
			if err != nil {
				return "", err
			}
			clonedBranch.CreatedAt = now
			clonedBranch.UpdatedAt = now
			clonedBlocks = append(clonedBlocks, clonedBranch)
		}
		active[oldHopID] = true
		defer delete(active, oldHopID)
		for _, oldLink := range children[oldHopID] {
			newChildID, err := cloneHop(oldLink.ChildHopID)
			if err != nil {
				return "", err
			}
			newLinkID, err := randomID("lnk")
			if err != nil {
				return "", err
			}
			credential, err := generateCredential(oldLink.Endpoint)
			if err != nil {
				return "", err
			}
			clonedLink := oldLink
			clonedLink.ID = newLinkID
			clonedLink.ParentHopID = newHopID
			clonedLink.ChildHopID = newChildID
			clonedLink.Credential = credential
			clonedLink.CreatedAt = now
			clonedLink.UpdatedAt = now
			clonedLink.Rules = append([]Rule(nil), oldLink.Rules...)
			for ruleIndex := range clonedLink.Rules {
				clonedLink.Rules[ruleIndex].ID, err = randomID("rul")
				if err != nil {
					return "", err
				}
			}
			clonedLinks = append(clonedLinks, clonedLink)
		}
		return newHopID, nil
	}

	childID, err := cloneHop(root.ChildHopID)
	if err != nil {
		return Link{}, nil, nil, nil, err
	}
	linkID, err := randomID("lnk")
	if err != nil {
		return Link{}, nil, nil, nil, err
	}
	credential, err := generateCredential(root.Endpoint)
	if err != nil {
		return Link{}, nil, nil, nil, err
	}
	clonedRoot := root
	clonedRoot.ID = linkID
	clonedRoot.ChildHopID = childID
	clonedRoot.Credential = credential
	clonedRoot.CreatedAt = now
	clonedRoot.UpdatedAt = now
	return clonedRoot, clonedHops, clonedLinks, clonedBlocks, nil
}

func migrateSchemaV1(state *State) error {
	for nodeIndex := range state.ProxyNodes {
		node := &state.ProxyNodes[nodeIndex]
		linkIndexes := make(map[string]int, len(node.Links))
		ordered := make(map[string][]string, len(node.Hops))
		for index := range node.Links {
			linkIndexes[node.Links[index].ID] = index
			node.Links[index].Rules = nil
			node.Links[index].Fallback = false
		}
		for hopIndex := range node.Hops {
			hop := &node.Hops[hopIndex]
			unconditional := false
			currentLinkID := ""
			closedLinks := make(map[string]bool)
			for _, legacy := range hop.LegacyRules {
				if unconditional {
					continue
				}
				if legacy.LegacyTarget == nil {
					return fmt.Errorf("Hop %q has a Rule without a target", hop.Name)
				}
				if legacy.Match == MatchNone {
					switch legacy.LegacyTarget.Type {
					case TargetLink:
						index, exists := linkIndexes[legacy.LegacyTarget.LinkID]
						if !exists || node.Links[index].ParentHopID != hop.ID {
							return fmt.Errorf("Hop %q fallback Rule references a missing child Link", hop.Name)
						}
						link := &node.Links[index]
						link.Rules = nil
						link.Fallback = true
						if !slices.Contains(ordered[hop.ID], link.ID) {
							ordered[hop.ID] = append(ordered[hop.ID], link.ID)
						}
					case TargetDirect, TargetReject:
						hop.Final = *legacy.LegacyTarget
					default:
						return fmt.Errorf("Hop %q has an invalid fallback Rule target", hop.Name)
					}
					unconditional = true
					continue
				}
				if legacy.LegacyTarget.Type != TargetLink {
					return fmt.Errorf("Hop %q has a conditional terminal Rule that cannot be represented by Link-owned routing", hop.Name)
				}
				index, exists := linkIndexes[legacy.LegacyTarget.LinkID]
				if !exists || node.Links[index].ParentHopID != hop.ID {
					return fmt.Errorf("Hop %q Rule references a missing child Link", hop.Name)
				}
				link := &node.Links[index]
				if link.ID != currentLinkID {
					if currentLinkID != "" {
						closedLinks[currentLinkID] = true
					}
					if closedLinks[link.ID] {
						return fmt.Errorf("Hop %q interleaves Rules for Link %q; Link-owned routing cannot preserve their priority", hop.Name, link.ID)
					}
					currentLinkID = link.ID
				}
				if !slices.Contains(ordered[hop.ID], link.ID) {
					ordered[hop.ID] = append(ordered[hop.ID], link.ID)
				}
				legacy.LegacyTarget = nil
				link.Rules = append(link.Rules, legacy)
			}
			hop.LegacyRules = nil
			if unconditional {
				if hop.Final.Type == TargetLink {
					hop.Final = Target{Type: TargetReject}
				}
			} else if hop.Final.Type == TargetLink {
				index, exists := linkIndexes[hop.Final.LinkID]
				if !exists || node.Links[index].ParentHopID != hop.ID {
					return fmt.Errorf("Hop %q fallback references a missing child Link", hop.Name)
				}
				for siblingIndex := range node.Links {
					if node.Links[siblingIndex].ParentHopID == hop.ID {
						node.Links[siblingIndex].Fallback = false
					}
				}
				node.Links[index].Rules = nil
				node.Links[index].Fallback = true
				hop.Final = Target{Type: TargetReject}
			} else if hop.Final.Type != TargetDirect && hop.Final.Type != TargetReject {
				return fmt.Errorf("Hop %q has an invalid terminal fallback", hop.Name)
			}
		}
		for _, hop := range node.Hops {
			sequence := append([]string(nil), ordered[hop.ID]...)
			for _, link := range node.Links {
				if link.ParentHopID == hop.ID && !link.Fallback && !slices.Contains(sequence, link.ID) {
					sequence = append(sequence, link.ID)
				}
			}
			for _, link := range node.Links {
				if link.ParentHopID == hop.ID && link.Fallback && !slices.Contains(sequence, link.ID) {
					sequence = append(sequence, link.ID)
				}
			}
			for order, linkID := range sequence {
				node.Links[linkIndexes[linkID]].Order = order
			}
		}
		normalizeLinkOrders(node)
	}
	return nil
}

func orderedSiblingLinkIndexes(node ProxyNode, parentHopID string) []int {
	indexes := make([]int, 0)
	for index, link := range node.Links {
		if link.ParentHopID == parentHopID {
			indexes = append(indexes, index)
		}
	}
	sort.SliceStable(indexes, func(left, right int) bool {
		return node.Links[indexes[left]].Order < node.Links[indexes[right]].Order
	})
	return indexes
}

func normalizeLinkOrders(node *ProxyNode) {
	for _, hop := range node.Hops {
		indexes := orderedSiblingLinkIndexes(*node, hop.ID)
		sort.SliceStable(indexes, func(left, right int) bool {
			leftLink, rightLink := node.Links[indexes[left]], node.Links[indexes[right]]
			if leftLink.Fallback != rightLink.Fallback {
				return !leftLink.Fallback
			}
			return leftLink.Order < rightLink.Order
		})
		for order, index := range indexes {
			node.Links[index].Order = order
		}
	}
}

type orderedRule struct {
	linkIndex  int
	ruleIndex  int
	blockIndex int
	rule       Rule
}

func orderedRulesForHop(node ProxyNode, hopID string) []orderedRule {
	result := make([]orderedRule, 0)
	for linkIndex := range node.Links {
		if node.Links[linkIndex].ParentHopID != hopID {
			continue
		}
		for ruleIndex, rule := range node.Links[linkIndex].Rules {
			result = append(result, orderedRule{linkIndex: linkIndex, ruleIndex: ruleIndex, blockIndex: -1, rule: rule})
		}
	}
	for blockIndex, branch := range node.BlockBranches {
		if branch.ParentHopID == hopID {
			result = append(result, orderedRule{linkIndex: -1, ruleIndex: -1, blockIndex: blockIndex, rule: branch.Rule})
		}
	}
	sort.SliceStable(result, func(left, right int) bool { return result[left].rule.Order < result[right].rule.Order })
	return result
}

func applyRuleOrder(node *ProxyNode, ordered []orderedRule) {
	for order, entry := range ordered {
		if entry.blockIndex >= 0 {
			node.BlockBranches[entry.blockIndex].Rule.Order = order
			continue
		}
		node.Links[entry.linkIndex].Rules[entry.ruleIndex].Order = order
	}
}

func normalizeRuleOrders(node *ProxyNode) {
	for _, hop := range node.Hops {
		applyRuleOrder(node, orderedRulesForHop(*node, hop.ID))
	}
}

func ruleCountForHop(node ProxyNode, hopID string) int {
	return len(orderedRulesForHop(node, hopID))
}

func migrateSchemaV2(state *State) {
	for nodeIndex := range state.ProxyNodes {
		node := &state.ProxyNodes[nodeIndex]
		for _, hop := range node.Hops {
			order := 0
			for _, linkIndex := range orderedSiblingLinkIndexes(*node, hop.ID) {
				for ruleIndex := range node.Links[linkIndex].Rules {
					node.Links[linkIndex].Rules[ruleIndex].Order = order
					order++
				}
			}
		}
	}
}

// Schema v4 makes a visible Rule branch the credential and routing isolation
// boundary. Older Links could own several Rules, causing those visually
// distinct paths to arrive at one shared child auth_user. Split each extra Rule
// into a sibling Link and clone its downstream subtree so the migrated topology
// initially retains the same behavior while gaining independent credentials.
func migrateSchemaV3(state *State) error {
	now := time.Now().UTC()
	for nodeIndex := range state.ProxyNodes {
		node := &state.ProxyNodes[nodeIndex]
		for {
			if len(node.Hops)+len(node.Links) > maxTopologyEntities {
				return fmt.Errorf("Proxy Node %q exceeds migration entity limit", node.Name)
			}
			linkIndex := slices.IndexFunc(node.Links, func(link Link) bool { return len(link.Rules) > 1 })
			if linkIndex < 0 {
				break
			}
			original := node.Links[linkIndex]
			rules := append([]Rule(nil), original.Rules...)
			node.Links[linkIndex].Rules = []Rule{rules[0]}
			for siblingIndex := range node.Links {
				if node.Links[siblingIndex].ParentHopID == original.ParentHopID && node.Links[siblingIndex].Order > original.Order {
					node.Links[siblingIndex].Order += len(rules) - 1
				}
			}
			for ruleIndex := 1; ruleIndex < len(rules); ruleIndex++ {
				clonedRoot, clonedHops, clonedLinks, clonedBlocks, err := cloneLinkBranch(*node, original, now)
				if err != nil {
					return err
				}
				clonedRoot.Order = original.Order + ruleIndex
				clonedRoot.Rules = []Rule{rules[ruleIndex]}
				node.Hops = append(node.Hops, clonedHops...)
				node.Links = append(node.Links, clonedRoot)
				node.Links = append(node.Links, clonedLinks...)
				node.BlockBranches = append(node.BlockBranches, clonedBlocks...)
			}
		}
		normalizeLinkOrders(node)
		normalizeRuleOrders(node)
	}
	return nil
}
