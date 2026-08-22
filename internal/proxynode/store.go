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
	mu    sync.RWMutex
	path  string
	state State
	build BuildInfo
	now   func() time.Time
}

func Open(path string, build BuildInfo) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("proxy node storage path is required")
	}
	clean := filepath.Clean(path)
	store := &Store{path: clean, build: build, now: time.Now}
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		store.state = State{Users: []User{}, ProxyNodes: []ProxyNode{}}
		store.build = normalizeBuild(build, store.now())
		if err := store.persistLocked(store.state, store.build); err != nil {
			return nil, err
		}
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
	if stored.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported schema version %d", ErrInvalidState, stored.SchemaVersion)
	}
	if err := validateBuildInfo(stored.LastUsedBy); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	if err := validateState(stored.Data); err != nil {
		return nil, err
	}
	store.state = stored.Data
	store.build = build
	return store, nil
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
	for _, user := range s.state.Users {
		if user.ID == id {
			return user, true
		}
	}
	return User{}, false
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

func (s *Store) CreateUser(name string) (User, error) {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return User{}, fmt.Errorf("%w: invalid end user name", ErrInvalidState)
	}
	id, err := randomID("usr")
	if err != nil {
		return User{}, err
	}
	now := s.now().UTC()
	created := User{ID: id, Name: name, CreatedAt: now, UpdatedAt: now}
	err = s.mutate(func(state *State) error {
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
	return s.mutate(func(state *State) error {
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
	return s.mutate(func(state *State) error {
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
	input.RootName = strings.TrimSpace(input.RootName)
	input.RootAgent = strings.TrimSpace(input.RootAgent)
	input.Entrance = normalizeEndpoint(input.Entrance)
	if input.RootName == "" {
		input.RootName = "Entrance"
	}
	if !validName(input.Name) || !validName(input.RootName) || !validAgentID(input.RootAgent) {
		return ProxyNode{}, fmt.Errorf("%w: invalid Proxy Node fields", ErrInvalidState)
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
			ID: hopID, Name: input.RootName, AgentID: input.RootAgent,
			Rules: []Rule{}, Final: Target{Type: TargetDirect}, CreatedAt: now, UpdatedAt: now,
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
		return nil
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
		return nil
	})
}

func (s *Store) UpdateEntrance(nodeID string, endpoint Endpoint) error {
	endpoint = normalizeEndpoint(endpoint)
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		old := node.Entrance.Endpoint
		preserveEndpointSecrets(old, &endpoint)
		if err := generateEndpointSecrets(&endpoint); err != nil {
			return err
		}
		credentialShapeChanged := old.Protocol != endpoint.Protocol ||
			(old.Protocol == ProtocolShadowsocks && old.Method != endpoint.Method)
		if credentialShapeChanged {
			for index := range node.Memberships {
				credential, err := generateCredential(endpoint)
				if err != nil {
					return err
				}
				node.Memberships[index].Credential = credential
			}
		}
		node.Entrance.Endpoint = endpoint
		return nil
	})
}

func (s *Store) AddMembership(nodeID, userID string) (Membership, error) {
	membershipID, err := randomID("mem")
	if err != nil {
		return Membership{}, err
	}
	var created Membership
	err = s.mutateProxyNode(nodeID, func(state *State, node *ProxyNode) error {
		if !slices.ContainsFunc(state.Users, func(user User) bool { return user.ID == userID }) {
			return ErrNotFound
		}
		if slices.ContainsFunc(node.Memberships, func(membership Membership) bool { return membership.UserID == userID }) {
			return ErrConflict
		}
		credential, err := generateCredential(node.Entrance.Endpoint)
		if err != nil {
			return err
		}
		created = Membership{ID: membershipID, UserID: userID, Credential: credential, CreatedAt: s.now().UTC()}
		node.Memberships = append(node.Memberships, created)
		return nil
	})
	return created, err
}

func (s *Store) RemoveMembership(nodeID, userID string) error {
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
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

func (s *Store) AddLink(nodeID string, input AddLinkInput) (Link, Hop, error) {
	input.ParentHopID = strings.TrimSpace(input.ParentHopID)
	input.ChildName = strings.TrimSpace(input.ChildName)
	input.ChildAgent = strings.TrimSpace(input.ChildAgent)
	input.Endpoint = normalizeEndpoint(input.Endpoint)
	if !validName(input.ChildName) || !validAgentID(input.ChildAgent) {
		return Link{}, Hop{}, fmt.Errorf("%w: invalid child Hop", ErrInvalidState)
	}
	if err := generateEndpointSecrets(&input.Endpoint); err != nil {
		return Link{}, Hop{}, err
	}
	linkID, err := randomID("lnk")
	if err != nil {
		return Link{}, Hop{}, err
	}
	hopID, err := randomID("hop")
	if err != nil {
		return Link{}, Hop{}, err
	}
	credential, err := generateCredential(input.Endpoint)
	if err != nil {
		return Link{}, Hop{}, err
	}
	now := s.now().UTC()
	child := Hop{ID: hopID, Name: input.ChildName, AgentID: input.ChildAgent, Rules: []Rule{}, Final: Target{Type: TargetDirect}, CreatedAt: now, UpdatedAt: now}
	link := Link{ID: linkID, ParentHopID: input.ParentHopID, ChildHopID: hopID, Endpoint: input.Endpoint, Credential: credential, CreatedAt: now, UpdatedAt: now}
	err = s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		if !slices.ContainsFunc(node.Hops, func(hop Hop) bool { return hop.ID == input.ParentHopID }) {
			return ErrNotFound
		}
		node.Hops = append(node.Hops, child)
		node.Links = append(node.Links, link)
		return nil
	})
	return link, child, err
}

func (s *Store) UpdateLink(nodeID, linkID string, endpoint Endpoint) error {
	endpoint = normalizeEndpoint(endpoint)
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		for index := range node.Links {
			if node.Links[index].ID != linkID {
				continue
			}
			old := node.Links[index].Endpoint
			preserveEndpointSecrets(old, &endpoint)
			if err := generateEndpointSecrets(&endpoint); err != nil {
				return err
			}
			if old.Protocol != endpoint.Protocol || (old.Protocol == ProtocolShadowsocks && old.Method != endpoint.Method) {
				credential, err := generateCredential(endpoint)
				if err != nil {
					return err
				}
				node.Links[index].Credential = credential
			}
			node.Links[index].Endpoint = endpoint
			node.Links[index].UpdatedAt = s.now().UTC()
			return nil
		}
		return ErrNotFound
	})
}

func (s *Store) UpdateHop(nodeID, hopID, name, agentID string) error {
	name = strings.TrimSpace(name)
	agentID = strings.TrimSpace(agentID)
	if !validName(name) || !validAgentID(agentID) {
		return fmt.Errorf("%w: invalid Hop", ErrInvalidState)
	}
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		for index := range node.Hops {
			if node.Hops[index].ID == hopID {
				node.Hops[index].Name = name
				node.Hops[index].AgentID = agentID
				node.Hops[index].UpdatedAt = s.now().UTC()
				return nil
			}
		}
		return ErrNotFound
	})
}

func (s *Store) DeleteLink(nodeID, linkID string) error {
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		rootIndex := slices.IndexFunc(node.Links, func(link Link) bool { return link.ID == linkID })
		if rootIndex < 0 {
			return ErrNotFound
		}
		removeHops := map[string]bool{node.Links[rootIndex].ChildHopID: true}
		changed := true
		for changed {
			changed = false
			for _, link := range node.Links {
				if removeHops[link.ParentHopID] && !removeHops[link.ChildHopID] {
					removeHops[link.ChildHopID] = true
					changed = true
				}
			}
		}
		removeLinks := make(map[string]bool)
		for _, link := range node.Links {
			if link.ID == linkID || removeHops[link.ParentHopID] || removeHops[link.ChildHopID] {
				removeLinks[link.ID] = true
			}
		}
		node.Hops = slices.DeleteFunc(node.Hops, func(hop Hop) bool { return removeHops[hop.ID] })
		node.Links = slices.DeleteFunc(node.Links, func(link Link) bool { return removeLinks[link.ID] })
		for hopIndex := range node.Hops {
			hop := &node.Hops[hopIndex]
			hop.Rules = slices.DeleteFunc(hop.Rules, func(rule Rule) bool {
				return rule.Target.Type == TargetLink && removeLinks[rule.Target.LinkID]
			})
			if hop.Final.Type == TargetLink && removeLinks[hop.Final.LinkID] {
				hop.Final = Target{Type: TargetReject}
			}
		}
		return nil
	})
}

func (s *Store) AddRule(nodeID string, input AddRuleInput) (Rule, error) {
	ruleID, err := randomID("rul")
	if err != nil {
		return Rule{}, err
	}
	created := Rule{ID: ruleID, Match: input.Match, Values: normalizeValues(input.Values), Target: input.Target}
	err = s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		for index := range node.Hops {
			if node.Hops[index].ID == input.HopID {
				node.Hops[index].Rules = append(node.Hops[index].Rules, created)
				node.Hops[index].UpdatedAt = s.now().UTC()
				return nil
			}
		}
		return ErrNotFound
	})
	return created, err
}

func (s *Store) DeleteRule(nodeID, hopID, ruleID string) error {
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		for index := range node.Hops {
			if node.Hops[index].ID != hopID {
				continue
			}
			before := len(node.Hops[index].Rules)
			node.Hops[index].Rules = slices.DeleteFunc(node.Hops[index].Rules, func(rule Rule) bool { return rule.ID == ruleID })
			if len(node.Hops[index].Rules) == before {
				return ErrNotFound
			}
			return nil
		}
		return ErrNotFound
	})
}

func (s *Store) MoveRule(nodeID, hopID, ruleID string, delta int) error {
	if delta != -1 && delta != 1 {
		return fmt.Errorf("%w: invalid Rule movement", ErrInvalidState)
	}
	return s.mutateProxyNode(nodeID, func(_ *State, node *ProxyNode) error {
		for hopIndex := range node.Hops {
			if node.Hops[hopIndex].ID != hopID {
				continue
			}
			rules := node.Hops[hopIndex].Rules
			index := slices.IndexFunc(rules, func(rule Rule) bool { return rule.ID == ruleID })
			if index < 0 {
				return ErrNotFound
			}
			target := index + delta
			if target < 0 || target >= len(rules) {
				return nil
			}
			rules[index], rules[target] = rules[target], rules[index]
			node.Hops[hopIndex].Rules = rules
			return nil
		}
		return ErrNotFound
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
		for _, hop := range node.Hops {
			for _, rule := range hop.Rules {
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
	next.Revision++
	if err := validateState(next); err != nil {
		return err
	}
	build := normalizeBuild(s.build, s.now())
	if err := s.persistLocked(next, build); err != nil {
		return err
	}
	s.state = next
	s.build = build
	return nil
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
