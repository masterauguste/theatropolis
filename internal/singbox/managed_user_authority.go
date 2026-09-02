package singbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

const (
	managedUserAuthorityFilename = "user-authority.json"
	managedUserAuthorityVersion  = 1
	maxManagedAuthorityBytes     = 8 << 20
	maxManagedAuthorityVariants  = 8

	// ManagedUserAuthorityTopologyMismatchDiagnostic is deliberately stable so
	// the master can distinguish a stale Agent topology from a generic runtime
	// failure and immediately replay its retained authoritative profile.
	ManagedUserAuthorityTopologyMismatchDiagnostic = "managed-user authority does not describe the active topology"
)

// ManagedUserAuthorityUser is one end-user identity. Link credentials are
// deliberately excluded: they remain owned exclusively by the topology plane.
type ManagedUserAuthorityUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ManagedUserAuthorityEndpoint binds the complete desired end-user set to one
// managed listener path within a particular topology shape.
type ManagedUserAuthorityEndpoint struct {
	Path  string                     `json:"path"`
	Users []ManagedUserAuthorityUser `json:"users"`
}

// ManagedUserAuthorityVariant is a user-plane projection for one topology
// shape. A command normally carries both the last-applied and current draft
// shapes so it remains valid while a fleet topology transaction is in flight.
type ManagedUserAuthorityVariant struct {
	TopologySHA256 [sha256.Size]byte              `json:"topology_sha256"`
	Endpoints      []ManagedUserAuthorityEndpoint `json:"endpoints"`
}

type managedUserAuthorityState struct {
	Version  int                           `json:"version"`
	Revision uint64                        `json:"revision"`
	Variants []ManagedUserAuthorityVariant `json:"variants"`
}

func cloneManagedUserAuthorityVariants(source []ManagedUserAuthorityVariant) []ManagedUserAuthorityVariant {
	result := make([]ManagedUserAuthorityVariant, len(source))
	for index, variant := range source {
		result[index] = variant
		result[index].Endpoints = make([]ManagedUserAuthorityEndpoint, len(variant.Endpoints))
		for endpointIndex, endpoint := range variant.Endpoints {
			result[index].Endpoints[endpointIndex] = endpoint
			result[index].Endpoints[endpointIndex].Users = append([]ManagedUserAuthorityUser(nil), endpoint.Users...)
		}
	}
	return result
}

func managedUserAuthoritiesEqual(left, right managedUserAuthorityState) bool {
	return reflect.DeepEqual(left, right)
}

// BuildManagedUserAuthorityVariant extracts only generated membership users
// from a compiled managed configuration. The structural digest deliberately
// ignores the users array and Shadowsocks's empty-listener managed marker.
func BuildManagedUserAuthorityVariant(config []byte) (ManagedUserAuthorityVariant, error) {
	parsed, err := parseManagedUserConfig(config)
	if err != nil {
		if bytes.Equal(bytes.TrimSpace(config), bytes.TrimSpace(DisabledManagedConfig())) {
			return ManagedUserAuthorityVariant{TopologySHA256: sha256.Sum256(config)}, nil
		}
		return ManagedUserAuthorityVariant{}, err
	}
	digest, err := managedTopologyDigest(parsed.Document)
	if err != nil {
		return ManagedUserAuthorityVariant{}, err
	}
	variant := ManagedUserAuthorityVariant{TopologySHA256: digest}
	for _, endpoint := range parsed.Endpoints {
		item := ManagedUserAuthorityEndpoint{Path: endpoint.Path, Users: []ManagedUserAuthorityUser{}}
		for _, user := range endpoint.Users {
			_, membership, identityErr := parseManagedMembershipIdentity(user.Username)
			if identityErr != nil {
				return ManagedUserAuthorityVariant{}, identityErr
			}
			if !membership {
				continue
			}
			item.Users = append(item.Users, ManagedUserAuthorityUser{
				Username: user.Username, Password: user.Password,
			})
		}
		variant.Endpoints = append(variant.Endpoints, item)
	}
	if err := validateManagedUserAuthorityVariant(variant); err != nil {
		return ManagedUserAuthorityVariant{}, err
	}
	return variant, nil
}

func managedTopologyDigest(document map[string]any) ([sha256.Size]byte, error) {
	inbounds, _ := document["inbounds"].([]any)
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]any)
		delete(inbound, "managed")
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// applyManagedUserAuthority overlays a matching authority variant onto config.
// Its boolean is false when the authority does not describe this topology.
func applyManagedUserAuthority(
	config []byte,
	variants []ManagedUserAuthorityVariant,
) ([]byte, bool, error) {
	if bytes.Equal(bytes.TrimSpace(config), bytes.TrimSpace(DisabledManagedConfig())) {
		return append([]byte(nil), config...), true, nil
	}
	parsed, err := parseManagedUserConfig(config)
	if err != nil {
		return nil, false, err
	}
	digest, err := managedTopologyDigest(parsed.Document)
	if err != nil {
		return nil, false, err
	}
	var selected *ManagedUserAuthorityVariant
	for index := range variants {
		if variants[index].TopologySHA256 == digest {
			selected = &variants[index]
			break
		}
	}
	if selected == nil {
		return append([]byte(nil), config...), false, nil
	}
	authority := make(map[string][]managedUser, len(selected.Endpoints))
	for _, endpoint := range selected.Endpoints {
		users := make([]managedUser, 0, len(endpoint.Users))
		for _, user := range endpoint.Users {
			users = append(users, managedUser{Username: user.Username, Password: user.Password})
		}
		authority[endpoint.Path] = users
	}
	for index := range parsed.Endpoints {
		endpoint := &parsed.Endpoints[index]
		authorizedUsers, described := authority[endpoint.Path]
		if !described {
			return nil, false, errors.New("managed-user authority omits a topology endpoint")
		}
		users := make([]managedUser, 0, len(endpoint.Users)+len(authority[endpoint.Path]))
		for _, user := range endpoint.Users {
			_, membership, identityErr := parseManagedMembershipIdentity(user.Username)
			if identityErr != nil {
				return nil, false, identityErr
			}
			if !membership {
				users = append(users, user)
			}
		}
		users = append(users, authorizedUsers...)
		sort.Slice(users, func(left, right int) bool { return users[left].Username < users[right].Username })
		for userIndex := 1; userIndex < len(users); userIndex++ {
			if users[userIndex-1].Username == users[userIndex].Username ||
				users[userIndex-1].Password == users[userIndex].Password {
				return nil, false, errors.New("managed-user authority contains a duplicate identity")
			}
		}
		endpoint.Users = users
		delete(authority, endpoint.Path)
	}
	if len(authority) != 0 {
		return nil, false, errors.New("managed-user authority references an endpoint outside its topology")
	}
	if err := installManagedEndpointUsers(parsed.Document, parsed.Endpoints); err != nil {
		return nil, false, err
	}
	encoded, err := json.MarshalIndent(parsed.Document, "", "  ")
	if err != nil {
		return nil, false, err
	}
	return append(encoded, '\n'), true, nil
}

func installManagedEndpointUsers(document map[string]any, endpoints []managedUserEndpoint) error {
	servers, err := managedUserServers(document)
	if err != nil {
		return err
	}
	byPath := make(map[string][]managedUser, len(endpoints))
	for _, endpoint := range endpoints {
		byPath[endpoint.Path] = endpoint.Users
	}
	inbounds, _ := document["inbounds"].([]any)
	byTag := make(map[string]map[string]any, len(inbounds))
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]any)
		tag, _ := inbound["tag"].(string)
		byTag[tag] = inbound
	}
	for path, tag := range servers {
		inbound := byTag[tag]
		if inbound == nil {
			return errors.New("managed-user authority references a missing inbound")
		}
		users := byPath[path]
		rawUsers := make([]any, 0, len(users))
		for _, user := range users {
			rawUsers = append(rawUsers, map[string]any{"name": user.Username, "password": user.Password})
		}
		inbound["users"] = rawUsers
		if inbound["type"] == "shadowsocks" && len(users) == 0 {
			inbound["managed"] = true
		} else {
			delete(inbound, "managed")
		}
	}
	return nil
}

func validateManagedUserAuthorityVariant(variant ManagedUserAuthorityVariant) error {
	if variant.TopologySHA256 == ([sha256.Size]byte{}) {
		return errors.New("managed-user authority topology digest is required")
	}
	seenPaths := make(map[string]struct{}, len(variant.Endpoints))
	seenMemberships := newManagedMembershipIdentityIndex()
	for _, endpoint := range variant.Endpoints {
		if !validManagedUserPath(endpoint.Path) {
			return errors.New("managed-user authority contains an invalid endpoint")
		}
		if _, exists := seenPaths[endpoint.Path]; exists {
			return errors.New("managed-user authority contains a duplicate endpoint")
		}
		seenPaths[endpoint.Path] = struct{}{}
		for _, user := range endpoint.Users {
			identity, membership, identityErr := parseManagedMembershipIdentity(user.Username)
			if identityErr != nil || !membership || strings.TrimSpace(user.Password) == "" || len(user.Username) > maxManagedUsernameBytes ||
				strings.ContainsRune(user.Username, '\x00') ||
				len(user.Password) > 256 || strings.ContainsAny(user.Password, "\x00\r\n") {
				return errors.New("managed-user authority contains an invalid user")
			}
			if err := seenMemberships.add(identity); err != nil {
				return errors.New("managed-user authority contains a duplicate membership")
			}
		}
	}
	return nil
}

func validateManagedUserAuthorityState(state managedUserAuthorityState) error {
	if state.Version != managedUserAuthorityVersion || state.Revision == 0 ||
		len(state.Variants) == 0 || len(state.Variants) > maxManagedAuthorityVariants {
		return errors.New("managed-user authority state is invalid")
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(state.Variants))
	for _, variant := range state.Variants {
		if err := validateManagedUserAuthorityVariant(variant); err != nil {
			return err
		}
		if _, exists := seen[variant.TopologySHA256]; exists {
			return errors.New("managed-user authority state contains duplicate topology variants")
		}
		seen[variant.TopologySHA256] = struct{}{}
	}
	return nil
}

func (m *Manager) loadManagedUserAuthority() (managedUserAuthorityState, bool, error) {
	path := filepath.Join(m.configDirectory, managedUserAuthorityFilename)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return managedUserAuthorityState{}, false, nil
	}
	if err != nil {
		return managedUserAuthorityState{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxManagedAuthorityBytes {
		return managedUserAuthorityState{}, false, errors.New("managed-user authority file is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return managedUserAuthorityState{}, false, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxManagedAuthorityBytes+1))
	decoder.DisallowUnknownFields()
	var state managedUserAuthorityState
	if err := decoder.Decode(&state); err != nil {
		return managedUserAuthorityState{}, false, fmt.Errorf("decode managed-user authority: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return managedUserAuthorityState{}, false, errors.New("managed-user authority contains trailing data")
	}
	if err := validateManagedUserAuthorityState(state); err != nil {
		return managedUserAuthorityState{}, false, err
	}
	return state, true, nil
}

func (m *Manager) persistManagedUserAuthority(state managedUserAuthorityState) error {
	if err := validateManagedUserAuthorityState(state); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxManagedAuthorityBytes {
		return errors.New("managed-user authority exceeds size limit")
	}
	temporary, err := os.CreateTemp(m.configDirectory, ".user-authority-*.tmp")
	if err != nil {
		return err
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
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := m.replaceFile(temporaryPath, filepath.Join(m.configDirectory, managedUserAuthorityFilename)); err != nil {
		return err
	}
	installed = true
	return syncDirectory(m.configDirectory)
}
