package singbox

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	managedMembershipIDPrefix     = "mem_"
	managedMembershipIDPayloadMin = 20
	managedMembershipIDPayloadMax = 32
	managedMembershipLegacyLen    = 12
	managedMembershipMarker       = "-m-"
	maxManagedUsernameBytes       = 128
)

var (
	errInvalidManagedMembershipIdentity   = errors.New("managed-user identity is malformed")
	errAmbiguousManagedMembershipIdentity = errors.New("managed-user identity is ambiguous")
)

// managedMembershipIdentity describes both generations of Membership label.
// Legacy readable labels carry only LegacyKey. Rolling labels carry the full
// opaque Membership ID and retain the same 12-byte key at the end solely so an
// older Agent can continue to recognize and revoke them safely.
type managedMembershipIdentity struct {
	FullID    string
	LegacyKey string
}

// parseManagedMembershipIdentity distinguishes generated Membership labels
// from topology-owned Link labels. A final, valid -m-<12> marker identifies a
// Membership. When its prefix is a complete mem_ ID, the compatibility suffix
// must be the first 12 characters of that ID's payload.
func parseManagedMembershipIdentity(name string) (managedMembershipIdentity, bool, error) {
	marker := strings.LastIndex(name, managedMembershipMarker)
	if marker < 0 {
		if validManagedMembershipFullID(name) {
			// Full IDs without the compatibility marker are not emitted during
			// this rolling generation. Treat one as malformed instead of silently
			// preserving it as a topology-owned Link identity.
			return managedMembershipIdentity{}, true, errInvalidManagedMembershipIdentity
		}
		return managedMembershipIdentity{}, false, nil
	}
	rollingPrefix := name[:marker]
	rollingPayloadLength := len(rollingPrefix) - len(managedMembershipIDPrefix)
	rollingShape := strings.HasPrefix(rollingPrefix, managedMembershipIDPrefix) &&
		rollingPayloadLength >= managedMembershipIDPayloadMin &&
		rollingPayloadLength <= managedMembershipIDPayloadMax
	if len(name)-marker-len(managedMembershipMarker) != managedMembershipLegacyLen {
		if rollingShape {
			return managedMembershipIdentity{}, true, errInvalidManagedMembershipIdentity
		}
		return managedMembershipIdentity{}, false, nil
	}
	if len(name) > maxManagedUsernameBytes || !utf8.ValidString(name) || strings.ContainsRune(name, '\x00') {
		return managedMembershipIdentity{}, true, errInvalidManagedMembershipIdentity
	}
	legacyKey := name[marker+len(managedMembershipMarker):]
	if !validManagedMembershipKey(legacyKey) {
		return managedMembershipIdentity{}, true, errInvalidManagedMembershipIdentity
	}
	identity := managedMembershipIdentity{LegacyKey: legacyKey}
	prefix := rollingPrefix
	if !rollingShape {
		return identity, true, nil
	}
	payload := prefix[len(managedMembershipIDPrefix):]
	if !validManagedMembershipIDPayload(payload) || legacyKey != payload[:managedMembershipLegacyLen] {
		return managedMembershipIdentity{}, true, errInvalidManagedMembershipIdentity
	}
	identity.FullID = prefix
	return identity, true, nil
}

func validManagedMembershipFullID(value string) bool {
	if !strings.HasPrefix(value, managedMembershipIDPrefix) {
		return false
	}
	return validManagedMembershipIDPayload(value[len(managedMembershipIDPrefix):])
}

func validManagedMembershipIDPayload(payload string) bool {
	if len(payload) < managedMembershipIDPayloadMin || len(payload) > managedMembershipIDPayloadMax {
		return false
	}
	for _, character := range payload {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validManagedMembershipKey(key string) bool {
	if len(key) != managedMembershipLegacyLen {
		return false
	}
	for _, character := range key {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// managedMembershipKey preserves the existing helper contract while preferring
// a full stable ID whenever the rolling label carries one.
func managedMembershipKey(name string) (string, bool) {
	identity, membership, err := parseManagedMembershipIdentity(name)
	if err != nil || !membership {
		return "", false
	}
	if identity.FullID != "" {
		return identity.FullID, true
	}
	return identity.LegacyKey, true
}

type managedMembershipIdentityIndex struct {
	byFull   map[string]managedMembershipIdentity
	byLegacy map[string]managedMembershipIdentity
}

func newManagedMembershipIdentityIndex() managedMembershipIdentityIndex {
	return managedMembershipIdentityIndex{
		byFull:   make(map[string]managedMembershipIdentity),
		byLegacy: make(map[string]managedMembershipIdentity),
	}
}

func (index managedMembershipIdentityIndex) add(identity managedMembershipIdentity) error {
	if _, exists := index.byLegacy[identity.LegacyKey]; exists {
		return errAmbiguousManagedMembershipIdentity
	}
	if identity.FullID != "" {
		if _, exists := index.byFull[identity.FullID]; exists {
			return errAmbiguousManagedMembershipIdentity
		}
		index.byFull[identity.FullID] = identity
	}
	index.byLegacy[identity.LegacyKey] = identity
	return nil
}

// authorizes uses the full ID when both sides have one. The legacy key is
// consulted only when exactly one side is an old readable label. Index
// construction rejects duplicate compatibility keys before this comparison.
func (index managedMembershipIdentityIndex) authorizes(candidate managedMembershipIdentity) (bool, error) {
	if candidate.FullID != "" {
		if _, exists := index.byFull[candidate.FullID]; exists {
			return true, nil
		}
	}
	active, exists := index.byLegacy[candidate.LegacyKey]
	if !exists {
		return false, nil
	}
	if active.FullID != "" && candidate.FullID != "" {
		return false, errAmbiguousManagedMembershipIdentity
	}
	return true, nil
}

func managedMembershipIdentityIndexForNames(names []string) (managedMembershipIdentityIndex, int, error) {
	index := newManagedMembershipIdentityIndex()
	count := 0
	for _, name := range names {
		identity, membership, err := parseManagedMembershipIdentity(name)
		if err != nil {
			return managedMembershipIdentityIndex{}, 0, err
		}
		if !membership {
			continue
		}
		if err := index.add(identity); err != nil {
			return managedMembershipIdentityIndex{}, 0, err
		}
		count++
	}
	return index, count, nil
}
