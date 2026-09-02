package pool

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

const (
	// encodedUserRefPrefix cannot occur in the legacy component grammar: old
	// user components must start with an ASCII letter or digit, with _server
	// as their only underscore-prefixed exception. This keeps old refs byte-for-
	// byte stable while allowing arbitrary valid managed-user labels to remain a
	// single slash-delimited ref component.
	encodedUserRefPrefix = "_user_"
	maxRawUserRefBytes   = 128
	managedUserTailBytes = 12
)

var managedUserTailMarkers = [...]string{"-m-", "-link-l-"}

// encodeUserRefComponent preserves the legacy ASCII spelling when possible
// and otherwise encodes the raw UTF-8 user name as unpadded URL-safe base64.
func encodeUserRefComponent(user string) (string, bool) {
	if user == serverKeyRefComponent || validComponent(user) {
		return user, true
	}
	if !validRawUserRefValue(user) {
		return "", false
	}
	return encodedUserRefPrefix + base64.RawURLEncoding.EncodeToString([]byte(user)), true
}

// decodeUserRefComponent accepts both the legacy ASCII spelling and the
// explicit encoded spelling. Encoded legacy values are rejected so every raw
// user name has one canonical ref and malformed aliases cannot be introduced.
func decodeUserRefComponent(component string) (string, bool) {
	if component == serverKeyRefComponent || validComponent(component) {
		return component, true
	}
	payload, found := strings.CutPrefix(component, encodedUserRefPrefix)
	if !found || payload == "" || payloadLenExceedsRawUserLimit(payload) {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != payload {
		return "", false
	}
	user := string(decoded)
	if !validRawUserRefValue(user) || user == serverKeyRefComponent || validComponent(user) {
		return "", false
	}
	return user, true
}

func payloadLenExceedsRawUserLimit(payload string) bool {
	return len(payload) > base64.RawURLEncoding.EncodedLen(maxRawUserRefBytes)
}

func validRawUserRefValue(user string) bool {
	return user != "" && len(user) <= maxRawUserRefBytes && utf8.ValidString(user) &&
		!strings.ContainsRune(user, '\x00')
}

// managedUserAliasKey returns the stable suffix retained by both generations
// of Theatropolis managed-user labels. The readable prefix changed during the
// migration to ID-based labels, but the 12-character membership/Link tail did
// not. Keeping the marker in the key prevents a membership and Link with the
// same short ID from ever aliasing each other.
func managedUserAliasKey(user string) (string, bool) {
	if !validRawUserRefValue(user) {
		return "", false
	}
	for _, marker := range managedUserTailMarkers {
		index := strings.LastIndex(user, marker)
		if index <= 0 || index+len(marker)+managedUserTailBytes != len(user) {
			continue
		}
		tail := user[index+len(marker):]
		if validManagedUserTail(tail) {
			return marker + tail, true
		}
	}
	return "", false
}

func validManagedUserTail(tail string) bool {
	if len(tail) != managedUserTailBytes {
		return false
	}
	for index := 0; index < len(tail); index++ {
		character := tail[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}
