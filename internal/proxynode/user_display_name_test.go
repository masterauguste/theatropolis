package proxynode

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEndUserDisplayNamesNormalizeConflictAndPersistWithoutChangingIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}

	user, err := store.CreateUser("  张 三 Cafe\u0301  ")
	if err != nil {
		t.Fatal(err)
	}
	if user.Name != "张 三 Café" {
		t.Fatalf("normalized end-user display name = %q, want %q", user.Name, "张 三 Café")
	}
	if !validID(user.ID, "usr_") {
		t.Fatalf("end-user internal ID = %q", user.ID)
	}

	if _, err := store.CreateUser("张 三 CAFÉ"); !errors.Is(err, ErrConflict) {
		t.Fatalf("canonically equivalent case-folded name error = %v, want ErrConflict", err)
	}

	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name:      "上海 节点",
		RootAgent: "edge-a",
		Entrance:  testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := store.AddMembership(node.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	originalToken := user.Subscription.Token
	originalCredential := membership.Credential.Secret
	originalAuthUser := AuthenticatedUserLabel(membership.ID)

	if err := store.RenameUser(user.ID, "  李 四  "); err != nil {
		t.Fatal(err)
	}
	renamed, ok := store.User(user.ID)
	if !ok {
		t.Fatal("renamed end user no longer exists under its internal ID")
	}
	if renamed.ID != user.ID || renamed.Name != "李 四" {
		t.Fatalf("renamed end user = %#v", renamed)
	}
	if renamed.Subscription.Token != originalToken {
		t.Fatal("renaming a management display name rotated the subscription token")
	}
	currentNode, _ := store.ProxyNode(node.ID)
	currentMembership := membershipForUser(&currentNode, user.ID)
	if currentMembership == nil || currentMembership.Credential.Secret != originalCredential {
		t.Fatal("renaming a management display name changed the Membership credential")
	}
	currentAuthUser := AuthenticatedUserLabel(currentMembership.ID)
	if currentAuthUser != originalAuthUser || !utf8.ValidString(currentAuthUser) || len(currentAuthUser) > 128 {
		t.Fatalf("renamed auth_user = %q, previous %q", currentAuthUser, originalAuthUser)
	}
	compiled, err := Compile(store.Snapshot(), testResolver{"edge-a": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Users []struct {
				Name string `json:"name"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(compiled.Configs["edge-a"], &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || len(config.Inbounds[0].Users) != 1 || config.Inbounds[0].Users[0].Name != currentAuthUser {
		t.Fatalf("compiled Unicode end-user auth identity = %#v, want %q", config.Inbounds, currentAuthUser)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	persisted, ok := reopened.User(user.ID)
	if !ok || persisted.ID != user.ID || persisted.Name != "李 四" || persisted.Subscription.Token != originalToken {
		t.Fatalf("persisted end user = %#v, exists %v", persisted, ok)
	}
}

func TestLegacyMaximumLengthEndUserNameStillOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	legacyName := strings.Repeat("a", maxLegacyDisplayNameBytes)
	user, err := store.CreateUser("legacy-user")
	if err != nil {
		t.Fatalf("create seed end user: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored envelope
	if err := json.Unmarshal(contents, &stored); err != nil {
		t.Fatal(err)
	}
	for index := range stored.Data.Users {
		if stored.Data.Users[index].ID == user.ID {
			stored.Data.Users[index].Name = legacyName
		}
	}
	contents, err = json.MarshalIndent(stored, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(contents, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testBuild())
	if err != nil {
		t.Fatalf("open state containing a legacy-length end-user name: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if persisted, ok := reopened.User(user.ID); !ok || persisted.Name != legacyName {
		t.Fatalf("persisted legacy-length end user = %#v, exists %v", persisted, ok)
	}
}

func TestEndUserAuthLabelPreservesFullMembershipID(t *testing.T) {
	membershipID := "mem_" + strings.Repeat("A", 12) + strings.Repeat("1", 20)
	if !validID(membershipID, "mem_") {
		t.Fatal("test Membership ID must be valid")
	}
	label := AuthenticatedUserLabel(membershipID)
	if !utf8.ValidString(label) {
		t.Fatalf("auth_user is invalid UTF-8: %q", label)
	}
	if len(label) > 128 {
		t.Fatalf("auth_user length = %d bytes, want <= 128", len(label))
	}
	if label != membershipID+"-m-AAAAAAAAAAAA" || !strings.HasPrefix(label, membershipID) {
		t.Fatalf("auth_user = %q, want complete Membership ID %q", label, membershipID)
	}
}

func TestCreateEndUserRejectsInvalidDisplayNameSpecifically(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	_, err = store.CreateUser("-用户")
	want := ErrInvalidState.Error() + ": invalid end user name"
	if err == nil || err.Error() != want || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("CreateUser() error = %v, want %q wrapping ErrInvalidState", err, want)
	}
	_, err = store.CreateUser(strings.Repeat("用", maxDisplayNameRunes+1))
	if err == nil || err.Error() != want || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("CreateUser() over-limit error = %v, want %q wrapping ErrInvalidState", err, want)
	}
}
