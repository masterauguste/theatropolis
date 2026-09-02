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

func TestProxyNodeNamesNormalizeConflictAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}

	node, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name:      "  上海 Cafe\u0301  ",
		RootAgent: "edge-a",
		Entrance:  testTLSEndpoint(ProtocolAnyTLS, 443),
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.Name != "上海 Café" {
		t.Fatalf("normalized Proxy Node name = %q, want %q", node.Name, "上海 Café")
	}

	if _, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name:      "上海 CAFÉ",
		RootAgent: "edge-b",
		Entrance:  testTLSEndpoint(ProtocolAnyTLS, 444),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("canonically equivalent case-folded name error = %v, want ErrConflict", err)
	}
	beforeRename := store.Snapshot()
	if err := store.RenameProxyNode(node.ID, "  北京 节点  "); err != nil {
		t.Fatal(err)
	}
	afterRename := store.Snapshot()
	if afterRename.Revision != beforeRename.Revision+1 ||
		afterRename.UserRevision != beforeRename.UserRevision {
		t.Fatalf(
			"rename revisions = topology %d, users %d; want %d, %d",
			afterRename.Revision,
			afterRename.UserRevision,
			beforeRename.Revision+1,
			beforeRename.UserRevision,
		)
	}
	renamed, ok := store.ProxyNode(node.ID)
	if !ok || renamed.Name != "北京 节点" {
		t.Fatalf("renamed Proxy Node = %#v, exists %v", renamed, ok)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	persisted, ok := reopened.ProxyNode(node.ID)
	if !ok {
		t.Fatal("normalized Proxy Node was not persisted")
	}
	if persisted.Name != "北京 节点" {
		t.Fatalf("persisted Proxy Node name = %q, want %q", persisted.Name, "北京 节点")
	}
}

func TestCreateProxyNodeReturnsSpecificFieldErrors(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "proxy-node-state.json"), testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	tests := []struct {
		name  string
		input CreateProxyNodeInput
		want  string
	}{
		{
			name: "invalid name",
			input: CreateProxyNodeInput{
				Name: "-节点", RootAgent: "edge-a",
				Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
			},
			want: ErrInvalidState.Error() + ": invalid Proxy Node name",
		},
		{
			name: "invalid entrance Agent",
			input: CreateProxyNodeInput{
				Name: "节点 A", RootAgent: "edge a",
				Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
			},
			want: ErrInvalidState.Error() + ": invalid entrance Agent",
		},
		{
			name: "name beyond editor limit",
			input: CreateProxyNodeInput{
				Name: strings.Repeat("节", maxDisplayNameRunes+1), RootAgent: "edge-a",
				Entrance: testTLSEndpoint(ProtocolAnyTLS, 443),
			},
			want: ErrInvalidState.Error() + ": invalid Proxy Node name",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := store.CreateProxyNode(test.input)
			if err == nil || err.Error() != test.want {
				t.Fatalf("CreateProxyNode() error = %v, want %q", err, test.want)
			}
			if !errors.Is(err, ErrInvalidState) {
				t.Fatalf("CreateProxyNode() error = %v, want ErrInvalidState", err)
			}
		})
	}
}

func TestLegacyMaximumLengthProxyNodeNameStillOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-node-state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	legacyName := strings.Repeat("a", maxLegacyDisplayNameBytes)
	if _, err := store.CreateProxyNode(CreateProxyNodeInput{
		Name:      "legacy-node",
		RootAgent: "edge-a",
		Entrance:  testTLSEndpoint(ProtocolAnyTLS, 443),
	}); err != nil {
		t.Fatalf("create seed Proxy Node: %v", err)
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
	stored.Data.ProxyNodes[0].Name = legacyName
	contents, err = json.MarshalIndent(stored, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(contents, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testBuild())
	if err != nil {
		t.Fatalf("open state containing a legacy-length Proxy Node name: %v", err)
	}
	_ = reopened.Close()
}

func TestAuthLabelsPreserveFullOpaqueIDsWithoutTruncation(t *testing.T) {
	membershipID := "mem_" + strings.Repeat("A", 12) + strings.Repeat("1", 20)
	linkID := "lnk_" + strings.Repeat("B", 12) + strings.Repeat("2", 20)
	labels := []struct {
		name     string
		value    string
		fullID   string
		expected string
	}{
		{
			name:     "Membership",
			value:    AuthenticatedUserLabel(membershipID),
			fullID:   membershipID,
			expected: membershipID + "-m-AAAAAAAAAAAA",
		},
		{
			name:     "Link",
			value:    linkUserLabel(linkID),
			fullID:   linkID,
			expected: linkID + "-link-l-BBBBBBBBBBBB",
		},
	}

	for _, label := range labels {
		t.Run(label.name, func(t *testing.T) {
			if !utf8.ValidString(label.value) {
				t.Fatalf("auth_user is invalid UTF-8: %q", label.value)
			}
			if len(label.value) > 128 {
				t.Fatalf("auth_user length = %d bytes, want <= 128", len(label.value))
			}
			if label.value != label.expected || !strings.HasPrefix(label.value, label.fullID) {
				t.Fatalf("auth_user = %q, want complete opaque ID in %q", label.value, label.expected)
			}
		})
	}
}
