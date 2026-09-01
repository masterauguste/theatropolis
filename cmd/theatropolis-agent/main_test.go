package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveMasterConnectionTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		configuredMaster string
		resolvedMaster   string
		dialAddress      string
		wantTarget       masterConnectionTarget
		wantError        string
	}{
		{
			name:             "ordinary remote Agent",
			configuredMaster: "master.example.com:443", resolvedMaster: "master.example.com:443",
			wantTarget: masterConnectionTarget{grpcTarget: "dns:///master.example.com:443", serverName: "master.example.com"},
		},
		{
			name:             "co-located Master",
			configuredMaster: "master.example.com:8443", resolvedMaster: "master.example.com:8443",
			dialAddress: "127.0.0.1:8443",
			wantTarget: masterConnectionTarget{
				grpcTarget: "passthrough:///master.example.com:8443", serverName: "master.example.com", dialAddress: "127.0.0.1:8443",
			},
		},
		{
			name:             "IPv6 loopback",
			configuredMaster: "master.example.com:443", resolvedMaster: "master.example.com:443",
			dialAddress: "[::1]:443",
			wantTarget: masterConnectionTarget{
				grpcTarget: "passthrough:///master.example.com:443", serverName: "master.example.com", dialAddress: "[::1]:443",
			},
		},
		{
			name:             "migration disables original local shortcut",
			configuredMaster: "old.example.com:443", resolvedMaster: "new.example.com:443",
			dialAddress: "127.0.0.1:443",
			wantTarget:  masterConnectionTarget{grpcTarget: "dns:///new.example.com:443", serverName: "new.example.com"},
		},
		{
			name:             "non-loopback override rejected",
			configuredMaster: "master.example.com:443", resolvedMaster: "master.example.com:443",
			dialAddress: "192.0.2.1:443", wantError: "loopback IP",
		},
		{
			name:             "named override port rejected",
			configuredMaster: "master.example.com:443", resolvedMaster: "master.example.com:443",
			dialAddress: "127.0.0.1:https", wantError: "numeric port",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveMasterConnectionTarget(
				test.configuredMaster,
				test.resolvedMaster,
				test.dialAddress,
			)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("resolve error = %v, want containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.wantTarget {
				t.Fatalf("target = %#v, want %#v", got, test.wantTarget)
			}
		})
	}
}

func TestRemoveLegacyAgentID(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "agent-id")
	if err := os.WriteFile(path, []byte("obsolete-server-name\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeLegacyAgentID(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("obsolete agent ID still exists: %v", err)
	}
}

func TestRemoveLegacyAgentIDRejectsSymlink(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("do not remove\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent-id")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := removeLegacyAgentID(path); err == nil {
		t.Fatal("symlinked obsolete agent ID was accepted")
	}
	if contents, err := os.ReadFile(target); err != nil || string(contents) != "do not remove\n" {
		t.Fatalf("symlink target changed: %q, %v", contents, err)
	}
}
