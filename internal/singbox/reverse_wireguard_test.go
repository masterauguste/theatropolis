package singbox

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagedWireGuardRejectsPrivilegeAndReservedSockets(t *testing.T) {
	for _, endpoint := range []string{`{"type":"wireguard","system":true}`, `{"type":"wireguard","listen_port":80}`, `{"type":"wireguard","listen_port":19090}`, `{"type":"wireguard","listen_port":19091}`, `{"type":"wireguard","listen_port":-1}`} {
		if err := ValidateManagedConfig([]byte(`{"endpoints":[` + endpoint + `]}`)); err == nil {
			t.Errorf("accepted unsafe endpoint %s", endpoint)
		}
	}
	if err := ValidateManagedConfig([]byte(`{"endpoints":[{"type":"wireguard","system":false,"listen_port":51820},{"type":"wireguard","system":false}]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestReverseSOCKSProbeRequiresAuthentication(t *testing.T) {
	for _, accept := range []bool{false, true} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			greeting := make([]byte, 3)
			_, _ = io.ReadFull(conn, greeting)
			_, _ = conn.Write([]byte{5, 2})
			auth := make([]byte, 2)
			_, _ = io.ReadFull(conn, auth)
			user := make([]byte, int(auth[1]))
			_, _ = io.ReadFull(conn, user)
			length := make([]byte, 1)
			_, _ = io.ReadFull(conn, length)
			secret := make([]byte, int(length[0]))
			_, _ = io.ReadFull(conn, secret)
			result := byte(1)
			if accept && string(user) == "link" && string(secret) == "secret" {
				result = 0
			}
			_, _ = conn.Write([]byte{1, result})
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err = probeReverseSOCKS(ctx, listener.Addr().String(), "link", "secret")
		cancel()
		_ = listener.Close()
		if (err == nil) != accept {
			t.Fatalf("accept=%v, error=%v", accept, err)
		}
	}
}

func TestReverseTunnelProbeBindsActiveProfileDigest(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewManager(ManagerOptions{Validator: Validator{BinaryPath: "unused", StateDirectory: dir}})
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"inbounds":[],"outbounds":[]}`)
	if err := os.MkdirAll(filepath.Join(dir, "sing-box"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sing-box", "active.json"), config, 0600); err != nil {
		t.Fatal(err)
	}
	variant, err := BuildManagedUserAuthorityVariant(config)
	if err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("other"))
	if err := manager.CheckReverseTunnels(context.Background(), other[:]); err == nil {
		t.Fatal("stale profile accepted")
	}
	if err := manager.CheckReverseTunnels(context.Background(), variant.TopologySHA256[:]); err != nil {
		t.Fatal(err)
	}
}

func TestReverseRelayAuthorityKeepsTopologyCredentials(t *testing.T) {
	config := []byte(`{"inbounds":[{"type":"socks","tag":"private","users":[{"username":"link-identity","password":"link-secret"}]}],"outbounds":[]}`)
	variant, err := BuildManagedUserAuthorityVariant(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(variant.Endpoints) != 0 {
		t.Fatal("relay registered as end-user authority")
	}
	materialized, matched, err := applyManagedUserAuthority(config, []ManagedUserAuthorityVariant{variant})
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("relay authority did not match")
	}
	var actual map[string]any
	_ = json.Unmarshal(materialized, &actual)
	user := actual["inbounds"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if user["password"] != "link-secret" {
		t.Fatal("user authority modified Link credentials")
	}
}

func TestReverseReadinessDigestIgnoresEntranceUserSynchronization(t *testing.T) {
	before := managedUserTestConfig(`[{"name":"cinema-alice-m-AAAAAAAAAAAA","password":"before"}]`)
	after := managedUserTestConfig(`[]`)
	variant, err := BuildManagedUserAuthorityVariant(before)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manager, err := NewManager(ManagerOptions{Validator: Validator{BinaryPath: "unused", StateDirectory: dir}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sing-box"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sing-box", "active.json"), after, 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.CheckReverseTunnels(context.Background(), variant.TopologySHA256[:]); err != nil {
		t.Fatalf("independent user authority invalidated transport readiness: %v", err)
	}
}
