package singbox

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSocketTableOwnership(t *testing.T) {
	for _, test := range []struct {
		name, local, state, inode, target string
		want                              bool
	}{
		{"owned-tcp", "0100007F:01BB", "0A", "123", "127.0.0.1:443", true},
		{"other-process", "0100007F:01BB", "0A", "456", "127.0.0.1:443", false},
		{"wrong-port", "0100007F:01BA", "0A", "123", "127.0.0.1:443", false},
		{"wrong-address", "0200007F:01BB", "0A", "123", "127.0.0.1:443", false},
		{"not-listening", "0100007F:01BB", "01", "123", "127.0.0.1:443", false},
		{"wildcard", "00000000:01BB", "0A", "123", "127.0.0.1:443", true},
		{"ipv6-loopback", "00000000000000000000000001000000:01BB", "0A", "123", "[::1]:443", true},
		{"ipv6-wildcard", "00000000000000000000000000000000:01BB", "0A", "123", "[::1]:443", true},
		{"mapped-ipv4", "0000000000000000FFFF00000100007F:01BB", "0A", "123", "127.0.0.1:443", true},
		{"invalid", "invalid:01BB", "0A", "123", "127.0.0.1:443", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			row := "0: " + test.local + " 00000000:0000 " + test.state + " 00000000:00000000 00:00000000 00000000 1000 0 " + test.inode
			got := socketTableOwnsListener(bufio.NewScanner(strings.NewReader(row)), netip.MustParseAddrPort(test.target), "0A", map[string]bool{"123": true})
			if got != test.want {
				t.Fatalf("ownership = %v, want %v", got, test.want)
			}
		})
	}
}

func TestProcessOwnsTLSListenerFailsClosed(t *testing.T) {
	proc := t.TempDir()
	process := filepath.Join(proc, "123")
	for _, directory := range []string{"fd", "net"} {
		if err := os.MkdirAll(filepath.Join(process, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(process, "fd", "7")); err != nil {
		t.Fatal(err)
	}
	row := "0: 0100007F:01BB 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12345\n"
	if err := os.WriteFile(filepath.Join(process, "net", "udp"), []byte(row), 0600); err != nil {
		t.Fatal(err)
	}
	target := tlsReadinessTarget{protocol: "hysteria2", address: "127.0.0.1:443"}
	if !processOwnsTLSListener(proc, 123, target) {
		t.Fatal("owned UDP listener not detected")
	}
	if processOwnsTLSListener(proc, 124, target) {
		t.Fatal("missing process accepted")
	}
	target.protocol = "anytls"
	if processOwnsTLSListener(proc, 123, target) {
		t.Fatal("UDP socket accepted as TCP listener")
	}
}

func TestProcessOwnsRealLinuxListeners(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production procfs ownership check requires Linux")
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	for _, target := range []tlsReadinessTarget{
		{protocol: "anytls", address: tcp.Addr().String()},
		{protocol: "hysteria2", address: udp.LocalAddr().String()},
	} {
		if !processOwnsTLSListener("/proc", os.Getpid(), target) {
			t.Fatalf("owned %s socket not found", target.protocol)
		}
	}
}
