package control

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

func withXFF(ctx context.Context, values ...string) context.Context {
	pairs := make([]string, 0, 2*len(values))
	for _, value := range values {
		pairs = append(pairs, "x-forwarded-for", value)
	}
	return metadata.NewIncomingContext(ctx, metadata.Pairs(pairs...))
}

func withPeerAddr(ctx context.Context, addr net.Addr) context.Context {
	return peer.NewContext(ctx, &peer.Peer{Addr: addr})
}

func tcpAddr(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

func TestObservedAddress(t *testing.T) {
	t.Parallel()

	background := context.Background()
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{
			name: "xff single element",
			ctx:  withXFF(background, "203.0.113.10"),
			want: "203.0.113.10",
		},
		{
			name: "spoofed earlier elements do not win",
			ctx:  withXFF(background, "1.2.3.4, 203.0.113.10"),
			want: "203.0.113.10",
		},
		{
			name: "last header value wins",
			ctx:  withXFF(background, "1.2.3.4", "5.6.7.8, 203.0.113.10"),
			want: "203.0.113.10",
		},
		{
			name: "elements are trimmed",
			ctx:  withXFF(background, "  203.0.113.10 , 198.51.100.9  "),
			want: "198.51.100.9",
		},
		{
			name: "ipv6 element",
			ctx:  withXFF(background, "2001:db8::44"),
			want: "2001:db8::44",
		},
		{
			name: "loopback dropped (dev addresses are not pool-usable)",
			ctx:  withXFF(background, "127.0.0.1"),
			want: "",
		},
		{
			name: "private xff dropped",
			ctx:  withXFF(background, "10.0.0.8"),
			want: "",
		},
		{
			name: "cgnat xff dropped",
			ctx:  withXFF(background, "100.64.0.9"),
			want: "",
		},
		{
			name: "ula xff dropped",
			ctx:  withXFF(background, "fd12:3456::1"),
			want: "",
		},
		{
			name: "reserved xff dropped",
			ctx:  withXFF(background, "240.0.0.9"),
			want: "",
		},
		{
			name: "non-routable xff falls back to peer",
			ctx: withPeerAddr(
				withXFF(background, "192.168.1.2"),
				tcpAddr("198.51.100.7", 8443),
			),
			want: "198.51.100.7",
		},
		{
			name: "private peer dropped",
			ctx:  withPeerAddr(background, tcpAddr("192.168.1.2", 8443)),
			want: "",
		},
		{
			name: "invalid xff falls back to peer",
			ctx: withPeerAddr(
				withXFF(background, "garbage"),
				tcpAddr("198.51.100.7", 8443),
			),
			want: "198.51.100.7",
		},
		{
			name: "peer fallback without xff",
			ctx:  withPeerAddr(background, tcpAddr("198.51.100.7", 8443)),
			want: "198.51.100.7",
		},
		{
			name: "ipv6 peer fallback",
			ctx:  withPeerAddr(background, tcpAddr("2001:db8::7", 8443)),
			want: "2001:db8::7",
		},
		{
			name: "no metadata and no peer",
			ctx:  background,
			want: "",
		},
		{
			name: "invalid xff and unusable peer",
			ctx: withPeerAddr(
				withXFF(background, "nope"),
				fakeAddr("bufconn"),
			),
			want: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := observedAddress(test.ctx); got != test.want {
				t.Fatalf("observedAddress() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSetObservedAddress(t *testing.T) {
	t.Parallel()

	registry := NewSessionRegistry()
	registry.SetObservedAddress("offline-agent", "203.0.113.1") // no session: no-op

	session := newSession("agent-one")
	if err := registry.Register(session); err != nil {
		t.Fatal(err)
	}
	registry.SetObservedAddress("agent-one", "203.0.113.1")
	info, exists := registry.AgentInfo("agent-one")
	if !exists {
		t.Fatal("session missing after register")
	}
	if info.ObservedAddress != "203.0.113.1" {
		t.Fatalf("ObservedAddress = %q, want %q", info.ObservedAddress, "203.0.113.1")
	}
}
