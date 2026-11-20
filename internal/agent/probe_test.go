package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// interfaceSource returns a static interface-address list.
func interfaceSource(addrs ...string) func() ([]net.Addr, error) {
	return func() ([]net.Addr, error) {
		var out []net.Addr
		for _, text := range addrs {
			out = append(out, &net.IPAddr{IP: net.ParseIP(text)})
		}
		return out, nil
	}
}

// echoServer serves a plain-text IP and counts requests.
func echoServer(t *testing.T, body string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprintln(w, body)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestAddressesKeepsOnlyRoutable(t *testing.T) {
	var hits atomic.Int32
	server := echoServer(t, "203.0.113.50", &hits)
	reporter := &AddressReporter{
		Source:      interfaceSource("10.0.0.8", "203.0.113.10", "192.168.1.2"),
		EndpointsV4: []string{server.URL},
		EndpointsV6: []string{server.URL},
	}
	v4, _ := reporter.Addresses()
	if len(v4) != 1 || v4[0] != "203.0.113.10" {
		t.Fatalf("v4 = %v, want only the globally routable interface address", v4)
	}
	if hits.Load() != 0 {
		t.Fatalf("Addresses() hit probe endpoints %d times; it must never probe", hits.Load())
	}
}

func TestAddressesPrivateOnlyNeverProbes(t *testing.T) {
	var hits atomic.Int32
	server := echoServer(t, "203.0.113.50", &hits)
	reporter := &AddressReporter{
		Source:      interfaceSource("10.0.0.8", "100.64.0.1"),
		EndpointsV4: []string{server.URL},
	}
	v4, _ := reporter.Addresses()
	if len(v4) != 0 {
		t.Fatalf("v4 = %v, want no addresses: private/CGNAT addresses are never reported", v4)
	}
	if hits.Load() != 0 {
		t.Fatalf("Addresses() probed %d times for a NATed family; probing is master-commanded only", hits.Load())
	}
}

func TestProbeSuccess(t *testing.T) {
	var hits atomic.Int32
	server := echoServer(t, "203.0.113.50", &hits)
	reporter := &AddressReporter{EndpointsV4: []string{server.URL}}
	addr, err := reporter.Probe(context.Background(), false)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if addr != netip.MustParseAddr("203.0.113.50") {
		t.Fatalf("Probe = %s, want 203.0.113.50", addr)
	}
}

func TestProbeFallsBackToNextEndpoint(t *testing.T) {
	var hits atomic.Int32
	server := echoServer(t, "203.0.113.50", &hits)
	reporter := &AddressReporter{EndpointsV4: []string{
		"http://127.0.0.1:1/none", // connection refused
		server.URL,
	}}
	addr, err := reporter.Probe(context.Background(), false)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if addr != netip.MustParseAddr("203.0.113.50") {
		t.Fatalf("Probe = %s, want 203.0.113.50", addr)
	}
}

func TestProbeFamilyMismatch(t *testing.T) {
	var hits atomic.Int32
	server := echoServer(t, "203.0.113.50", &hits)
	reporter := &AddressReporter{EndpointsV6: []string{server.URL}}
	if _, err := reporter.Probe(context.Background(), true); err == nil {
		t.Fatal("Probe of a v6 family against a v4 echo succeeded, want error")
	}
	if hits.Load() == 0 {
		t.Fatal("probe endpoint was never queried")
	}
}

func TestProbeAllEndpointsFail(t *testing.T) {
	var hits atomic.Int32
	server := echoServer(t, "not-an-ip", &hits)
	reporter := &AddressReporter{EndpointsV4: []string{server.URL}}
	if _, err := reporter.Probe(context.Background(), false); err == nil {
		t.Fatal("Probe with an unusable echo succeeded, want error")
	}
}

func TestProbeNoEndpoints(t *testing.T) {
	reporter := &AddressReporter{EndpointsV4: []string{}}
	if _, err := reporter.Probe(context.Background(), false); err == nil {
		t.Fatal("Probe with no endpoints succeeded, want error")
	}
}

func TestProbeContextCanceledBeforeStart(t *testing.T) {
	var hits atomic.Int32
	server := echoServer(t, "203.0.113.50", &hits)
	reporter := &AddressReporter{EndpointsV4: []string{server.URL}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reporter.Probe(ctx, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe error = %v, want context.Canceled", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("canceled probe still hit endpoints %d times", hits.Load())
	}
}

func TestProbeContextCanceledMidFlight(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	reporter := &AddressReporter{EndpointsV4: []string{server.URL}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := reporter.Probe(ctx, false)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled probe succeeded, want error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not respect context cancellation")
	}
}

func TestProbeEndpointValidation(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		status  int
		is6     bool
		wantErr bool
	}{
		{name: "valid v4", body: "203.0.113.50", status: 200},
		{name: "valid v6", body: "2001:db8::1", status: 200, is6: true},
		{name: "wrong family", body: "203.0.113.50", status: 200, is6: true, wantErr: true},
		{name: "private echo", body: "10.0.0.8", status: 200, wantErr: true},
		{name: "cgnat echo", body: "100.64.0.1", status: 200, wantErr: true},
		{name: "reserved echo", body: "240.0.0.9", status: 200, wantErr: true},
		{name: "ula echo", body: "fd00::9", status: 200, is6: true, wantErr: true},
		{name: "garbage", body: "<html>nope</html>", status: 200, wantErr: true},
		{name: "status", body: "203.0.113.50", status: 502, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var hits atomic.Int32
			server := echoServer(t, test.body, &hits)
			if test.status != 200 {
				server.Close()
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(test.status)
				}))
				t.Cleanup(server.Close)
			}
			reporter := &AddressReporter{}
			_, err := reporter.probeEndpoint(context.Background(), server.URL, test.is6)
			if test.wantErr && err == nil {
				t.Fatalf("probeEndpoint(%q) succeeded, want error", test.body)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("probeEndpoint(%q) error = %v", test.body, err)
			}
		})
	}
}

func TestProbeEndpointRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, strings.Repeat("1", maxProbeBodyBytes+10))
	}))
	t.Cleanup(server.Close)
	reporter := &AddressReporter{}
	if _, err := reporter.probeEndpoint(context.Background(), server.URL, false); err == nil {
		t.Fatal("oversized probe body accepted")
	}
}

func TestGloballyRoutable(t *testing.T) {
	tests := []struct {
		addr     string
		routable bool
	}{
		{"203.0.113.10", true}, // TEST-NET-3: kept deliberately (test stand-in)
		{"192.0.2.1", true},    // TEST-NET-1: kept deliberately
		{"198.51.100.7", true}, // TEST-NET-2: kept deliberately
		{"2001:db8::1", true},  // documentation range: kept deliberately
		{"8.8.8.8", true},
		{"100.63.255.255", true}, // just below CGNAT
		{"100.128.0.1", true},    // just above CGNAT
		{"223.255.255.255", true},
		{"10.0.0.8", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.1.2", false},
		{"100.64.0.1", false},      // CGNAT start
		{"100.127.255.255", false}, // CGNAT end
		{"240.0.0.1", false},       // reserved 240/4
		{"255.255.255.255", false},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"224.0.0.1", false},
		{"0.0.0.0", false},
		{"fc00::1", false},
		{"fd12:3456::1", false},
		{"::1", false},
		{"fe80::1", false},
	}
	for _, test := range tests {
		addr := netip.MustParseAddr(test.addr)
		if got := globallyRoutable(addr); got != test.routable {
			t.Errorf("globallyRoutable(%s) = %v, want %v", test.addr, got, test.routable)
		}
	}
}
