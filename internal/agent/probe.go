package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Address discovery strategy: interface addresses are collected on hello and
// every heartbeat and reported as-is (globally routable ones only — see
// CollectAddresses). The agent never probes on its own — public-address
// probing (for hosts behind 1:1 NAT, where the NIC only carries a private
// address) happens only on an explicit master ProbeAddresses command,
// answered via Probe. Probing therefore never runs unsolicited background
// traffic and never blocks the control loop.

const (
	// maxProbeBodyBytes caps echo responses; a plain-text IP is a handful of
	// bytes, anything larger is not an echo service.
	maxProbeBodyBytes = 4096
	// probeTimeout bounds each individual endpoint attempt.
	probeTimeout = 3 * time.Second
)

// defaultProbeEndpoints are plain-text IP echo services, per address family.
// The api4/api6 and ipv4/ipv6 host variants only resolve in their family, so
// a successful probe also proves that family's outbound connectivity.
// (Tests substitute local http endpoints via the Endpoints fields.)
var defaultProbeEndpointsV4 = []string{
	"https://api4.ipify.org",
	"https://ipv4.icanhazip.com",
}
var defaultProbeEndpointsV6 = []string{
	"https://api6.ipify.org",
	"https://ipv6.icanhazip.com",
}

// AddressReporter resolves the addresses the agent reports to the master and
// runs on-command public address probes. It holds no state, so all methods
// are safe for concurrent use and none perform network I/O except Probe.
type AddressReporter struct {
	// Source lists interface addresses; nil means net.InterfaceAddrs.
	Source func() ([]net.Addr, error)
	// Client performs probe requests; nil means a default client with a
	// per-request timeout. Tests point it at httptest servers.
	Client *http.Client
	// EndpointsV4/EndpointsV6 override the default echo endpoints (tests).
	EndpointsV4 []string
	EndpointsV6 []string
}

func (r *AddressReporter) httpClient() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return &http.Client{Timeout: probeTimeout}
}

// Addresses returns the reported v4 and v6 interface address lists.
// CollectAddresses already keeps only globally routable addresses, so the
// lists pass through unchanged. A source failure is non-fatal and yields nil
// lists, matching the previous collect-once behavior.
func (r *AddressReporter) Addresses() (v4, v6 []string) {
	src := r.Source
	if src == nil {
		src = net.InterfaceAddrs
	}
	if4, if6, err := CollectAddresses(src)
	if err != nil {
		return nil, nil
	}
	return if4, if6
}

// Probe queries the family's echo endpoints in order and returns the first
// validated public address. It runs only on explicit master command and
// respects ctx cancellation between and during endpoint attempts.
func (r *AddressReporter) Probe(ctx context.Context, is6 bool) (netip.Addr, error) {
	endpoints := r.endpoints(is6)
	var lastErr error
	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			return netip.Addr{}, err
		}
		addr, err := r.probeEndpoint(ctx, endpoint, is6)
		if err == nil {
			return addr, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no probe endpoints configured")
	}
	return netip.Addr{}, lastErr
}

func (r *AddressReporter) endpoints(is6 bool) []string {
	endpoints := r.EndpointsV4
	if is6 {
		endpoints = r.EndpointsV6
	}
	if endpoints == nil {
		endpoints = defaultProbeEndpointsV4
		if is6 {
			endpoints = defaultProbeEndpointsV6
		}
	}
	return endpoints
}

// probeEndpoint fetches a plain-text IP echo and validates it belongs to the
// requested family and is publicly routable (an echo service behind a
// misconfigured proxy could otherwise hand us another private address).
func (r *AddressReporter) probeEndpoint(
	ctx context.Context,
	endpoint string,
	is6 bool,
) (netip.Addr, error) {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("build probe request: %w", err)
	}
	request.Header.Set("User-Agent", "theatropolis-agent")
	response, err := r.httpClient().Do(request)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("probe %s: %w", endpoint, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("probe %s: unexpected status %d", endpoint, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProbeBodyBytes+1))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read probe body: %w", err)
	}
	if len(body) > maxProbeBodyBytes {
		return netip.Addr{}, fmt.Errorf("probe %s: response too large", endpoint)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("probe %s: invalid address: %w", endpoint, err)
	}
	if addr.Is6() != is6 || !globallyRoutable(addr) {
		return netip.Addr{}, fmt.Errorf("probe %s: unusable address %s", endpoint, addr)
	}
	return addr, nil
}
