package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Address discovery strategy: interface addresses are collected on hello and
// every heartbeat and reported as-is (globally routable ones only — see
// CollectAddresses). Families WITHOUT a globally routable interface address
// (hosts behind 1:1 NAT, where the NIC only carries a private address) are
// covered two ways: the master can command an on-demand probe
// (ProbeAddresses, answered via AddressReporter.Probe), and ProbeScheduler
// periodically probes those families on its own — Komari-style — reporting
// only address changes, so the master always learns both families
// eventually. Probing runs off the control loop, and direct-attach hosts
// (routable address on the NIC) never generate probe traffic.

const (
	// maxProbeBodyBytes caps echo responses; a plain-text IP is a handful of
	// bytes, anything larger is not an echo service.
	maxProbeBodyBytes = 4096
	// probeTimeout bounds each individual endpoint attempt.
	probeTimeout = 3 * time.Second
	// DefaultProbeInterval is how often ProbeScheduler re-probes a family
	// that has no globally routable interface address.
	DefaultProbeInterval = 5 * time.Minute
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

// defaultProbeClients are the process-wide probe HTTP clients, one per
// family; see familyProbeClient. Package-level so all schedulers share
// their connection pools.
var (
	defaultProbeClientV4 = familyProbeClient(false)
	defaultProbeClientV6 = familyProbeClient(true)
)

// familyProbeClient returns an HTTP client locked to one IP family: the
// transport dials "tcp4"/"tcp6" only, so a v4 probe can never egress via
// v6 (or vice versa) even when an endpoint hostname resolves in both
// families. Without this a v4 probe answered over a v6 route would report
// the wrong public address.
func familyProbeClient(is6 bool) *http.Client {
	network := "tcp4"
	if is6 {
		network = "tcp6"
	}
	dialer := &net.Dialer{Timeout: probeTimeout}
	return &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, address)
			},
		},
	}
}

// ProbeScheduler periodically discovers the agent's public addresses itself
// (Komari-style) for families that have no globally routable interface
// address. The runner calls Maintain from its heartbeat tick; probes run
// asynchronously and only address changes are reported, so steady state
// costs one echo request per family per Interval and no report traffic.
//
// The zero value is ready to use: default endpoints, family-locked clients,
// DefaultProbeInterval, and an immediate first probe per family (lastAttempt
// starts at the zero time, which is always older than any interval).
type ProbeScheduler struct {
	// Now is the clock; nil means time.Now. Tests inject a fake clock.
	Now func() time.Time
	// Interval is the minimum time between probe attempts per family —
	// failures count as attempts, so a broken family is retried one
	// Interval later, not on every heartbeat. Zero selects
	// DefaultProbeInterval; negative disables periodic probing entirely
	// (Maintain becomes a no-op; noteProbed still records).
	Interval time.Duration
	// EndpointsV4/EndpointsV6 override the default echo endpoints (tests).
	EndpointsV4 []string
	EndpointsV6 []string
	// ClientV4/ClientV6 override the family-locked default clients (tests).
	ClientV4 *http.Client
	ClientV6 *http.Client

	// mu guards the per-family state, indexed by familyIndex.
	mu           sync.Mutex
	lastReported [2]netip.Addr
	lastAttempt  [2]time.Time
	refreshing   [2]bool
	generation   [2]uint64
}

// Maintain is the heartbeat-tick entry point for one family. It probes
// asynchronously only when the family has no globally routable interface
// address (hasRoutable, computed by the caller from CollectAddresses), no
// refresh is in flight, and the last attempt is at least Interval old. On
// success an address differing from the last reported one is stored and
// handed to report — the first success always reports, since lastReported
// starts invalid. Failures are silent: the attempt was already recorded,
// so the next retry happens one Interval later.
func (s *ProbeScheduler) Maintain(
	is6 bool,
	hasRoutable bool,
	report func(netip.Addr),
) {
	if hasRoutable || s.Interval < 0 {
		return
	}
	index := familyIndex(is6)
	s.mu.Lock()
	if s.refreshing[index] ||
		s.now().Sub(s.lastAttempt[index]) < s.interval() {
		s.mu.Unlock()
		return
	}
	s.lastAttempt[index] = s.now()
	s.refreshing[index] = true
	s.generation[index]++
	generation := s.generation[index]
	s.mu.Unlock()

	go func() {
		addr, err := s.probe(context.Background(), is6)
		s.mu.Lock()
		s.refreshing[index] = false
		if s.generation[index] != generation {
			// A newer on-demand result superseded this in-flight periodic
			// attempt. Discard its stale result and leave the newer attempt
			// timestamp and address untouched.
			s.mu.Unlock()
			return
		}
		changed := err == nil && addr != s.lastReported[index]
		if changed {
			s.lastReported[index] = addr
		}
		s.mu.Unlock()
		// Report outside the lock: the callback queues a frame for the
		// control loop and may briefly block on a full channel.
		if changed && report != nil {
			report(addr)
		}
	}()
}

// noteProbed folds a successful on-demand probe result into the periodic
// state so Maintain neither re-probes the family until the normal interval
// elapses nor re-reports an address the master already knows.
func (s *ProbeScheduler) noteProbed(is6 bool, addr netip.Addr) {
	s.mu.Lock()
	index := familyIndex(is6)
	s.lastReported[index] = addr
	s.lastAttempt[index] = s.now()
	// Invalidate an older periodic probe that may currently be in flight.
	s.generation[index]++
	s.mu.Unlock()
}

// probe runs one probe through the shared AddressReporter machinery (same
// endpoint order and validation) with the family's locked client.
func (s *ProbeScheduler) probe(ctx context.Context, is6 bool) (netip.Addr, error) {
	reporter := &AddressReporter{
		Client:      s.client(is6),
		EndpointsV4: s.EndpointsV4,
		EndpointsV6: s.EndpointsV6,
	}
	return reporter.Probe(ctx, is6)
}

func (s *ProbeScheduler) client(is6 bool) *http.Client {
	if is6 {
		if s.ClientV6 != nil {
			return s.ClientV6
		}
		return defaultProbeClientV6
	}
	if s.ClientV4 != nil {
		return s.ClientV4
	}
	return defaultProbeClientV4
}

func (s *ProbeScheduler) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

func (s *ProbeScheduler) interval() time.Duration {
	if s.Interval == 0 {
		return DefaultProbeInterval
	}
	return s.Interval
}

// familyIndex maps the boolean family selector to a state array index.
func familyIndex(is6 bool) int {
	if is6 {
		return 1
	}
	return 0
}
