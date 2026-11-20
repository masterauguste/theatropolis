package agent

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually advanced ProbeScheduler clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// variableEchoServer serves a plain-text IP from an atomic value, so a test
// can change the reported public address between probes.
func variableEchoServer(
	t *testing.T,
	body *atomic.Value,
	hits *atomic.Int32,
) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprintln(w, body.Load().(string))
	}))
	t.Cleanup(server.Close)
	return server
}

// waitForHits polls until the echo endpoint has been queried exactly want
// times; the probe under test runs asynchronously.
func waitForHits(t *testing.T, hits *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for hits.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("endpoint hits = %d, want %d", hits.Load(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// nextReport returns the next reported address, failing on timeout.
func nextReport(t *testing.T, reports <-chan netip.Addr) netip.Addr {
	t.Helper()
	select {
	case addr := <-reports:
		return addr
	case <-time.After(5 * time.Second):
		t.Fatal("no probe report arrived")
		return netip.Addr{}
	}
}

// assertNoReport settles briefly, then requires the report channel to be
// empty. The preceding waitForHits guarantees the probe itself finished, so
// a short settle window covers the report handoff.
func assertNoReport(t *testing.T, reports <-chan netip.Addr) {
	t.Helper()
	time.Sleep(50 * time.Millisecond)
	select {
	case addr := <-reports:
		t.Fatalf("unexpected probe report: %s", addr)
	default:
	}
}

// waitForIdle waits until one family's asynchronous probe has returned.
func waitForIdle(t *testing.T, scheduler *ProbeScheduler, is6 bool) {
	t.Helper()
	index := familyIndex(is6)
	deadline := time.Now().Add(5 * time.Second)
	for {
		scheduler.mu.Lock()
		refreshing := scheduler.refreshing[index]
		scheduler.mu.Unlock()
		if !refreshing {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("probe scheduler did not become idle")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMaintainProbesOnlyWithoutRoutableAddress(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	var body atomic.Value
	body.Store("203.0.113.50")
	server := variableEchoServer(t, &body, &hits)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	scheduler := &ProbeScheduler{
		Now:         clock.Now,
		Interval:    time.Minute,
		EndpointsV4: []string{server.URL},
	}
	reports := make(chan netip.Addr, 4)
	report := func(addr netip.Addr) { reports <- addr }

	// A family with a globally routable interface address never probes.
	scheduler.Maintain(false, true, report)
	assertNoReport(t, reports)
	if got := hits.Load(); got != 0 {
		t.Fatalf("hits = %d, want 0: a direct-attach family must never probe", got)
	}

	// Without a routable interface address the first Maintain probes and the
	// first success always reports.
	scheduler.Maintain(false, false, report)
	waitForHits(t, &hits, 1)
	if addr := nextReport(t, reports); addr != netip.MustParseAddr("203.0.113.50") {
		t.Fatalf("reported %s, want 203.0.113.50", addr)
	}
}

func TestMaintainSuppressesRetriesWithinInterval(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	var body atomic.Value
	body.Store("203.0.113.50")
	server := variableEchoServer(t, &body, &hits)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	scheduler := &ProbeScheduler{
		Now:         clock.Now,
		Interval:    time.Minute,
		EndpointsV4: []string{server.URL},
	}
	reports := make(chan netip.Addr, 4)
	report := func(addr netip.Addr) { reports <- addr }

	scheduler.Maintain(false, false, report)
	waitForHits(t, &hits, 1)
	nextReport(t, reports)

	// Same tick and half an interval later: no new attempt.
	scheduler.Maintain(false, false, report)
	clock.Advance(30 * time.Second)
	scheduler.Maintain(false, false, report)
	assertNoReport(t, reports)
	if got := hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1: attempts inside the interval must be suppressed", got)
	}

	// Past the interval the family is probed again.
	clock.Advance(31 * time.Second)
	scheduler.Maintain(false, false, report)
	waitForHits(t, &hits, 2)
}

func TestMaintainReportsChangesOnly(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	var body atomic.Value
	body.Store("203.0.113.50")
	server := variableEchoServer(t, &body, &hits)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	scheduler := &ProbeScheduler{
		Now:         clock.Now,
		Interval:    time.Minute,
		EndpointsV4: []string{server.URL},
	}
	reports := make(chan netip.Addr, 4)
	report := func(addr netip.Addr) { reports <- addr }

	scheduler.Maintain(false, false, report)
	waitForHits(t, &hits, 1)
	nextReport(t, reports)

	// Same address again: the probe runs but nothing is re-reported.
	clock.Advance(time.Minute)
	scheduler.Maintain(false, false, report)
	waitForHits(t, &hits, 2)
	assertNoReport(t, reports)

	// A changed address is stored and reported.
	body.Store("203.0.113.60")
	clock.Advance(time.Minute)
	scheduler.Maintain(false, false, report)
	waitForHits(t, &hits, 3)
	if addr := nextReport(t, reports); addr != netip.MustParseAddr("203.0.113.60") {
		t.Fatalf("reported %s, want 203.0.113.60", addr)
	}
}

func TestMaintainFailureSuppressesRetryUntilNextInterval(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	server := echoServer(t, "not-an-ip", &hits)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	scheduler := &ProbeScheduler{
		Now:         clock.Now,
		Interval:    time.Minute,
		EndpointsV4: []string{server.URL},
	}
	reports := make(chan netip.Addr, 4)
	report := func(addr netip.Addr) { reports <- addr }

	scheduler.Maintain(false, false, report)
	waitForHits(t, &hits, 1)
	assertNoReport(t, reports)

	// The failure was recorded as an attempt: heartbeats inside the
	// interval do not retry.
	scheduler.Maintain(false, false, report)
	if got := hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1: a failed family must not retry every heartbeat", got)
	}

	clock.Advance(time.Minute)
	scheduler.Maintain(false, false, report)
	waitForHits(t, &hits, 2)
	assertNoReport(t, reports)
}

func TestMaintainSingleFlightWhileRefreshInFlight(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = fmt.Fprintln(w, "203.0.113.50")
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	scheduler := &ProbeScheduler{
		Now:         clock.Now,
		Interval:    time.Minute,
		EndpointsV4: []string{server.URL},
	}
	reports := make(chan netip.Addr, 4)
	report := func(addr netip.Addr) { reports <- addr }

	scheduler.Maintain(false, false, report)
	waitForHits(t, &hits, 1)

	// Even with the interval elapsed, a refresh already in flight blocks
	// further attempts.
	clock.Advance(2 * time.Minute)
	scheduler.Maintain(false, false, report)
	time.Sleep(50 * time.Millisecond)
	if got := hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1: probes must be single-flight per family", got)
	}

	close(release)
	if addr := nextReport(t, reports); addr != netip.MustParseAddr("203.0.113.50") {
		t.Fatalf("reported %s, want 203.0.113.50", addr)
	}
}

func TestNoteProbedResetsIntervalAndSuppressesRedundantReport(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	var body atomic.Value
	body.Store("203.0.113.50")
	server := variableEchoServer(t, &body, &hits)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	scheduler := &ProbeScheduler{
		Now:         clock.Now,
		Interval:    time.Minute,
		EndpointsV4: []string{server.URL},
	}
	reports := make(chan netip.Addr, 4)
	report := func(addr netip.Addr) { reports <- addr }

	// An on-demand probe already told the master 203.0.113.50.
	scheduler.noteProbed(false, netip.MustParseAddr("203.0.113.50"))

	// The next heartbeat does not immediately duplicate the on-demand
	// request: it must wait for the regular interval.
	scheduler.Maintain(false, false, report)
	assertNoReport(t, reports)
	if got := hits.Load(); got != 0 {
		t.Fatalf("hits = %d, want 0 before the interval elapses", got)
	}

	// Once the interval elapses, a genuine change is probed and reported.
	body.Store("203.0.113.60")
	clock.Advance(time.Minute)
	scheduler.Maintain(false, false, report)
	waitForHits(t, &hits, 1)
	if addr := nextReport(t, reports); addr != netip.MustParseAddr("203.0.113.60") {
		t.Fatalf("reported %s, want 203.0.113.60", addr)
	}
}

func TestNoteProbedSupersedesInflightPeriodicProbe(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		close(started)
		<-release
		_, _ = fmt.Fprintln(w, "203.0.113.50")
	}))
	t.Cleanup(server.Close)

	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	scheduler := &ProbeScheduler{
		Now:         clock.Now,
		Interval:    time.Minute,
		EndpointsV4: []string{server.URL},
	}
	reports := make(chan netip.Addr, 2)

	scheduler.Maintain(false, false, func(addr netip.Addr) { reports <- addr })
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("periodic probe did not start")
	}

	// A newer on-demand success wins while the periodic request is still
	// running. Its timer and address must survive the older response.
	scheduler.noteProbed(false, netip.MustParseAddr("203.0.113.60"))
	close(release)
	waitForIdle(t, scheduler, false)
	assertNoReport(t, reports)

	scheduler.Maintain(false, false, func(addr netip.Addr) { reports <- addr })
	assertNoReport(t, reports)
	if got := hits.Load(); got != 1 {
		t.Fatalf("hits = %d, want 1 before the reset interval elapses", got)
	}
}

func TestMaintainDisabledByNegativeInterval(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	server := echoServer(t, "203.0.113.50", &hits)
	scheduler := &ProbeScheduler{
		Interval:    -1,
		EndpointsV4: []string{server.URL},
	}
	reports := make(chan netip.Addr, 1)
	scheduler.Maintain(false, false, func(addr netip.Addr) { reports <- addr })
	assertNoReport(t, reports)
	if got := hits.Load(); got != 0 {
		t.Fatalf("hits = %d, want 0: a negative interval disables probing", got)
	}
}

func TestFamilyProbeClientLocksFamily(t *testing.T) {
	t.Parallel()

	var hits4 atomic.Int32
	server4 := echoServer(t, "203.0.113.50", &hits4) // 127.0.0.1 only

	listener6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback available: %v", err)
	}
	server6 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "2001:db8::50")
	}))
	server6.Listener = listener6
	server6.Start()
	t.Cleanup(server6.Close)

	get := func(client *http.Client, url string) error {
		response, err := client.Get(url)
		if err != nil {
			return err
		}
		response.Body.Close()
		return nil
	}

	client4 := familyProbeClient(false)
	if err := get(client4, server4.URL); err != nil {
		t.Fatalf("v4 client could not reach a v4 endpoint: %v", err)
	}
	if err := get(client4, server6.URL); err == nil {
		t.Fatal("v4 client reached a v6-only endpoint: the dialer does not force tcp4")
	}

	client6 := familyProbeClient(true)
	if err := get(client6, server6.URL); err != nil {
		t.Fatalf("v6 client could not reach a v6 endpoint: %v", err)
	}
	if err := get(client6, server4.URL); err == nil {
		t.Fatal("v6 client reached a v4-only endpoint: the dialer does not force tcp6")
	}
}
