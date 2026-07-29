// Package pool tracks the fleet-wide outbound pool: shared manual outbounds,
// per-agent reachable addresses, and per-agent render state. It also derives
// pool entries from deployed agent configurations and renders logical configs
// containing theatropolis-pool-ref outbounds into concrete sing-box configs.
package pool

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// MaxRegistryFileBytes caps the on-disk registry document.
	MaxRegistryFileBytes = 4 << 20
	// MaxManualOutboundBytes caps one stored manual outbound object.
	MaxManualOutboundBytes = 64 << 10
	// MaxAddressesPerFamily caps reported addresses per IP family per agent.
	MaxAddressesPerFamily = 8

	diskRegistryVersion = 1
)

var (
	ErrInvalidName     = errors.New("pool: invalid name")
	ErrInvalidOutbound = errors.New("pool: invalid manual outbound")
	ErrManualNotFound  = errors.New("pool: manual outbound not found")
	ErrInvalidAddress  = errors.New("pool: invalid address")
	ErrInvalidFamily   = errors.New("pool: invalid address family")
)

// Family identifies an IP address family, or FamilyAuto for the automatic
// family chain used by address resolution.
type Family int

const (
	// FamilyAuto resolves IPv4 first, then IPv6 (see AddressSourceForFamily).
	FamilyAuto Family = iota
	FamilyIPv4
	FamilyIPv6
)

// ParseFamily parses a family selector: "" and "auto" select FamilyAuto,
// "ipv4" and "ipv6" select the respective family.
func ParseFamily(value string) (Family, error) {
	switch strings.TrimSpace(value) {
	case "", "auto":
		return FamilyAuto, nil
	case "ipv4":
		return FamilyIPv4, nil
	case "ipv6":
		return FamilyIPv6, nil
	default:
		return FamilyAuto, ErrInvalidFamily
	}
}

func (f Family) String() string {
	switch f {
	case FamilyAuto:
		return "auto"
	case FamilyIPv4:
		return "ipv4"
	case FamilyIPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

// AddressSource identifies which address source won resolution.
type AddressSource int

const (
	SourceOverride AddressSource = iota
	SourceObserved
	SourceProbed
	SourceReported
)

func (s AddressSource) String() string {
	switch s {
	case SourceOverride:
		return "override"
	case SourceObserved:
		return "observed"
	case SourceProbed:
		return "probed"
	case SourceReported:
		return "reported"
	default:
		return "unknown"
	}
}

// componentPattern is shared by manual names, agent IDs, inbound tags, and
// user names so every ref component round-trips through ref parsing. It is
// the same charset as agent IDs in internal/identity.
var componentPattern = regexp.MustCompile(`\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\z`)

// cgnatPrefix is the shared carrier-grade NAT space (RFC 6598) and
// reserved240Prefix the reserved former class-E space (RFC 1112). netip's
// IsGlobalUnicast/IsPrivate cover neither, but both are never publicly
// routable, so globallyRoutable excludes them explicitly. This mirrors the
// agent-side rule in internal/agent, which cannot be imported here.
var (
	cgnatPrefix       = netip.MustParsePrefix("100.64.0.0/10")
	reserved240Prefix = netip.MustParsePrefix("240.0.0.0/4")
)

// globallyRoutable reports whether addr may be used as a pool outbound
// server address: globally reachable, never private/NAT/reserved space.
// TEST-NET/documentation ranges are NOT excluded — they stand in for public
// addresses throughout the test suites. The registry is the last gate for
// this rule: every address source (reported, probed, observed, override) is
// filtered or rejected here even when an upstream check was bypassed.
func globallyRoutable(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() && // drops loopback, link-local, multicast, unspecified
		!addr.IsPrivate() && // RFC 1918 v4 + ULA fc00::/7
		!cgnatPrefix.Contains(addr) && // 100.64.0.0/10
		!reserved240Prefix.Contains(addr) // 240.0.0.0/4
}

func validComponent(component string) bool {
	return componentPattern.MatchString(component)
}

// validUserComponent additionally accepts the _server placeholder, which
// deliberately falls outside the agent-ID charset so it can never collide
// with a real user name, tag, or manual name.
func validUserComponent(component string) bool {
	return component == serverKeyRefComponent || validComponent(component)
}

// ManualEntry is one operator-provided shared outbound.
type ManualEntry struct {
	Name      string
	Outbound  json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

type manualRecord struct {
	outbound  json.RawMessage
	createdAt time.Time
	updatedAt time.Time
}

type agentRecord struct {
	reportedV4 []string
	reportedV6 []string
	observed   string
	probedV4   []string
	probedV6   []string
	override   string
	updatedAt  time.Time
}

type renderedRecord struct {
	poolVersion uint64
	configSHA   [32]byte
}

// Registry persists the outbound pool at <state-dir>/outbound-pool.json.
// All methods are safe for concurrent use.
type Registry struct {
	mu          sync.RWMutex
	persistPath string
	// Now supplies the current time for created_at/updated_at stamps. It is
	// set to time.Now by Open; tests may replace it before concurrent use.
	Now func() time.Time

	poolVersion uint64
	manual      map[string]manualRecord
	agents      map[string]agentRecord
	rendered    map[string]renderedRecord
}

// Open loads the registry from path, or returns an empty registry persisting
// to path when the file does not exist yet.
func Open(path string) (*Registry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("pool: registry path is required")
	}
	registry := &Registry{
		persistPath: filepath.Clean(path),
		Now:         time.Now,
		manual:      make(map[string]manualRecord),
		agents:      make(map[string]agentRecord),
		rendered:    make(map[string]renderedRecord),
	}

	info, err := os.Lstat(registry.persistPath)
	if errors.Is(err, os.ErrNotExist) {
		return registry, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pool: inspect registry: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("pool: registry is not a regular file")
	}
	if info.Size() > MaxRegistryFileBytes {
		return nil, errors.New("pool: registry exceeds the size limit")
	}
	if err := os.Chmod(registry.persistPath, 0o600); err != nil {
		return nil, fmt.Errorf("pool: secure registry: %w", err)
	}

	file, err := os.Open(registry.persistPath)
	if err != nil {
		return nil, fmt.Errorf("pool: open registry: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, MaxRegistryFileBytes+1))
	decoder.DisallowUnknownFields()
	var stored diskRegistry
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("pool: decode registry: %w", err)
	}
	if stored.Version != diskRegistryVersion {
		return nil, fmt.Errorf("pool: unsupported registry version %d", stored.Version)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("pool: registry contains trailing JSON data")
		}
		return nil, fmt.Errorf("pool: decode trailing registry data: %w", err)
	}

	seenManual := make(map[string]struct{}, len(stored.Manual))
	for _, manual := range stored.Manual {
		if !validComponent(manual.Name) {
			return nil, errors.New("pool: registry contains an invalid manual name")
		}
		if _, duplicate := seenManual[manual.Name]; duplicate {
			return nil, errors.New("pool: registry contains a duplicate manual name")
		}
		seenManual[manual.Name] = struct{}{}
		outbound, err := validateManualOutbound(manual.Outbound)
		if err != nil {
			return nil, fmt.Errorf("pool: registry contains an invalid manual outbound: %w", err)
		}
		registry.manual[manual.Name] = manualRecord{
			outbound:  outbound,
			createdAt: manual.CreatedAt.UTC(),
			updatedAt: manual.UpdatedAt.UTC(),
		}
	}
	for agentID, agent := range stored.Agents {
		if !validComponent(agentID) {
			return nil, errors.New("pool: registry contains an invalid agent ID")
		}
		record, err := validateDiskAgent(agent)
		if err != nil {
			return nil, err
		}
		registry.agents[agentID] = record
	}
	for agentID, rendered := range stored.Rendered {
		if !validComponent(agentID) {
			return nil, errors.New("pool: registry contains an invalid agent ID")
		}
		digest, err := hex.DecodeString(rendered.ConfigSHA256)
		if err != nil || len(digest) != 32 {
			return nil, errors.New("pool: registry contains an invalid rendered digest")
		}
		var sha [32]byte
		copy(sha[:], digest)
		registry.rendered[agentID] = renderedRecord{
			poolVersion: rendered.PoolVersion,
			configSHA:   sha,
		}
	}
	registry.poolVersion = stored.PoolVersion
	return registry, nil
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// UpsertManual creates or replaces a manual outbound. Updating an existing
// name keeps its original creation time. The pool version is bumped.
func (r *Registry) UpsertManual(name string, outbound json.RawMessage) error {
	if !validComponent(name) {
		return ErrInvalidName
	}
	outbound, err := validateManualOutbound(outbound)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	previous, existed := r.manual[name]
	record := manualRecord{
		outbound:  outbound,
		createdAt: r.now(),
		updatedAt: r.now(),
	}
	if existed {
		record.createdAt = previous.createdAt
	}
	r.manual[name] = record
	previousVersion := r.poolVersion
	r.poolVersion++
	if err := r.persistLocked(); err != nil {
		if existed {
			r.manual[name] = previous
		} else {
			delete(r.manual, name)
		}
		r.poolVersion = previousVersion
		return err
	}
	return nil
}

// RemoveManual deletes a manual outbound and bumps the pool version.
func (r *Registry) RemoveManual(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	previous, existed := r.manual[name]
	if !existed {
		return ErrManualNotFound
	}
	delete(r.manual, name)
	previousVersion := r.poolVersion
	r.poolVersion++
	if err := r.persistLocked(); err != nil {
		r.manual[name] = previous
		r.poolVersion = previousVersion
		return err
	}
	return nil
}

// Manual returns all manual entries sorted by name.
func (r *Registry) Manual() []ManualEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entries := make([]ManualEntry, 0, len(r.manual))
	for name, record := range r.manual {
		entries = append(entries, ManualEntry{
			Name:      name,
			Outbound:  append(json.RawMessage(nil), record.outbound...),
			CreatedAt: record.createdAt,
			UpdatedAt: record.updatedAt,
		})
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].Name < entries[right].Name
	})
	return entries
}

// ManualByName returns one manual entry by name.
func (r *Registry) ManualByName(name string) (ManualEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	record, exists := r.manual[name]
	if !exists {
		return ManualEntry{}, false
	}
	return ManualEntry{
		Name:      name,
		Outbound:  append(json.RawMessage(nil), record.outbound...),
		CreatedAt: record.createdAt,
		UpdatedAt: record.updatedAt,
	}, true
}

// SetReported stores the addresses an agent reported for itself. Entries
// that are not globally routable are silently dropped (see
// normalizeAddresses). It persists only when the address set actually
// changed, so callers may invoke it on every heartbeat. A change bumps the
// pool version.
func (r *Registry) SetReported(agentID string, v4, v6 []string) (bool, error) {
	if !validComponent(agentID) {
		return false, ErrInvalidName
	}
	normalizedV4, err := normalizeAddresses(v4, true)
	if err != nil {
		return false, err
	}
	normalizedV6, err := normalizeAddresses(v6, false)
	if err != nil {
		return false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	previous, existed := r.agents[agentID]
	if existed &&
		stringSlicesEqual(previous.reportedV4, normalizedV4) &&
		stringSlicesEqual(previous.reportedV6, normalizedV6) {
		return false, nil
	}
	if !existed && len(normalizedV4) == 0 && len(normalizedV6) == 0 {
		return false, nil
	}

	r.agents[agentID] = agentRecord{
		reportedV4: normalizedV4,
		reportedV6: normalizedV6,
		observed:   previous.observed,
		probedV4:   previous.probedV4,
		probedV6:   previous.probedV6,
		override:   previous.override,
		updatedAt:  r.now(),
	}
	previousVersion := r.poolVersion
	r.poolVersion++
	if err := r.persistLocked(); err != nil {
		if existed {
			r.agents[agentID] = previous
		} else {
			delete(r.agents, agentID)
		}
		r.poolVersion = previousVersion
		return false, err
	}
	return true, nil
}

// SetProbed stores the addresses an on-demand agent probe returned. It shares
// SetReported's semantics: family-checked parsing, silent dropping of
// non-globally-routable entries, at most MaxAddressesPerFamily per family, a
// no-op (no persist, no version bump) when the sets are unchanged, and a
// persist + pool version bump on change.
func (r *Registry) SetProbed(agentID string, v4, v6 []string) (bool, error) {
	if !validComponent(agentID) {
		return false, ErrInvalidName
	}
	normalizedV4, err := normalizeAddresses(v4, true)
	if err != nil {
		return false, err
	}
	normalizedV6, err := normalizeAddresses(v6, false)
	if err != nil {
		return false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	previous, existed := r.agents[agentID]
	if existed &&
		stringSlicesEqual(previous.probedV4, normalizedV4) &&
		stringSlicesEqual(previous.probedV6, normalizedV6) {
		return false, nil
	}
	if !existed && len(normalizedV4) == 0 && len(normalizedV6) == 0 {
		return false, nil
	}

	r.agents[agentID] = agentRecord{
		reportedV4: previous.reportedV4,
		reportedV6: previous.reportedV6,
		observed:   previous.observed,
		probedV4:   normalizedV4,
		probedV6:   normalizedV6,
		override:   previous.override,
		updatedAt:  r.now(),
	}
	previousVersion := r.poolVersion
	r.poolVersion++
	if err := r.persistLocked(); err != nil {
		if existed {
			r.agents[agentID] = previous
		} else {
			delete(r.agents, agentID)
		}
		r.poolVersion = previousVersion
		return false, err
	}
	return true, nil
}

// SetObserved sets or clears (empty addr) the address observed from the
// agent's control connection. A non-empty addr must parse as an IP address.
// A parsed address that is not globally routable is IGNORED — the call
// reports changed=false and keeps the previous value rather than storing or
// clearing anything: the control plane already maps unusable observations to
// "", so a non-routable value here means a caller bypassed that check, and
// silently discarding it is safer than either persisting it or treating it
// as a clear. Changes bump the pool version; setting the already-current
// value is a no-op.
func (r *Registry) SetObserved(agentID, addr string) (bool, error) {
	if !validComponent(agentID) {
		return false, ErrInvalidName
	}
	addr = strings.TrimSpace(addr)
	if addr != "" {
		parsed, err := netip.ParseAddr(addr)
		if err != nil {
			return false, ErrInvalidAddress
		}
		if !globallyRoutable(parsed) {
			return false, nil
		}
		addr = parsed.String()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	previous, existed := r.agents[agentID]
	if existed && previous.observed == addr {
		return false, nil
	}
	if !existed && addr == "" {
		return false, nil
	}

	record := agentRecord{observed: addr, updatedAt: r.now()}
	if existed {
		record.reportedV4 = previous.reportedV4
		record.reportedV6 = previous.reportedV6
		record.probedV4 = previous.probedV4
		record.probedV6 = previous.probedV6
		record.override = previous.override
	}
	r.agents[agentID] = record
	previousVersion := r.poolVersion
	r.poolVersion++
	if err := r.persistLocked(); err != nil {
		if existed {
			r.agents[agentID] = previous
		} else {
			delete(r.agents, agentID)
		}
		r.poolVersion = previousVersion
		return false, err
	}
	return true, nil
}

// SetOverride sets or clears (empty addr) the operator-pinned address for an
// agent. A non-empty addr must parse as a globally routable IP address;
// anything else (including private, ULA, CGNAT, and reserved space) is
// rejected with ErrInvalidAddress, which the web UI surfaces as a 400.
// Changes bump the pool version; setting the already-current value is a
// no-op.
func (r *Registry) SetOverride(agentID, addr string) error {
	if !validComponent(agentID) {
		return ErrInvalidName
	}
	addr = strings.TrimSpace(addr)
	if addr != "" {
		parsed, err := netip.ParseAddr(addr)
		if err != nil || !globallyRoutable(parsed) {
			return ErrInvalidAddress
		}
		addr = parsed.String()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	previous, existed := r.agents[agentID]
	if existed && previous.override == addr {
		return nil
	}
	if !existed && addr == "" {
		return nil
	}

	record := agentRecord{override: addr, updatedAt: r.now()}
	if existed {
		record.reportedV4 = previous.reportedV4
		record.reportedV6 = previous.reportedV6
		record.observed = previous.observed
		record.probedV4 = previous.probedV4
		record.probedV6 = previous.probedV6
	}
	r.agents[agentID] = record
	previousVersion := r.poolVersion
	r.poolVersion++
	if err := r.persistLocked(); err != nil {
		if existed {
			r.agents[agentID] = previous
		} else {
			delete(r.agents, agentID)
		}
		r.poolVersion = previousVersion
		return err
	}
	return nil
}

// AddressSourceForFamily resolves the usable address for one agent and IP
// family, walking the source hierarchy per family:
//
//	override (operator-pinned, when it matches the family)
//	→ observed (control-connection address, when it matches the family)
//	→ probed (first on-demand probe result of the family)
//	→ reported (first interface-reported address of the family)
//
// FamilyAuto walks the families in order IPv4 then IPv6, applying the full
// per-family chain at each step, and returns the first hit. ok is false when
// the agent is unknown or no source yields an address for the requested
// family.
func (r *Registry) AddressSourceForFamily(agentID string, family Family) (addr string, source AddressSource, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	record, exists := r.agents[agentID]
	if !exists {
		return "", 0, false
	}
	return resolveForFamily(record, family)
}

// resolveForFamily implements AddressSourceForFamily on a record the caller
// already holds. All stored addresses were validated (and thereby carry a
// definite family) when written.
func resolveForFamily(record agentRecord, family Family) (string, AddressSource, bool) {
	if family == FamilyAuto {
		if addr, source, ok := resolveForFamily(record, FamilyIPv4); ok {
			return addr, source, true
		}
		return resolveForFamily(record, FamilyIPv6)
	}
	if family != FamilyIPv4 && family != FamilyIPv6 {
		return "", 0, false
	}
	if record.override != "" && addressFamily(record.override) == family {
		return record.override, SourceOverride, true
	}
	if record.observed != "" && addressFamily(record.observed) == family {
		return record.observed, SourceObserved, true
	}
	probed := record.probedV4
	reported := record.reportedV4
	if family == FamilyIPv6 {
		probed = record.probedV6
		reported = record.reportedV6
	}
	if len(probed) > 0 {
		return probed[0], SourceProbed, true
	}
	if len(reported) > 0 {
		return reported[0], SourceReported, true
	}
	return "", 0, false
}

// addressFamily returns the family of a normalized stored address.
func addressFamily(addr string) Family {
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return FamilyAuto // unreachable for registry-validated addresses
	}
	if parsed.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

// AgentAddressForFamily resolves the usable address for an agent and family
// via AddressSourceForFamily, discarding the source attribution.
func (r *Registry) AgentAddressForFamily(agentID string, family Family) (string, bool) {
	addr, _, ok := r.AddressSourceForFamily(agentID, family)
	return addr, ok
}

// AgentAddress resolves the usable address for an agent with FamilyAuto:
// override, then observed, then the first probed IPv4, then the first
// reported IPv4, then the same chain for IPv6.
func (r *Registry) AgentAddress(agentID string) (string, bool) {
	return r.AgentAddressForFamily(agentID, FamilyAuto)
}

// PoolVersion is the monotonic content version, bumped by every mutation
// that can change derived entries or rendered output.
func (r *Registry) PoolVersion() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.poolVersion
}

// MarkRendered records that an agent's config was rendered at the given pool
// version with the given config digest. It does not bump the pool version.
func (r *Registry) MarkRendered(agentID string, poolVersion uint64, sha [32]byte) error {
	if !validComponent(agentID) {
		return ErrInvalidName
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	previous, existed := r.rendered[agentID]
	r.rendered[agentID] = renderedRecord{poolVersion: poolVersion, configSHA: sha}
	if err := r.persistLocked(); err != nil {
		if existed {
			r.rendered[agentID] = previous
		} else {
			delete(r.rendered, agentID)
		}
		return err
	}
	return nil
}

// RenderedVersion returns the pool version and digest of the config last
// rendered for an agent.
func (r *Registry) RenderedVersion(agentID string) (uint64, [32]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	record, exists := r.rendered[agentID]
	if !exists {
		return 0, [32]byte{}, false
	}
	return record.poolVersion, record.configSHA, true
}

// RemoveAgent drops all pool state for an agent (addresses and render
// markers). The pool version is bumped only when something was removed.
func (r *Registry) RemoveAgent(agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	previousAgent, hadAgent := r.agents[agentID]
	previousRendered, hadRendered := r.rendered[agentID]
	if !hadAgent && !hadRendered {
		return nil
	}
	delete(r.agents, agentID)
	delete(r.rendered, agentID)
	previousVersion := r.poolVersion
	r.poolVersion++
	if err := r.persistLocked(); err != nil {
		if hadAgent {
			r.agents[agentID] = previousAgent
		}
		if hadRendered {
			r.rendered[agentID] = previousRendered
		}
		r.poolVersion = previousVersion
		return err
	}
	return nil
}

// validateManualOutbound enforces the manual outbound shape: a JSON object
// within the size cap carrying a non-empty string type. It returns a copy.
func validateManualOutbound(outbound json.RawMessage) (json.RawMessage, error) {
	if len(outbound) == 0 || len(outbound) > MaxManualOutboundBytes {
		return nil, ErrInvalidOutbound
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(outbound, &object); err != nil || object == nil {
		return nil, ErrInvalidOutbound
	}
	var outboundType string
	if err := json.Unmarshal(object["type"], &outboundType); err != nil || outboundType == "" {
		return nil, ErrInvalidOutbound
	}
	return append(json.RawMessage(nil), outbound...), nil
}

// normalizeAddresses parses, family-checks, and canonicalizes one address
// list. Unparseable or wrong-family entries are rejected with
// ErrInvalidAddress; parsed addresses that are not globally routable are
// silently DROPPED (machine-provided lists keep their routable entries).
// Used by SetReported/SetProbed and by disk validation, so stale private
// addresses written by older versions are filtered at load too.
func normalizeAddresses(addresses []string, wantV4 bool) ([]string, error) {
	if len(addresses) > MaxAddressesPerFamily {
		return nil, ErrInvalidAddress
	}
	normalized := make([]string, 0, len(addresses))
	for _, address := range addresses {
		parsed, err := netip.ParseAddr(strings.TrimSpace(address))
		if err != nil || parsed.Is4() != wantV4 {
			return nil, ErrInvalidAddress
		}
		if !globallyRoutable(parsed) {
			continue
		}
		normalized = append(normalized, parsed.String())
	}
	return normalized, nil
}

func validateDiskAgent(agent diskAgent) (agentRecord, error) {
	v4, err := normalizeAddresses(agent.ReportedV4, true)
	if err != nil {
		return agentRecord{}, errors.New("pool: registry contains an invalid reported address")
	}
	v6, err := normalizeAddresses(agent.ReportedV6, false)
	if err != nil {
		return agentRecord{}, errors.New("pool: registry contains an invalid reported address")
	}
	probedV4, err := normalizeAddresses(agent.ProbedV4, true)
	if err != nil {
		return agentRecord{}, errors.New("pool: registry contains an invalid probed address")
	}
	probedV6, err := normalizeAddresses(agent.ProbedV6, false)
	if err != nil {
		return agentRecord{}, errors.New("pool: registry contains an invalid probed address")
	}
	observed := strings.TrimSpace(agent.ObservedAddress)
	if observed != "" {
		parsed, err := netip.ParseAddr(observed)
		if err != nil {
			return agentRecord{}, errors.New("pool: registry contains an invalid observed address")
		}
		// Stale non-routable values written before the globally-routable
		// rule are dropped at load rather than resolved.
		if !globallyRoutable(parsed) {
			observed = ""
		} else {
			observed = parsed.String()
		}
	}
	override := strings.TrimSpace(agent.AddressOverride)
	if override != "" {
		parsed, err := netip.ParseAddr(override)
		if err != nil {
			return agentRecord{}, errors.New("pool: registry contains an invalid address override")
		}
		if !globallyRoutable(parsed) {
			override = ""
		} else {
			override = parsed.String()
		}
	}
	return agentRecord{
		reportedV4: v4,
		reportedV6: v6,
		observed:   observed,
		probedV4:   probedV4,
		probedV6:   probedV6,
		override:   override,
		updatedAt:  agent.UpdatedAt.UTC(),
	}, nil
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type diskRegistry struct {
	Version     int                   `json:"version"`
	PoolVersion uint64                `json:"pool_version"`
	Manual      []diskManual          `json:"manual"`
	Agents      map[string]diskAgent  `json:"agents"`
	Rendered    map[string]diskRender `json:"rendered"`
}

type diskManual struct {
	Name      string          `json:"name"`
	Outbound  json.RawMessage `json:"outbound"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// diskAgent is the on-disk agent record. The observed/probed fields were
// added after version 1 shipped; they are optional, so version-1 documents
// written before them load cleanly (missing fields decode as empty).
type diskAgent struct {
	ReportedV4      []string  `json:"reported_v4"`
	ReportedV6      []string  `json:"reported_v6"`
	ObservedAddress string    `json:"observed_address,omitempty"`
	ProbedV4        []string  `json:"probed_v4,omitempty"`
	ProbedV6        []string  `json:"probed_v6,omitempty"`
	AddressOverride string    `json:"address_override"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type diskRender struct {
	PoolVersion  uint64 `json:"pool_version"`
	ConfigSHA256 string `json:"config_sha256"`
}

// persistLocked atomically replaces the registry file: temp write + chmod +
// fsync + rename + directory fsync. The caller holds r.mu and owns in-memory
// rollback on error.
func (r *Registry) persistLocked() error {
	stored := diskRegistry{
		Version:     diskRegistryVersion,
		PoolVersion: r.poolVersion,
		Manual:      make([]diskManual, 0, len(r.manual)),
		Agents:      make(map[string]diskAgent, len(r.agents)),
		Rendered:    make(map[string]diskRender, len(r.rendered)),
	}
	names := make([]string, 0, len(r.manual))
	for name := range r.manual {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		record := r.manual[name]
		stored.Manual = append(stored.Manual, diskManual{
			Name:      name,
			Outbound:  record.outbound,
			CreatedAt: record.createdAt.UTC(),
			UpdatedAt: record.updatedAt.UTC(),
		})
	}
	for agentID, record := range r.agents {
		stored.Agents[agentID] = diskAgent{
			ReportedV4:      append([]string(nil), record.reportedV4...),
			ReportedV6:      append([]string(nil), record.reportedV6...),
			ObservedAddress: record.observed,
			ProbedV4:        append([]string(nil), record.probedV4...),
			ProbedV6:        append([]string(nil), record.probedV6...),
			AddressOverride: record.override,
			UpdatedAt:       record.updatedAt.UTC(),
		}
	}
	for agentID, record := range r.rendered {
		stored.Rendered[agentID] = diskRender{
			PoolVersion:  record.poolVersion,
			ConfigSHA256: hex.EncodeToString(record.configSHA[:]),
		}
	}
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("pool: encode registry: %w", err)
	}
	encoded = append(encoded, '\n')

	directory := filepath.Dir(r.persistPath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("pool: create registry directory: %w", err)
	}
	tempFile, err := os.CreateTemp(directory, ".outbound-pool-*.tmp")
	if err != nil {
		return fmt.Errorf("pool: create temporary registry: %w", err)
	}
	tempPath := tempFile.Name()
	installed := false
	defer func() {
		_ = tempFile.Close()
		if !installed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := tempFile.Chmod(0o600); err != nil {
		return fmt.Errorf("pool: secure temporary registry: %w", err)
	}
	if _, err := tempFile.Write(encoded); err != nil {
		return fmt.Errorf("pool: write temporary registry: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("pool: flush temporary registry: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("pool: close temporary registry: %w", err)
	}
	if err := replaceFile(tempPath, r.persistPath); err != nil {
		return fmt.Errorf("pool: replace registry: %w", err)
	}
	installed = true
	return nil
}
