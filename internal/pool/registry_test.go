package pool

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var registryTestNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func openTestRegistry(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "outbound-pool.json")
	registry, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	registry.Now = func() time.Time { return registryTestNow }
	return registry, path
}

func reopenTestRegistry(t *testing.T, path string) *Registry {
	t.Helper()
	registry, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", path, err)
	}
	return registry
}

func TestOpenMissingFile(t *testing.T) {
	registry, _ := openTestRegistry(t)
	if registry.PoolVersion() != 0 {
		t.Fatalf("PoolVersion() = %d, want 0", registry.PoolVersion())
	}
	if entries := registry.Manual(); len(entries) != 0 {
		t.Fatalf("Manual() = %v, want empty", entries)
	}
	if _, ok := registry.AgentAddress("edge-1"); ok {
		t.Fatal("AgentAddress() ok = true, want false")
	}
}

func TestOpenRequiresPath(t *testing.T) {
	if _, err := Open("  "); err == nil {
		t.Fatal("Open() error = nil, want error")
	}
}

func TestManualCRUDAndReload(t *testing.T) {
	registry, path := openTestRegistry(t)

	outbound := json.RawMessage(`{"type":"socks","server":"10.0.0.1","server_port":1080}`)
	if err := registry.UpsertManual("upstream-socks", outbound); err != nil {
		t.Fatalf("UpsertManual() error = %v", err)
	}
	if registry.PoolVersion() != 1 {
		t.Fatalf("PoolVersion() = %d, want 1", registry.PoolVersion())
	}
	if err := registry.UpsertManual("backup", json.RawMessage(`{"type":"direct"}`)); err != nil {
		t.Fatalf("UpsertManual() error = %v", err)
	}
	if registry.PoolVersion() != 2 {
		t.Fatalf("PoolVersion() = %d, want 2", registry.PoolVersion())
	}

	entry, ok := registry.ManualByName("upstream-socks")
	if !ok {
		t.Fatal("ManualByName() ok = false, want true")
	}
	if string(entry.Outbound) != string(outbound) {
		t.Fatalf("ManualByName() outbound = %s, want %s", entry.Outbound, outbound)
	}
	if !entry.CreatedAt.Equal(registryTestNow) || !entry.UpdatedAt.Equal(registryTestNow) {
		t.Fatalf("ManualByName() times = %v/%v, want %v", entry.CreatedAt, entry.UpdatedAt, registryTestNow)
	}
	if _, ok := registry.ManualByName("missing"); ok {
		t.Fatal("ManualByName(missing) ok = true, want false")
	}

	entries := registry.Manual()
	if len(entries) != 2 || entries[0].Name != "backup" || entries[1].Name != "upstream-socks" {
		t.Fatalf("Manual() = %v, want sorted [backup upstream-socks]", entries)
	}

	later := registryTestNow.Add(time.Hour)
	registry.Now = func() time.Time { return later }
	if err := registry.UpsertManual("upstream-socks", json.RawMessage(`{"type":"socks","server":"10.0.0.2","server_port":1080}`)); err != nil {
		t.Fatalf("UpsertManual() error = %v", err)
	}
	entry, _ = registry.ManualByName("upstream-socks")
	if !entry.CreatedAt.Equal(registryTestNow) {
		t.Fatalf("CreatedAt = %v, want preserved %v", entry.CreatedAt, registryTestNow)
	}
	if !entry.UpdatedAt.Equal(later) {
		t.Fatalf("UpdatedAt = %v, want %v", entry.UpdatedAt, later)
	}
	if registry.PoolVersion() != 3 {
		t.Fatalf("PoolVersion() = %d, want 3", registry.PoolVersion())
	}

	if err := registry.RemoveManual("backup"); err != nil {
		t.Fatalf("RemoveManual() error = %v", err)
	}
	if registry.PoolVersion() != 4 {
		t.Fatalf("PoolVersion() = %d, want 4", registry.PoolVersion())
	}
	if err := registry.RemoveManual("backup"); !errors.Is(err, ErrManualNotFound) {
		t.Fatalf("RemoveManual() error = %v, want ErrManualNotFound", err)
	}

	reloaded := reopenTestRegistry(t, path)
	if reloaded.PoolVersion() != 4 {
		t.Fatalf("reloaded PoolVersion() = %d, want 4", reloaded.PoolVersion())
	}
	entries = reloaded.Manual()
	if len(entries) != 1 || entries[0].Name != "upstream-socks" {
		t.Fatalf("reloaded Manual() = %v, want [upstream-socks]", entries)
	}
	if !entries[0].CreatedAt.Equal(registryTestNow) || !entries[0].UpdatedAt.Equal(later) {
		t.Fatalf("reloaded times = %v/%v", entries[0].CreatedAt, entries[0].UpdatedAt)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("registry mode = %o, want 600", info.Mode().Perm())
	}
}

func TestUpsertManualValidation(t *testing.T) {
	registry, _ := openTestRegistry(t)

	oversized := append(json.RawMessage(`{"type":"x","pad":"`), make([]byte, MaxManualOutboundBytes)...)
	oversized = append(oversized, '"', '}')
	cases := []struct {
		name     string
		outbound json.RawMessage
		want     error
	}{
		{"", json.RawMessage(`{"type":"socks"}`), ErrInvalidName},
		{"-leading-dash", json.RawMessage(`{"type":"socks"}`), ErrInvalidName},
		{"bad name", json.RawMessage(`{"type":"socks"}`), ErrInvalidName},
		{strings.Repeat("a", 129), json.RawMessage(`{"type":"socks"}`), ErrInvalidName},
		{"ok", nil, ErrInvalidOutbound},
		{"ok", json.RawMessage(`"string"`), ErrInvalidOutbound},
		{"ok", json.RawMessage(`[1,2]`), ErrInvalidOutbound},
		{"ok", json.RawMessage(`{"server":"x"}`), ErrInvalidOutbound},
		{"ok", json.RawMessage(`{"type":""}`), ErrInvalidOutbound},
		{"ok", json.RawMessage(`{"type":7}`), ErrInvalidOutbound},
		{"ok", json.RawMessage(`{"type":"socks"`), ErrInvalidOutbound},
		{"ok", oversized, ErrInvalidOutbound},
	}
	for _, testCase := range cases {
		if err := registry.UpsertManual(testCase.name, testCase.outbound); !errors.Is(err, testCase.want) {
			t.Errorf("UpsertManual(%q, %s) error = %v, want %v",
				testCase.name, truncateForTest(testCase.outbound), err, testCase.want)
		}
	}
	if registry.PoolVersion() != 0 {
		t.Fatalf("PoolVersion() = %d after rejected upserts, want 0", registry.PoolVersion())
	}
}

func truncateForTest(data []byte) string {
	if len(data) > 40 {
		return string(data[:40]) + "…"
	}
	return string(data)
}

func TestSetReportedChangeDetection(t *testing.T) {
	registry, path := openTestRegistry(t)

	changed, err := registry.SetReported("edge-1", []string{"203.0.113.10"}, []string{"2001:db8::1"})
	if err != nil || !changed {
		t.Fatalf("SetReported() = %v, %v, want true, nil", changed, err)
	}
	if registry.PoolVersion() != 1 {
		t.Fatalf("PoolVersion() = %d, want 1", registry.PoolVersion())
	}
	address, ok := registry.AgentAddress("edge-1")
	if !ok || address != "203.0.113.10" {
		t.Fatalf("AgentAddress() = %q, %v, want 203.0.113.10, true", address, ok)
	}

	infoBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	changed, err = registry.SetReported("edge-1", []string{"203.0.113.10"}, []string{"2001:db8::1"})
	if err != nil || changed {
		t.Fatalf("SetReported() unchanged set = %v, %v, want false, nil", changed, err)
	}
	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		t.Fatal("SetReported() with unchanged set persisted; want no write")
	}
	if registry.PoolVersion() != 1 {
		t.Fatalf("PoolVersion() = %d, want 1 (no bump without change)", registry.PoolVersion())
	}

	// No record and no addresses: also a no-op.
	changed, err = registry.SetReported("edge-2", nil, nil)
	if err != nil || changed {
		t.Fatalf("SetReported() empty new agent = %v, %v, want false, nil", changed, err)
	}

	changed, err = registry.SetReported("edge-1", nil, []string{"2001:db8::1"})
	if err != nil || !changed {
		t.Fatalf("SetReported() changed set = %v, %v, want true, nil", changed, err)
	}
	address, ok = registry.AgentAddress("edge-1")
	if !ok || address != "2001:db8::1" {
		t.Fatalf("AgentAddress() = %q, %v, want 2001:db8::1, true", address, ok)
	}

	reloaded := reopenTestRegistry(t, path)
	address, ok = reloaded.AgentAddress("edge-1")
	if !ok || address != "2001:db8::1" {
		t.Fatalf("reloaded AgentAddress() = %q, %v, want 2001:db8::1, true", address, ok)
	}
}

func TestSetReportedValidation(t *testing.T) {
	registry, _ := openTestRegistry(t)

	if _, err := registry.SetReported("bad agent", []string{"1.2.3.4"}, nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("SetReported() error = %v, want ErrInvalidName", err)
	}
	if _, err := registry.SetReported("edge-1", []string{"not-an-ip"}, nil); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("SetReported() error = %v, want ErrInvalidAddress", err)
	}
	if _, err := registry.SetReported("edge-1", []string{"2001:db8::1"}, nil); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("SetReported() v6 in v4 list error = %v, want ErrInvalidAddress", err)
	}
	if _, err := registry.SetReported("edge-1", nil, []string{"1.2.3.4"}); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("SetReported() v4 in v6 list error = %v, want ErrInvalidAddress", err)
	}
	tooMany := make([]string, MaxAddressesPerFamily+1)
	for index := range tooMany {
		tooMany[index] = "192.0.2.1"
	}
	if _, err := registry.SetReported("edge-1", tooMany, nil); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("SetReported() too many error = %v, want ErrInvalidAddress", err)
	}
	if registry.PoolVersion() != 0 {
		t.Fatalf("PoolVersion() = %d after rejected reports, want 0", registry.PoolVersion())
	}
}

func TestSetReportedAndProbedDropNonRoutable(t *testing.T) {
	registry, _ := openTestRegistry(t)

	// Non-routable entries are silently dropped; the routable rest is kept.
	changed, err := registry.SetReported(
		"edge-1",
		[]string{"10.0.0.8", "203.0.113.1", "100.64.0.9", "240.0.0.9", "127.0.0.1"},
		[]string{"fd12:3456::1", "2001:db8::1"},
	)
	if err != nil || !changed {
		t.Fatalf("SetReported() = %v, %v, want true, nil", changed, err)
	}
	addr, source, ok := registry.AddressSourceForFamily("edge-1", FamilyIPv4)
	if !ok || addr != "203.0.113.1" || source != SourceReported {
		t.Fatalf("AddressSourceForFamily(ipv4) = %q, %v, %v, want reported 203.0.113.1", addr, source, ok)
	}
	addr, source, ok = registry.AddressSourceForFamily("edge-1", FamilyIPv6)
	if !ok || addr != "2001:db8::1" || source != SourceReported {
		t.Fatalf("AddressSourceForFamily(ipv6) = %q, %v, %v, want reported 2001:db8::1", addr, source, ok)
	}

	// An agent whose only reported addresses are private yields NO address.
	changed, err = registry.SetReported("edge-2", []string{"192.168.1.2"}, []string{"fd00::9"})
	if err != nil || changed {
		t.Fatalf("SetReported(private only) = %v, %v, want false, nil (empty record)", changed, err)
	}
	if _, _, ok := registry.AddressSourceForFamily("edge-2", FamilyAuto); ok {
		t.Fatal("AddressSourceForFamily() ok = true for a private-only agent, want false")
	}

	// Same dropping for probed addresses.
	changed, err = registry.SetProbed("edge-3", []string{"172.16.0.5", "203.0.113.20"}, nil)
	if err != nil || !changed {
		t.Fatalf("SetProbed() = %v, %v, want true, nil", changed, err)
	}
	addr, source, ok = registry.AddressSourceForFamily("edge-3", FamilyIPv4)
	if !ok || addr != "203.0.113.20" || source != SourceProbed {
		t.Fatalf("AddressSourceForFamily() = %q, %v, %v, want probed 203.0.113.20", addr, source, ok)
	}
}

func TestSetOverrideRejectsNonRoutable(t *testing.T) {
	registry, _ := openTestRegistry(t)

	for _, rejected := range []string{
		"10.0.0.8",
		"172.16.0.1",
		"192.168.1.2",
		"100.64.0.9",
		"240.0.0.9",
		"127.0.0.1",
		"fc00::1",
		"fd12:3456::1",
		"fe80::1",
		"::1",
	} {
		if err := registry.SetOverride("edge-1", rejected); !errors.Is(err, ErrInvalidAddress) {
			t.Fatalf("SetOverride(%q) error = %v, want ErrInvalidAddress", rejected, err)
		}
	}
	if registry.PoolVersion() != 0 {
		t.Fatalf("PoolVersion() = %d after rejected overrides, want 0", registry.PoolVersion())
	}
	if _, ok := registry.AgentAddress("edge-1"); ok {
		t.Fatal("AgentAddress() ok = true after rejected overrides, want false")
	}

	// TEST-NET/documentation ranges stay valid operator overrides.
	if err := registry.SetOverride("edge-1", "198.51.100.9"); err != nil {
		t.Fatalf("SetOverride(TEST-NET) error = %v", err)
	}
}

func TestAddressSelectionOrder(t *testing.T) {
	registry, _ := openTestRegistry(t)

	if _, err := registry.SetReported("edge-1", []string{"203.0.113.1", "203.0.113.2"}, []string{"2001:db8::1"}); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	address, ok := registry.AgentAddress("edge-1")
	if !ok || address != "203.0.113.1" {
		t.Fatalf("AgentAddress() = %q, %v, want first v4", address, ok)
	}

	if err := registry.SetOverride("edge-1", "198.51.100.9"); err != nil {
		t.Fatalf("SetOverride() error = %v", err)
	}
	address, ok = registry.AgentAddress("edge-1")
	if !ok || address != "198.51.100.9" {
		t.Fatalf("AgentAddress() = %q, %v, want override", address, ok)
	}
	versionWithOverride := registry.PoolVersion()

	// Re-setting the same override is a no-op.
	if err := registry.SetOverride("edge-1", "198.51.100.9"); err != nil {
		t.Fatalf("SetOverride() error = %v", err)
	}
	if registry.PoolVersion() != versionWithOverride {
		t.Fatalf("PoolVersion() bumped on no-op override: %d != %d", registry.PoolVersion(), versionWithOverride)
	}

	if err := registry.SetOverride("edge-1", ""); err != nil {
		t.Fatalf("SetOverride(clear) error = %v", err)
	}
	address, ok = registry.AgentAddress("edge-1")
	if !ok || address != "203.0.113.1" {
		t.Fatalf("AgentAddress() after clear = %q, %v, want first v4", address, ok)
	}

	if err := registry.SetOverride("edge-1", "not-an-ip"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("SetOverride() error = %v, want ErrInvalidAddress", err)
	}

	// Override works for an agent with no reported addresses.
	if err := registry.SetOverride("edge-2", "2001:db8::5"); err != nil {
		t.Fatalf("SetOverride() error = %v", err)
	}
	address, ok = registry.AgentAddress("edge-2")
	if !ok || address != "2001:db8::5" {
		t.Fatalf("AgentAddress() = %q, %v, want override-only", address, ok)
	}

	// v6 fallback when no v4 and no override.
	if _, err := registry.SetReported("edge-3", nil, []string{"2001:db8::7"}); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	address, ok = registry.AgentAddress("edge-3")
	if !ok || address != "2001:db8::7" {
		t.Fatalf("AgentAddress() = %q, %v, want v6 fallback", address, ok)
	}
}

func TestMarkRendered(t *testing.T) {
	registry, path := openTestRegistry(t)

	if _, _, ok := registry.RenderedVersion("edge-1"); ok {
		t.Fatal("RenderedVersion() ok = true, want false")
	}
	digest := sha256.Sum256([]byte("rendered config"))
	if err := registry.MarkRendered("edge-1", 7, digest); err != nil {
		t.Fatalf("MarkRendered() error = %v", err)
	}
	if registry.PoolVersion() != 0 {
		t.Fatalf("PoolVersion() = %d, want 0 (MarkRendered must not bump)", registry.PoolVersion())
	}
	poolVersion, sha, ok := registry.RenderedVersion("edge-1")
	if !ok || poolVersion != 7 || sha != digest {
		t.Fatalf("RenderedVersion() = %d, %x, %v", poolVersion, sha, ok)
	}
	if err := registry.MarkRendered("bad agent", 1, digest); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("MarkRendered() error = %v, want ErrInvalidName", err)
	}

	reloaded := reopenTestRegistry(t, path)
	poolVersion, sha, ok = reloaded.RenderedVersion("edge-1")
	if !ok || poolVersion != 7 || sha != digest {
		t.Fatalf("reloaded RenderedVersion() = %d, %x, %v", poolVersion, sha, ok)
	}
}

func TestRemoveAgent(t *testing.T) {
	registry, path := openTestRegistry(t)

	if err := registry.RemoveAgent("edge-1"); err != nil {
		t.Fatalf("RemoveAgent() absent error = %v, want nil", err)
	}
	if registry.PoolVersion() != 0 {
		t.Fatalf("PoolVersion() = %d, want 0 (nothing removed)", registry.PoolVersion())
	}

	if _, err := registry.SetReported("edge-1", []string{"203.0.113.1"}, nil); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	if err := registry.MarkRendered("edge-1", registry.PoolVersion(), sha256.Sum256([]byte("x"))); err != nil {
		t.Fatalf("MarkRendered() error = %v", err)
	}
	versionBefore := registry.PoolVersion()
	if err := registry.RemoveAgent("edge-1"); err != nil {
		t.Fatalf("RemoveAgent() error = %v", err)
	}
	if registry.PoolVersion() != versionBefore+1 {
		t.Fatalf("PoolVersion() = %d, want %d", registry.PoolVersion(), versionBefore+1)
	}
	if _, ok := registry.AgentAddress("edge-1"); ok {
		t.Fatal("AgentAddress() ok = true after removal")
	}
	if _, _, ok := registry.RenderedVersion("edge-1"); ok {
		t.Fatal("RenderedVersion() ok = true after removal")
	}

	reloaded := reopenTestRegistry(t, path)
	if _, ok := reloaded.AgentAddress("edge-1"); ok {
		t.Fatal("reloaded AgentAddress() ok = true after removal")
	}
	if _, _, ok := reloaded.RenderedVersion("edge-1"); ok {
		t.Fatal("reloaded RenderedVersion() ok = true after removal")
	}
}

// breakPersist replaces the registry file with a directory so the atomic
// rename fails, exercising in-memory rollback.
func breakPersist(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(path)
	})
}

func TestPersistFailureRollsBackManual(t *testing.T) {
	registry, path := openTestRegistry(t)
	if err := registry.UpsertManual("existing", json.RawMessage(`{"type":"direct"}`)); err != nil {
		t.Fatalf("UpsertManual() error = %v", err)
	}
	versionBefore := registry.PoolVersion()
	breakPersist(t, path)

	if err := registry.UpsertManual("new-entry", json.RawMessage(`{"type":"direct"}`)); err == nil {
		t.Fatal("UpsertManual() error = nil, want persist failure")
	}
	if _, ok := registry.ManualByName("new-entry"); ok {
		t.Fatal("ManualByName(new-entry) ok = true after failed persist, want rolled back")
	}
	if _, ok := registry.ManualByName("existing"); !ok {
		t.Fatal("ManualByName(existing) lost after failed persist")
	}
	if registry.PoolVersion() != versionBefore {
		t.Fatalf("PoolVersion() = %d, want rolled back %d", registry.PoolVersion(), versionBefore)
	}

	if err := registry.RemoveManual("existing"); err == nil {
		t.Fatal("RemoveManual() error = nil, want persist failure")
	}
	if _, ok := registry.ManualByName("existing"); !ok {
		t.Fatal("ManualByName(existing) ok = false after failed remove, want rolled back")
	}
	if registry.PoolVersion() != versionBefore {
		t.Fatalf("PoolVersion() = %d, want rolled back %d", registry.PoolVersion(), versionBefore)
	}
}

func TestPersistFailureRollsBackAddresses(t *testing.T) {
	registry, path := openTestRegistry(t)
	if _, err := registry.SetReported("edge-1", []string{"203.0.113.1"}, nil); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	versionBefore := registry.PoolVersion()
	breakPersist(t, path)

	if _, err := registry.SetReported("edge-1", []string{"203.0.113.2"}, nil); err == nil {
		t.Fatal("SetReported() error = nil, want persist failure")
	}
	address, ok := registry.AgentAddress("edge-1")
	if !ok || address != "203.0.113.1" {
		t.Fatalf("AgentAddress() = %q, %v after failed persist, want rolled back 203.0.113.1", address, ok)
	}
	if err := registry.SetOverride("edge-1", "198.51.100.1"); err == nil {
		t.Fatal("SetOverride() error = nil, want persist failure")
	}
	address, ok = registry.AgentAddress("edge-1")
	if !ok || address != "203.0.113.1" {
		t.Fatalf("AgentAddress() = %q, %v after failed override, want 203.0.113.1", address, ok)
	}
	if err := registry.RemoveAgent("edge-1"); err == nil {
		t.Fatal("RemoveAgent() error = nil, want persist failure")
	}
	if _, ok := registry.AgentAddress("edge-1"); !ok {
		t.Fatal("AgentAddress() ok = false after failed remove, want rolled back")
	}
	if registry.PoolVersion() != versionBefore {
		t.Fatalf("PoolVersion() = %d, want rolled back %d", registry.PoolVersion(), versionBefore)
	}
}

func TestOpenRejectsInvalidDocuments(t *testing.T) {
	validManual := `{"name":"ok","outbound":{"type":"socks"},"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z"}`
	cases := []struct {
		name    string
		content string
	}{
		{"not json", `{`},
		{"wrong version", `{"version":2,"pool_version":0,"manual":[],"agents":{},"rendered":{}}`},
		{"unknown field", `{"version":1,"pool_version":0,"manual":[],"agents":{},"rendered":{},"surprise":1}`},
		{"trailing data", `{"version":1,"pool_version":0,"manual":[],"agents":{},"rendered":{}} {}`},
		{"bad manual name", `{"version":1,"pool_version":0,"manual":[{"name":"bad name","outbound":{"type":"x"},"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z"}],"agents":{},"rendered":{}}`},
		{"duplicate manual", `{"version":1,"pool_version":0,"manual":[` + validManual + `,` + validManual + `],"agents":{},"rendered":{}}`},
		{"manual outbound not object", `{"version":1,"pool_version":0,"manual":[{"name":"ok","outbound":[1],"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z"}],"agents":{},"rendered":{}}`},
		{"manual outbound no type", `{"version":1,"pool_version":0,"manual":[{"name":"ok","outbound":{"server":"x"},"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z"}],"agents":{},"rendered":{}}`},
		{"bad agent id", `{"version":1,"pool_version":0,"manual":[],"agents":{"bad agent":{"reported_v4":[],"reported_v6":[],"address_override":"","updated_at":"2026-01-02T03:04:05Z"}},"rendered":{}}`},
		{"bad reported address", `{"version":1,"pool_version":0,"manual":[],"agents":{"edge-1":{"reported_v4":["nope"],"reported_v6":[],"address_override":"","updated_at":"2026-01-02T03:04:05Z"}},"rendered":{}}`},
		{"v6 in v4 list", `{"version":1,"pool_version":0,"manual":[],"agents":{"edge-1":{"reported_v4":["2001:db8::1"],"reported_v6":[],"address_override":"","updated_at":"2026-01-02T03:04:05Z"}},"rendered":{}}`},
		{"too many addresses", `{"version":1,"pool_version":0,"manual":[],"agents":{"edge-1":{"reported_v4":["192.0.2.1","192.0.2.1","192.0.2.1","192.0.2.1","192.0.2.1","192.0.2.1","192.0.2.1","192.0.2.1","192.0.2.1"],"reported_v6":[],"address_override":"","updated_at":"2026-01-02T03:04:05Z"}},"rendered":{}}`},
		{"bad override", `{"version":1,"pool_version":0,"manual":[],"agents":{"edge-1":{"reported_v4":[],"reported_v6":[],"address_override":"nope","updated_at":"2026-01-02T03:04:05Z"}},"rendered":{}}`},
		{"bad rendered digest", `{"version":1,"pool_version":0,"manual":[],"agents":{},"rendered":{"edge-1":{"pool_version":1,"config_sha256":"zz"}}}`},
		{"bad rendered agent", `{"version":1,"pool_version":0,"manual":[],"agents":{},"rendered":{"bad agent":{"pool_version":1,"config_sha256":"` + strings.Repeat("ab", 32) + `"}}}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outbound-pool.json")
			if err := os.WriteFile(path, []byte(testCase.content), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if _, err := Open(path); err == nil {
				t.Fatalf("Open() error = nil, want error for %s", testCase.name)
			}
		})
	}
}

func TestOpenValidDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbound-pool.json")
	content := `{
  "version": 1,
  "pool_version": 7,
  "manual": [{"name": "upstream-socks", "outbound": {"type": "socks", "server": "10.0.0.1"}, "created_at": "2026-01-02T03:04:05Z", "updated_at": "2026-01-02T03:04:05Z"}],
  "agents": {"edge-paris-1": {"reported_v4": ["203.0.113.4"], "reported_v6": [], "address_override": "", "updated_at": "2026-01-02T03:04:05Z"}},
  "rendered": {"edge-lyon-1": {"pool_version": 6, "config_sha256": "` + strings.Repeat("ab", 32) + `"}}
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	registry, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if registry.PoolVersion() != 7 {
		t.Fatalf("PoolVersion() = %d, want 7", registry.PoolVersion())
	}
	address, ok := registry.AgentAddress("edge-paris-1")
	if !ok || address != "203.0.113.4" {
		t.Fatalf("AgentAddress() = %q, %v", address, ok)
	}
	poolVersion, _, ok := registry.RenderedVersion("edge-lyon-1")
	if !ok || poolVersion != 6 {
		t.Fatalf("RenderedVersion() = %d, %v", poolVersion, ok)
	}
	if _, ok := registry.ManualByName("upstream-socks"); !ok {
		t.Fatal("ManualByName() ok = false")
	}
}

func TestParseFamily(t *testing.T) {
	cases := []struct {
		input string
		want  Family
	}{
		{"", FamilyAuto},
		{"auto", FamilyAuto},
		{"ipv4", FamilyIPv4},
		{"ipv6", FamilyIPv6},
	}
	for _, testCase := range cases {
		family, err := ParseFamily(testCase.input)
		if err != nil || family != testCase.want {
			t.Errorf("ParseFamily(%q) = %v, %v, want %v, nil", testCase.input, family, err, testCase.want)
		}
	}
	for _, input := range []string{"v4", "4", "ip", "IPV4", "ipv7"} {
		if _, err := ParseFamily(input); !errors.Is(err, ErrInvalidFamily) {
			t.Errorf("ParseFamily(%q) error = %v, want ErrInvalidFamily", input, err)
		}
	}
	if got := []string{FamilyAuto.String(), FamilyIPv4.String(), FamilyIPv6.String()}; strings.Join(got, ",") != "auto,ipv4,ipv6" {
		t.Fatalf("Family.String() = %v", got)
	}
	if got := []string{SourceOverride.String(), SourceObserved.String(), SourceProbed.String(), SourceReported.String()}; strings.Join(got, ",") != "override,observed,probed,reported" {
		t.Fatalf("AddressSource.String() = %v", got)
	}
}

// seedHierarchyAgent fills one agent with every address source, including the
// legacy on-disk state where probed and reported addresses coexist. Current
// setters keep those two fallback sources mutually exclusive per family, but
// resolution remains compatible with registries written by older releases.
func seedHierarchyAgent(t *testing.T, registry *Registry, agentID string) {
	t.Helper()
	registry.mu.Lock()
	registry.agents[agentID] = agentRecord{
		reportedV4: []string{"203.0.113.10"},
		reportedV6: []string{"2001:db8::10"},
		probedV4:   []string{"203.0.113.20"},
		probedV6:   []string{"2001:db8::20"},
	}
	registry.mu.Unlock()
	if _, err := registry.SetObserved(agentID, "2001:db8::30"); err != nil {
		t.Fatalf("SetObserved() error = %v", err)
	}
	if err := registry.SetOverride(agentID, "203.0.113.40"); err != nil {
		t.Fatalf("SetOverride() error = %v", err)
	}
}

func TestAddressSourceForFamilyHierarchy(t *testing.T) {
	registry, _ := openTestRegistry(t)
	seedHierarchyAgent(t, registry, "edge-1")

	assertResolution := func(family Family, wantAddr string, wantSource AddressSource) {
		t.Helper()
		addr, source, ok := registry.AddressSourceForFamily("edge-1", family)
		if !ok || addr != wantAddr || source != wantSource {
			t.Fatalf("AddressSourceForFamily(%v) = %q, %v, %v, want %q, %v, true",
				family, addr, source, ok, wantAddr, wantSource)
		}
		wrapped, ok := registry.AgentAddressForFamily("edge-1", family)
		if !ok || wrapped != wantAddr {
			t.Fatalf("AgentAddressForFamily(%v) = %q, %v, want %q, true", family, wrapped, ok, wantAddr)
		}
	}

	// Full chain: v4 override wins v4; v6 observed wins v6; auto walks v4 first.
	assertResolution(FamilyIPv4, "203.0.113.40", SourceOverride)
	assertResolution(FamilyIPv6, "2001:db8::30", SourceObserved)
	assertResolution(FamilyAuto, "203.0.113.40", SourceOverride)

	// The v4 override does not satisfy a v6 request (and vice versa).
	if err := registry.SetOverride("edge-1", ""); err != nil {
		t.Fatalf("SetOverride(clear) error = %v", err)
	}
	assertResolution(FamilyIPv4, "203.0.113.20", SourceProbed) // observed is v6, skipped
	assertResolution(FamilyIPv6, "2001:db8::30", SourceObserved)

	// Clearing observed drops v6 to probed; v4 probed precedes reported.
	if _, err := registry.SetObserved("edge-1", ""); err != nil {
		t.Fatalf("SetObserved(clear) error = %v", err)
	}
	assertResolution(FamilyIPv6, "2001:db8::20", SourceProbed)
	assertResolution(FamilyAuto, "203.0.113.20", SourceProbed)

	// Clearing probed drops both families to reported.
	if _, err := registry.SetProbed("edge-1", nil, nil); err != nil {
		t.Fatalf("SetProbed(clear) error = %v", err)
	}
	assertResolution(FamilyIPv4, "203.0.113.10", SourceReported)
	assertResolution(FamilyIPv6, "2001:db8::10", SourceReported)
	assertResolution(FamilyAuto, "203.0.113.10", SourceReported)

	// Auto falls through to the v6 chain when no v4 source exists.
	if _, err := registry.SetReported("edge-1", nil, []string{"2001:db8::10"}); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	assertResolution(FamilyAuto, "2001:db8::10", SourceReported)

	// Nothing left: not ok. Unknown agents and invalid families: not ok.
	if _, err := registry.SetReported("edge-1", nil, nil); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	if _, _, ok := registry.AddressSourceForFamily("edge-1", FamilyAuto); ok {
		t.Fatal("AddressSourceForFamily() ok = true with no addresses, want false")
	}
	if _, _, ok := registry.AddressSourceForFamily("edge-gone", FamilyAuto); ok {
		t.Fatal("AddressSourceForFamily() ok = true for unknown agent, want false")
	}
	if _, _, ok := registry.AddressSourceForFamily("edge-1", Family(7)); ok {
		t.Fatal("AddressSourceForFamily() ok = true for invalid family, want false")
	}
}

func TestAddressSourceObservedV4(t *testing.T) {
	registry, _ := openTestRegistry(t)
	if _, err := registry.SetReported("edge-1", []string{"203.0.113.10"}, []string{"2001:db8::10"}); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	if _, err := registry.SetObserved("edge-1", "198.51.100.7"); err != nil {
		t.Fatalf("SetObserved() error = %v", err)
	}
	addr, source, ok := registry.AddressSourceForFamily("edge-1", FamilyIPv4)
	if !ok || addr != "198.51.100.7" || source != SourceObserved {
		t.Fatalf("AddressSourceForFamily(ipv4) = %q, %v, %v, want observed v4", addr, source, ok)
	}
	// A v4 observed address does not satisfy a v6 request.
	addr, source, ok = registry.AddressSourceForFamily("edge-1", FamilyIPv6)
	if !ok || addr != "2001:db8::10" || source != SourceReported {
		t.Fatalf("AddressSourceForFamily(ipv6) = %q, %v, %v, want reported v6", addr, source, ok)
	}
}

func TestSetObservedSemantics(t *testing.T) {
	registry, path := openTestRegistry(t)

	if _, err := registry.SetObserved("bad agent", "1.2.3.4"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("SetObserved() error = %v, want ErrInvalidName", err)
	}
	if _, err := registry.SetObserved("edge-1", "not-an-ip"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("SetObserved() error = %v, want ErrInvalidAddress", err)
	}
	if registry.PoolVersion() != 0 {
		t.Fatalf("PoolVersion() = %d after rejected calls, want 0", registry.PoolVersion())
	}

	// Only globally routable addresses are stored; anything else is ignored.
	changed, err := registry.SetObserved("edge-1", "198.51.100.7")
	if err != nil || !changed {
		t.Fatalf("SetObserved() = %v, %v, want true, nil", changed, err)
	}
	if registry.PoolVersion() != 1 {
		t.Fatalf("PoolVersion() = %d, want 1", registry.PoolVersion())
	}
	addr, source, ok := registry.AddressSourceForFamily("edge-1", FamilyIPv4)
	if !ok || addr != "198.51.100.7" || source != SourceObserved {
		t.Fatalf("AddressSourceForFamily() = %q, %v, %v", addr, source, ok)
	}

	// A non-routable value is ignored entirely: no change, no version bump,
	// the previous value is kept (it is NOT treated as a clear).
	for _, ignored := range []string{"127.0.0.1", "10.0.0.8", "100.64.0.9", "240.0.0.9", "fd12:3456::1"} {
		changed, err = registry.SetObserved("edge-1", ignored)
		if err != nil || changed {
			t.Fatalf("SetObserved(%q) = %v, %v, want false, nil (ignored)", ignored, changed, err)
		}
	}
	if registry.PoolVersion() != 1 {
		t.Fatalf("PoolVersion() = %d after ignored values, want 1", registry.PoolVersion())
	}
	addr, source, ok = registry.AddressSourceForFamily("edge-1", FamilyIPv4)
	if !ok || addr != "198.51.100.7" || source != SourceObserved {
		t.Fatalf("AddressSourceForFamily() = %q, %v, %v after ignored values", addr, source, ok)
	}
	// An ignored value for an unknown agent creates no record.
	if changed, err = registry.SetObserved("edge-3", "10.0.0.8"); err != nil || changed {
		t.Fatalf("SetObserved(new agent, private) = %v, %v, want false, nil", changed, err)
	}
	if _, _, ok := registry.AddressSourceForFamily("edge-3", FamilyAuto); ok {
		t.Fatal("ignored observed value created a record")
	}

	// No record and clearing: no-op. Same value again: no-op, no persist.
	changed, err = registry.SetObserved("edge-2", "")
	if err != nil || changed {
		t.Fatalf("SetObserved(clear absent) = %v, %v, want false, nil", changed, err)
	}
	infoBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	changed, err = registry.SetObserved("edge-1", "198.51.100.7")
	if err != nil || changed {
		t.Fatalf("SetObserved(same) = %v, %v, want false, nil", changed, err)
	}
	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		t.Fatal("SetObserved() with unchanged value persisted; want no write")
	}

	// Persisted across reload.
	reloaded := reopenTestRegistry(t, path)
	addr, _, ok = reloaded.AddressSourceForFamily("edge-1", FamilyIPv4)
	if !ok || addr != "198.51.100.7" {
		t.Fatalf("reloaded AddressSourceForFamily() = %q, %v", addr, ok)
	}

	// Clearing bumps the version and unresolves.
	versionBefore := registry.PoolVersion()
	changed, err = registry.SetObserved("edge-1", "")
	if err != nil || !changed {
		t.Fatalf("SetObserved(clear) = %v, %v, want true, nil", changed, err)
	}
	if registry.PoolVersion() != versionBefore+1 {
		t.Fatalf("PoolVersion() = %d, want %d", registry.PoolVersion(), versionBefore+1)
	}
	if _, _, ok := registry.AddressSourceForFamily("edge-1", FamilyAuto); ok {
		t.Fatal("AddressSourceForFamily() ok = true after clear, want false")
	}
}

func TestSetProbedSemantics(t *testing.T) {
	registry, path := openTestRegistry(t)

	if _, err := registry.SetProbed("bad agent", []string{"1.2.3.4"}, nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("SetProbed() error = %v, want ErrInvalidName", err)
	}
	if _, err := registry.SetProbed("edge-1", []string{"2001:db8::1"}, nil); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("SetProbed() v6 in v4 list error = %v, want ErrInvalidAddress", err)
	}
	if _, err := registry.SetProbed("edge-1", nil, []string{"1.2.3.4"}); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("SetProbed() v4 in v6 list error = %v, want ErrInvalidAddress", err)
	}
	tooMany := make([]string, MaxAddressesPerFamily+1)
	for index := range tooMany {
		tooMany[index] = "192.0.2.1"
	}
	if _, err := registry.SetProbed("edge-1", tooMany, nil); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("SetProbed() too many error = %v, want ErrInvalidAddress", err)
	}
	if registry.PoolVersion() != 0 {
		t.Fatalf("PoolVersion() = %d after rejected calls, want 0", registry.PoolVersion())
	}

	changed, err := registry.SetProbed("edge-1", []string{"203.0.113.20"}, []string{"2001:db8::20"})
	if err != nil || !changed {
		t.Fatalf("SetProbed() = %v, %v, want true, nil", changed, err)
	}
	if registry.PoolVersion() != 1 {
		t.Fatalf("PoolVersion() = %d, want 1", registry.PoolVersion())
	}

	// Unchanged sets: no-op, no persist.
	infoBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	changed, err = registry.SetProbed("edge-1", []string{"203.0.113.20"}, []string{"2001:db8::20"})
	if err != nil || changed {
		t.Fatalf("SetProbed(same) = %v, %v, want false, nil", changed, err)
	}
	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		t.Fatal("SetProbed() with unchanged sets persisted; want no write")
	}

	// No record and empty sets: no-op.
	changed, err = registry.SetProbed("edge-2", nil, nil)
	if err != nil || changed {
		t.Fatalf("SetProbed(empty new agent) = %v, %v, want false, nil", changed, err)
	}

	// A newly reported routable family replaces its older probe fallback;
	// the other family's probe survives.
	if _, err := registry.SetReported("edge-1", []string{"203.0.113.10"}, nil); err != nil {
		t.Fatalf("SetReported() error = %v", err)
	}
	addr, source, ok := registry.AddressSourceForFamily("edge-1", FamilyIPv4)
	if !ok || addr != "203.0.113.10" || source != SourceReported {
		t.Fatalf("AddressSourceForFamily() = %q, %v, %v, want newly reported address", addr, source, ok)
	}

	reloaded := reopenTestRegistry(t, path)
	addr, source, ok = reloaded.AddressSourceForFamily("edge-1", FamilyIPv6)
	if !ok || addr != "2001:db8::20" || source != SourceProbed {
		t.Fatalf("reloaded AddressSourceForFamily(ipv6) = %q, %v, %v", addr, source, ok)
	}

	// A late probe report cannot displace a currently reported routable
	// address, including after persistence/reload.
	changed, err = reloaded.SetProbed(
		"edge-1",
		[]string{"203.0.113.30"},
		[]string{"2001:db8::20"},
	)
	if err != nil || changed {
		t.Fatalf("SetProbed(masked family) = %v, %v, want false, nil", changed, err)
	}
	addr, source, ok = reloaded.AddressSourceForFamily("edge-1", FamilyIPv4)
	if !ok || addr != "203.0.113.10" || source != SourceReported {
		t.Fatalf("AddressSourceForFamily() = %q, %v, %v after late probe", addr, source, ok)
	}
}

func TestPersistFailureRollsBackObservedAndProbed(t *testing.T) {
	registry, path := openTestRegistry(t)
	if _, err := registry.SetObserved("edge-1", "198.51.100.7"); err != nil {
		t.Fatalf("SetObserved() error = %v", err)
	}
	if _, err := registry.SetProbed("edge-1", []string{"203.0.113.20"}, nil); err != nil {
		t.Fatalf("SetProbed() error = %v", err)
	}
	versionBefore := registry.PoolVersion()
	breakPersist(t, path)

	if _, err := registry.SetObserved("edge-1", "198.51.100.8"); err == nil {
		t.Fatal("SetObserved() error = nil, want persist failure")
	}
	addr, source, ok := registry.AddressSourceForFamily("edge-1", FamilyIPv4)
	if !ok || addr != "198.51.100.7" || source != SourceObserved {
		t.Fatalf("AddressSourceForFamily() = %q, %v, %v after failed persist, want rolled back", addr, source, ok)
	}
	if _, err := registry.SetProbed("edge-1", []string{"203.0.113.21"}, nil); err == nil {
		t.Fatal("SetProbed() error = nil, want persist failure")
	}
	addr, source, ok = registry.AddressSourceForFamily("edge-1", FamilyIPv4)
	if !ok || addr != "198.51.100.7" || source != SourceObserved {
		t.Fatalf("AddressSourceForFamily() = %q, %v, %v after failed probed persist, want rolled back", addr, source, ok)
	}
	if registry.PoolVersion() != versionBefore {
		t.Fatalf("PoolVersion() = %d, want rolled back %d", registry.PoolVersion(), versionBefore)
	}
}

func TestOpenV1DocumentWithoutNewFields(t *testing.T) {
	// A registry document written before observed/probed addresses existed:
	// version stays 1 and the absent optional fields decode as empty.
	path := filepath.Join(t.TempDir(), "outbound-pool.json")
	content := `{
  "version": 1,
  "pool_version": 3,
  "manual": [],
  "agents": {"edge-1": {"reported_v4": ["203.0.113.4"], "reported_v6": ["2001:db8::4"], "address_override": "", "updated_at": "2026-01-02T03:04:05Z"}},
  "rendered": {}
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	registry, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v, want v1 document without new fields to load", err)
	}
	addr, source, ok := registry.AddressSourceForFamily("edge-1", FamilyAuto)
	if !ok || addr != "203.0.113.4" || source != SourceReported {
		t.Fatalf("AddressSourceForFamily() = %q, %v, %v, want reported v4", addr, source, ok)
	}
}

func TestOpenRejectsInvalidNewFields(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"bad observed", `{"version":1,"pool_version":0,"manual":[],"agents":{"edge-1":{"reported_v4":[],"reported_v6":[],"observed_address":"nope","address_override":"","updated_at":"2026-01-02T03:04:05Z"}},"rendered":{}}`},
		{"bad probed v4", `{"version":1,"pool_version":0,"manual":[],"agents":{"edge-1":{"reported_v4":[],"reported_v6":[],"probed_v4":["2001:db8::1"],"address_override":"","updated_at":"2026-01-02T03:04:05Z"}},"rendered":{}}`},
		{"bad probed v6", `{"version":1,"pool_version":0,"manual":[],"agents":{"edge-1":{"reported_v4":[],"reported_v6":[],"probed_v6":["1.2.3.4"],"address_override":"","updated_at":"2026-01-02T03:04:05Z"}},"rendered":{}}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outbound-pool.json")
			if err := os.WriteFile(path, []byte(testCase.content), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if _, err := Open(path); err == nil {
				t.Fatalf("Open() error = nil, want error for %s", testCase.name)
			}
		})
	}
}

func TestRemoveAgentClearsNewFields(t *testing.T) {
	registry, path := openTestRegistry(t)
	seedHierarchyAgent(t, registry, "edge-1")
	if err := registry.RemoveAgent("edge-1"); err != nil {
		t.Fatalf("RemoveAgent() error = %v", err)
	}
	if _, _, ok := registry.AddressSourceForFamily("edge-1", FamilyAuto); ok {
		t.Fatal("AddressSourceForFamily() ok = true after removal")
	}
	reloaded := reopenTestRegistry(t, path)
	if _, _, ok := reloaded.AddressSourceForFamily("edge-1", FamilyAuto); ok {
		t.Fatal("reloaded AddressSourceForFamily() ok = true after removal")
	}
}
