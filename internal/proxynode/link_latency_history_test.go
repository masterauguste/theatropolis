package proxynode

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLinkLatencyHistoryAggregatesAndPersistsPhysicalTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	targetID := "0123456789abcdef0123456789abcdef"
	start := time.Date(2026, 8, 31, 10, 1, 0, 0, time.UTC)
	for index, observation := range []LinkLatencyObservation{
		{TargetID: targetID, Responded: true, Connected: true, Duration: 20 * time.Millisecond},
		{TargetID: targetID, Responded: true, Connected: false, Duration: 40 * time.Millisecond},
		{TargetID: targetID},
	} {
		if err := store.RecordLinkLatencySnapshot("edge-a", start.Add(time.Duration(index)*time.Minute), []LinkLatencyObservation{observation}); err != nil {
			t.Fatal(err)
		}
	}
	buckets, err := store.LinkLatencyHistory("edge-a", targetID, start.Add(-time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 1 || buckets[0].Samples != 3 || buckets[0].Responses != 2 ||
		buckets[0].Connections != 1 || buckets[0].DurationSum != 60*time.Millisecond ||
		buckets[0].DurationMin != 20*time.Millisecond || buckets[0].DurationMax != 40*time.Millisecond {
		t.Fatalf("history = %#v", buckets)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, testBuild())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	buckets, err = reopened.LinkLatencyHistory("edge-a", targetID, start.Add(-time.Minute), 15*time.Minute)
	if err != nil || len(buckets) != 1 || buckets[0].Samples != 3 {
		t.Fatalf("reopened history = %#v, %v", buckets, err)
	}
	// An empty snapshot is what a parent Agent reports after its final Link is
	// removed. It must keep recent shared history, then prune it by retention
	// without requiring that logical Link to still exist.
	if err := reopened.RecordLinkLatencySnapshot("edge-a", start.Add(29*24*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	buckets, err = reopened.LinkLatencyHistory("edge-a", targetID, start.Add(-time.Minute), 15*time.Minute)
	if err != nil || len(buckets) != 1 {
		t.Fatalf("history was deleted with Link absence = %#v, %v", buckets, err)
	}
	if err := reopened.RecordLinkLatencySnapshot("edge-a", start.Add(31*24*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	buckets, err = reopened.LinkLatencyHistory("edge-a", targetID, start.Add(-time.Minute), 15*time.Minute)
	if err != nil || len(buckets) != 0 {
		t.Fatalf("expired history = %#v, %v", buckets, err)
	}
}
