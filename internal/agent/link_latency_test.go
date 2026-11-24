package agent

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

type staticLinkLatencyTargets []singbox.LinkLatencyTarget

func (s staticLinkLatencyTargets) LinkLatencyTargets() ([]singbox.LinkLatencyTarget, error) {
	return append([]singbox.LinkLatencyTarget(nil), s...), nil
}

func TestCollectLinkLatencyDeduplicatesPhysicalDestinationOverTCP(t *testing.T) {
	targets := staticLinkLatencyTargets{
		{OutboundTag: "tp-out-one", Address: "203.0.113.20", Port: singbox.PeerLatencyListenPort, Transport: "tcp"},
		{OutboundTag: "tp-out-two", Address: "203.0.113.20", Port: singbox.PeerLatencyListenPort, Transport: "tcp"},
		{OutboundTag: "tp-out-three", Address: "203.0.113.20", Port: singbox.PeerLatencyListenPort, Transport: "tcp"},
		{OutboundTag: "tp-out-four", Address: "2001:db8::20", Port: singbox.PeerLatencyListenPort, Transport: "tcp"},
	}
	type call struct {
		address   string
		port      uint16
		probeType controlv1.LinkLatencyProbeType
	}
	var mutex sync.Mutex
	var calls []call
	probe := func(_ context.Context, target linkLatencyProbeTarget) (controlv1.LinkLatencyStatus, time.Duration) {
		mutex.Lock()
		calls = append(calls, call{address: target.address, port: target.port, probeType: target.probeType})
		mutex.Unlock()
		return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REACHABLE, 12 * time.Millisecond
	}
	result := collectLinkLatencyWithProbe(context.Background(), targets, time.Unix(1_800_000_000, 0), probe)
	if result.err != nil {
		t.Fatal(result.err)
	}
	if len(calls) != 2 || len(result.report.GetSamples()) != 2 {
		t.Fatalf("calls = %#v; samples = %#v", calls, result.report.GetSamples())
	}
	for _, candidate := range calls {
		if candidate.probeType != controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP || candidate.port != singbox.PeerLatencyListenPort {
			t.Fatalf("call = %#v, want TCP port %d", candidate, singbox.PeerLatencyListenPort)
		}
	}
	for _, sample := range result.report.GetSamples() {
		if sample.GetTargetId() == "" || sample.GetProbeType() != controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP {
			t.Fatalf("sample = %#v", sample)
		}
		if slices.Contains(sample.GetOutboundTags(), "tp-out-one") && len(sample.GetOutboundTags()) != 3 {
			t.Fatalf("shared physical sample tags = %#v, want 3 tags", sample.GetOutboundTags())
		}
	}
}
