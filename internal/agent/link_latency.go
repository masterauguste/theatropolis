package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

const (
	defaultLinkLatencyPeriod  = 30 * time.Second
	defaultLinkLatencyTimeout = 3 * time.Second
	maxLinkLatencyEndpoints   = 256
	maxLinkLatencyConcurrency = 32
)

type linkLatencyTargetProvider interface {
	LinkLatencyTargets() ([]singbox.LinkLatencyTarget, error)
}

type linkLatencyCollectionResult struct {
	report *controlv1.LinkLatencyReport
	err    error
}

type linkLatencyProbeResult struct {
	report *controlv1.LinkLatencyProbeReport
}

type linkLatencyProbeTarget struct {
	address   string
	port      uint16
	probeType controlv1.LinkLatencyProbeType
}

func collectLinkLatency(ctx context.Context, provider linkLatencyTargetProvider, now time.Time) linkLatencyCollectionResult {
	return collectLinkLatencyWithProbe(ctx, provider, now, probeTCPPath)
}

func collectLinkLatencyWithProbe(
	ctx context.Context,
	provider linkLatencyTargetProvider,
	now time.Time,
	probe func(context.Context, linkLatencyProbeTarget) (controlv1.LinkLatencyStatus, time.Duration),
) linkLatencyCollectionResult {
	targets, err := provider.LinkLatencyTargets()
	if err != nil {
		return linkLatencyCollectionResult{err: err}
	}
	if len(targets) == 0 {
		return linkLatencyCollectionResult{report: &controlv1.LinkLatencyReport{ObservedAtUnix: now.Unix()}}
	}
	type physicalTarget struct {
		linkLatencyProbeTarget
		tags []string
	}
	byPath := make(map[string]*physicalTarget)
	for _, target := range targets {
		probeType := controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP
		port := target.Port
		if port == 0 {
			port = singbox.PeerLatencyListenPort
		}
		pathKey := "tcp\x00" + target.Address
		physical := byPath[pathKey]
		if physical == nil {
			physical = &physicalTarget{linkLatencyProbeTarget: linkLatencyProbeTarget{
				address:   target.Address,
				port:      port,
				probeType: probeType,
			}}
			byPath[pathKey] = physical
		}
		physical.tags = append(physical.tags, target.OutboundTag)
		// Keep one deterministic representative per destination IP. Every
		// logical Link using that physical path receives the same TCP sample.
		if port < physical.port {
			physical.port = port
		}
	}
	if len(byPath) > maxLinkLatencyEndpoints {
		return linkLatencyCollectionResult{err: &linkLatencyLimitError{}}
	}
	type endpointResult struct {
		status   controlv1.LinkLatencyStatus
		duration time.Duration
	}
	results := make(map[string]endpointResult, len(byPath))
	var mu sync.Mutex
	semaphore := make(chan struct{}, maxLinkLatencyConcurrency)
	var group sync.WaitGroup
	for pathKey, target := range byPath {
		pathKey, target := pathKey, target
		group.Add(1)
		go func() {
			defer group.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}
			status, duration := probe(ctx, target.linkLatencyProbeTarget)
			mu.Lock()
			results[pathKey] = endpointResult{status: status, duration: duration}
			mu.Unlock()
		}()
	}
	group.Wait()
	report := &controlv1.LinkLatencyReport{ObservedAtUnix: now.Unix()}
	paths := make([]string, 0, len(byPath))
	for pathKey := range byPath {
		paths = append(paths, pathKey)
	}
	sort.Strings(paths)
	for _, pathKey := range paths {
		result, exists := results[pathKey]
		if !exists {
			continue
		}
		target := byPath[pathKey]
		tags := append([]string(nil), target.tags...)
		sort.Strings(tags)
		report.Samples = append(report.Samples, &controlv1.LinkLatencySample{
			OutboundTag:          tags[0],
			OutboundTags:         tags,
			TargetId:             linkLatencyTargetID(target.probeType, target.address),
			ProbeType:            target.probeType,
			Status:               result.status,
			DurationMilliseconds: uint64(result.duration.Milliseconds()),
		})
	}
	return linkLatencyCollectionResult{report: report}
}

func linkLatencyTargetID(probeType controlv1.LinkLatencyProbeType, address string) string {
	digest := sha256.Sum256([]byte(probeType.String() + "\x00" + address))
	return hex.EncodeToString(digest[:16])
}

func probeTCPPath(ctx context.Context, target linkLatencyProbeTarget) (controlv1.LinkLatencyStatus, time.Duration) {
	probeContext, cancel := context.WithTimeout(ctx, defaultLinkLatencyTimeout)
	defer cancel()
	started := time.Now()
	dialer := net.Dialer{}
	connection, dialErr := dialer.DialContext(
		probeContext,
		"tcp",
		net.JoinHostPort(target.address, strconv.Itoa(int(target.port))),
	)
	duration := time.Since(started)
	if dialErr == nil {
		_ = connection.Close()
		return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REACHABLE, duration
	}
	if errors.Is(dialErr, syscall.ECONNREFUSED) {
		return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REFUSED, duration
	}
	return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_UNREACHABLE, duration
}

func runLinkLatencyProbe(
	ctx context.Context,
	command *controlv1.LinkLatencyProbeCommand,
	output chan<- linkLatencyProbeResult,
) {
	report := &controlv1.LinkLatencyProbeReport{}
	if command != nil {
		report.RequestId = command.GetRequestId()
	}
	address := netip.Addr{}
	if command != nil {
		address, _ = netip.ParseAddr(command.GetAddress())
	}
	if command == nil || report.RequestId == "" || len(report.RequestId) > 128 ||
		!globallyRoutable(address) || command.GetPort() < 1 || command.GetPort() > 65535 {
		report.Status = controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_UNREACHABLE
		select {
		case output <- linkLatencyProbeResult{report: report}:
		case <-ctx.Done():
		}
		return
	}
	target := linkLatencyProbeTarget{
		address:   address.String(),
		port:      uint16(command.GetPort()),
		probeType: controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP,
	}
	status, duration := probeTCPPath(ctx, target)
	report.Status = status
	report.DurationMilliseconds = uint64(duration.Milliseconds())
	select {
	case output <- linkLatencyProbeResult{report: report}:
	case <-ctx.Done():
	}
}

type linkLatencyLimitError struct{}

func (*linkLatencyLimitError) Error() string {
	return "active configuration has too many Link latency endpoints"
}
