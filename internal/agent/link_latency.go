package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/quic-go"
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
	address    string
	port       uint16
	probeType  controlv1.LinkLatencyProbeType
	serverName string
	obfsType   string
	obfsSecret string
}

func collectLinkLatency(ctx context.Context, provider linkLatencyTargetProvider, now time.Time) linkLatencyCollectionResult {
	return collectLinkLatencyWithProbe(ctx, provider, now, probeLinkPath)
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
		if target.Transport == "quic" {
			probeType = controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_QUIC
		}
		pathKey := target.Transport + "\x00" + target.Address
		physical := byPath[pathKey]
		if physical == nil {
			physical = &physicalTarget{linkLatencyProbeTarget: linkLatencyProbeTarget{
				address: target.Address, port: target.Port, probeType: probeType,
				serverName: target.ServerName, obfsType: target.ObfsType, obfsSecret: target.ObfsSecret,
			}}
			byPath[pathKey] = physical
		}
		physical.tags = append(physical.tags, target.OutboundTag)
		// Keep one deterministic representative per destination and transport.
		// Every logical Link using that physical path receives the same sample.
		if target.Port < physical.port {
			physical.port = target.Port
			physical.serverName = target.ServerName
			physical.obfsType = target.ObfsType
			physical.obfsSecret = target.ObfsSecret
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

func probeLinkPath(ctx context.Context, target linkLatencyProbeTarget) (controlv1.LinkLatencyStatus, time.Duration) {
	if target.probeType == controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_QUIC {
		return probeQUIC(ctx, target)
	}
	return probeTCPPath(ctx, target)
}

func probeQUIC(ctx context.Context, target linkLatencyProbeTarget) (controlv1.LinkLatencyStatus, time.Duration) {
	probeContext, cancel := context.WithTimeout(ctx, defaultLinkLatencyTimeout)
	defer cancel()
	address, err := netip.ParseAddr(target.address)
	if err != nil {
		return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_UNREACHABLE, 0
	}
	network := "udp6"
	listenAddress := &net.UDPAddr{IP: net.IPv6unspecified}
	if address.Is4() {
		network = "udp4"
		listenAddress.IP = net.IPv4zero
	}
	packetConn, err := net.ListenUDP(network, listenAddress)
	if err != nil {
		return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_UNREACHABLE, 0
	}
	defer packetConn.Close()
	var probeConn net.PacketConn = packetConn
	switch target.obfsType {
	case "":
	case "salamander":
		probeConn, err = obfs.WrapPacketConnSalamander(packetConn, []byte(target.obfsSecret))
		if err != nil {
			return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_UNREACHABLE, 0
		}
	case "gecko":
		probeConn, err = obfs.WrapPacketConnGecko(packetConn, obfs.GeckoOptions{
			Password: []byte(target.obfsSecret),
		})
		if err != nil {
			return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_UNREACHABLE, 0
		}
	default:
		return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_UNREACHABLE, 0
	}
	started := time.Now()
	connection, err := quic.Dial(
		probeContext,
		probeConn,
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, target.port)),
		&tls.Config{ // #nosec G402 -- availability probe; Link TLS validation remains unchanged.
			ServerName: target.serverName, InsecureSkipVerify: true, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
		},
		&quic.Config{HandshakeIdleTimeout: defaultLinkLatencyTimeout, MaxIdleTimeout: defaultLinkLatencyTimeout},
	)
	duration := time.Since(started)
	if err != nil {
		return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_UNREACHABLE, duration
	}
	_ = connection.CloseWithError(0, "probe complete")
	return controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REACHABLE, duration
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
		!globallyRoutable(address) || command.GetPort() < 1 || command.GetPort() > 65535 ||
		len(command.GetServerName()) > 253 || len(command.GetObfsType()) > 32 || len(command.GetObfsSecret()) > 1024 ||
		strings.ContainsRune(command.GetServerName(), '\x00') || strings.ContainsRune(command.GetObfsType(), '\x00') {
		report.Status = controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_UNREACHABLE
		select {
		case output <- linkLatencyProbeResult{report: report}:
		case <-ctx.Done():
		}
		return
	}
	target := linkLatencyProbeTarget{
		address: address.String(), port: uint16(command.GetPort()), probeType: command.GetProbeType(),
		serverName: strings.TrimSpace(command.GetServerName()), obfsType: strings.TrimSpace(command.GetObfsType()),
		obfsSecret: command.GetObfsSecret(),
	}
	if target.probeType != controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP &&
		target.probeType != controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_QUIC {
		target.probeType = controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP
	}
	status, duration := probeLinkPath(ctx, target)
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
