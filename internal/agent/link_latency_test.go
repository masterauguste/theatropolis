package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/quic-go"
	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

type staticLinkLatencyTargets []singbox.LinkLatencyTarget

func (s staticLinkLatencyTargets) LinkLatencyTargets() ([]singbox.LinkLatencyTarget, error) {
	return append([]singbox.LinkLatencyTarget(nil), s...), nil
}

func TestProbeQUICCompletesHysteriaTransportHandshake(t *testing.T) {
	certificate := testQUICCertificate(t)
	for _, testCase := range []struct {
		name, obfsType, secret string
	}{
		{name: "plain"},
		{name: "salamander", obfsType: "salamander", secret: "salamander-secret"},
		{name: "gecko", obfsType: "gecko", secret: "gecko-secret"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			var packetConn net.PacketConn = udpConn
			switch testCase.obfsType {
			case "salamander":
				packetConn, err = obfs.WrapPacketConnSalamander(udpConn, []byte(testCase.secret))
			case "gecko":
				packetConn, err = obfs.WrapPacketConnGecko(udpConn, obfs.GeckoOptions{Password: []byte(testCase.secret)})
			}
			if err != nil {
				_ = udpConn.Close()
				t.Fatal(err)
			}
			listener, err := quic.Listen(packetConn, &tls.Config{
				Certificates: []tls.Certificate{certificate},
				NextProtos:   []string{"h3"},
				MinVersion:   tls.VersionTLS13,
			}, &quic.Config{HandshakeIdleTimeout: defaultLinkLatencyTimeout})
			if err != nil {
				_ = packetConn.Close()
				t.Fatal(err)
			}
			defer listener.Close()
			serverContext, cancelServer := context.WithTimeout(context.Background(), defaultLinkLatencyTimeout)
			defer cancelServer()
			go func() {
				connection, acceptErr := listener.Accept(serverContext)
				if acceptErr == nil {
					_ = connection.CloseWithError(0, "test complete")
				}
			}()

			address := udpConn.LocalAddr().(*net.UDPAddr)
			status, _ := probeQUIC(context.Background(), linkLatencyProbeTarget{
				address: "127.0.0.1", port: uint16(address.Port),
				probeType:  controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_QUIC,
				serverName: "probe.test", obfsType: testCase.obfsType, obfsSecret: testCase.secret,
			})
			if status != controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REACHABLE {
				t.Fatalf("status = %s, want reachable", status)
			}
		})
	}
}

func testQUICCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "probe.test"},
		DNSNames:     []string{"probe.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}

func TestCollectLinkLatencyDeduplicatesPhysicalDestination(t *testing.T) {
	targets := staticLinkLatencyTargets{
		{OutboundTag: "tp-out-one", Address: "203.0.113.20", Port: 443, Transport: "quic"},
		{OutboundTag: "tp-out-quic-shared", Address: "203.0.113.20", Port: 8443, Transport: "quic"},
		{OutboundTag: "tp-out-two", Address: "203.0.113.20", Port: 20048, Transport: "tcp"},
		{OutboundTag: "tp-out-three", Address: "203.0.113.20", Port: 8443, Transport: "tcp"},
		{OutboundTag: "tp-out-four", Address: "2001:db8::20", Port: 443, Transport: "tcp"},
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
	if len(calls) != 3 || len(result.report.GetSamples()) != 3 {
		t.Fatalf("calls = %#v; samples = %#v", calls, result.report.GetSamples())
	}
	var ipv4Call call
	for _, candidate := range calls {
		if candidate.address == "203.0.113.20" && candidate.probeType == controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP {
			ipv4Call = candidate
		}
	}
	if ipv4Call.port != 8443 {
		t.Fatalf("IPv4 representative port = %d, want lowest TCP listener 8443", ipv4Call.port)
	}
	for _, sample := range result.report.GetSamples() {
		if sample.GetTargetId() == "" {
			t.Fatal("physical sample has no stable target ID")
		}
		if slices.Contains(sample.GetOutboundTags(), "tp-out-one") && len(sample.GetOutboundTags()) != 2 {
			t.Fatalf("shared physical sample tags = %#v", sample.GetOutboundTags())
		}
	}
}
