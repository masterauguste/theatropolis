package singbox

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/quic-go"
)

func readinessCertificate(t *testing.T, expired bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(time.Hour)
	if expired {
		notAfter = time.Now().Add(-time.Minute)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"ready.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func readinessConfig(t *testing.T, protocol, address string, certificate tls.Certificate) []byte {
	t.Helper()
	socket, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{
		"type": protocol, "listen": socket.IP.String(), "listen_port": socket.Port,
		"tls": map[string]any{
			"enabled": true, "server_name": "ready.test",
			"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})),
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func readinessTLSServer(t *testing.T, config *tls.Config) string {
	t.Helper()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
				_ = connection.(*tls.Conn).Handshake()
			}()
		}
	}()
	return listener.Addr().String()
}

func TestTLSReadinessVerifiesCertificateAndIdentity(t *testing.T) {
	for _, scenario := range []string{"valid", "expired", "wrong-host", "wrong-certificate", "untrusted-acme"} {
		t.Run(scenario, func(t *testing.T) {
			certificate := readinessCertificate(t, scenario == "expired")
			servedCertificate := certificate
			if scenario == "wrong-certificate" {
				servedCertificate = readinessCertificate(t, false)
			}
			address := readinessTLSServer(t, &tls.Config{Certificates: []tls.Certificate{servedCertificate}})
			targets, err := readinessTargets(readinessConfig(t, "anytls", address, certificate), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "wrong-host" {
				targets[0].config.ServerName = "wrong.test"
			}
			if scenario == "untrusted-acme" {
				// ACME providers must use system trust, never a local pin or
				// InsecureSkipVerify, even if the listener completes TLS.
				config := strings.Replace(string(readinessConfig(t, "anytls", address, certificate)), `"server_name":"ready.test"`, `"server_name":"ready.test","certificate_provider":"acme"`, 1)
				targets, err = readinessTargets([]byte(config), t.TempDir())
				if err != nil || targets[0].config.RootCAs != nil || targets[0].config.InsecureSkipVerify {
					t.Fatalf("ACME trust configuration: %v, %v", targets, err)
				}
			}
			err = probeTLSReadiness(context.Background(), targets[0])
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("probe error = %v", err)
			}
		})
	}
}

func TestTLSReadinessHysteria2VerifiedQUIC(t *testing.T) {
	for _, mode := range []string{"", "salamander", "gecko"} {
		t.Run("obfs-"+mode, func(t *testing.T) {
			certificate := readinessCertificate(t, false)
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			wrapped := packet
			switch mode {
			case "salamander":
				wrapped, err = obfs.WrapPacketConnSalamander(packet, []byte("readiness-secret"))
			case "gecko":
				wrapped, err = obfs.WrapPacketConnGecko(packet, obfs.GeckoOptions{Password: []byte("readiness-secret")})
			}
			if err != nil {
				t.Fatal(err)
			}
			listener, err := quic.Listen(wrapped, &tls.Config{
				Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			targets, err := readinessTargets(readinessConfig(t, "hysteria2", packet.LocalAddr().String(), certificate), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			target := targets[0]
			target.obfsType, target.obfsSecret = mode, "readiness-secret"
			if err := probeTLSReadiness(context.Background(), target); err != nil {
				t.Fatalf("verified QUIC: %v", err)
			}
			target.config.ServerName = "wrong.test"
			if err := probeTLSReadiness(context.Background(), target); err == nil {
				t.Fatal("QUIC accepted a certificate with the wrong identity")
			}
		})
	}
}

func TestTLSReadinessTargetsLocalSocketsAndProviderDomains(t *testing.T) {
	config := []byte(`{"inbounds":[
		{"type":"shadowsocks","listen_port":80},
		{"type":"anytls","listen":"0.0.0.0","listen_port":443,"tls":{"enabled":true,"certificate_provider":"acme"}},
		{"type":"hysteria2","listen":"::","listen_port":8443,"tls":{"enabled":true,"certificate_provider":"acme"},"obfs":{"type":"gecko","password":"secret"}}
	],"certificate_providers":[{"tag":"acme","domain":["ready.test","*.other.test"]}]}`)
	targets, err := readinessTargets(config, t.TempDir())
	if err != nil || len(targets) != 4 {
		t.Fatalf("targets = %v, %v", targets, err)
	}
	if targets[0].address != "127.0.0.1:443" || targets[2].address != "[::1]:8443" ||
		targets[1].config.ServerName != "theatropolis-readiness.other.test" ||
		targets[2].obfsType != "gecko" || targets[2].obfsSecret != "secret" {
		t.Fatal("wrong local address, certificate identity, or obfuscation")
	}
	for _, target := range targets {
		if target.config.RootCAs != nil || target.config.InsecureSkipVerify {
			t.Fatal("ACME certificate verification disabled")
		}
	}
}

func TestTLSReadinessRejectsAnotherProcessListener(t *testing.T) {
	certificate := readinessCertificate(t, false)
	address := readinessTLSServer(t, &tls.Config{Certificates: []tls.Certificate{certificate}})
	targets, err := readinessTargets(readinessConfig(t, "anytls", address, certificate), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var checked atomic.Bool
	err = waitTLSReadiness(ctx, targets, func(tlsReadinessTarget) bool { checked.Store(true); return false })
	if err == nil || !checked.Load() {
		t.Fatalf("unowned listener check = %v", err)
	}
}

func TestTLSReadinessRequiresEveryListener(t *testing.T) {
	certificate := readinessCertificate(t, false)
	address := readinessTLSServer(t, &tls.Config{Certificates: []tls.Certificate{certificate}})
	targets, err := readinessTargets(readinessConfig(t, "anytls", address, certificate), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bad := targets[0]
	bad.config = bad.config.Clone()
	bad.config.ServerName = "wrong.test"
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := waitTLSReadiness(ctx, append(targets, bad), nil); err == nil {
		t.Fatal("one ready listener hid another failed listener")
	}
}

func TestTLSReadinessLoadsManagedCertificatePath(t *testing.T) {
	directory := t.TempDir()
	config := []byte(`{"inbounds":[{"type":"anytls","listen_port":443,"tls":{
		"enabled":true,"server_name":"ready.test",
		"certificate_path":"certificates/theatropolis-self-signed/test/certificate.pem",
		"key_path":"certificates/theatropolis-self-signed/test/private-key.pem"
	}}]}`)
	if err := prepareManagedSelfSignedCertificates(config, directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	targets, err := readinessTargets(config, directory)
	if err != nil || len(targets) != 1 || targets[0].config.RootCAs == nil || targets[0].config.InsecureSkipVerify {
		t.Fatalf("managed certificate readiness = %v, %v", targets, err)
	}
}

func TestManagerWaitsForUsableCertificate(t *testing.T) {
	certificate := readinessCertificate(t, false)
	var ready atomic.Bool
	attempted := make(chan struct{}, 1)
	address := readinessTLSServer(t, &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		select {
		case attempted <- struct{}{}:
		default:
		}
		if !ready.Load() {
			return nil, errors.New("certificate issuance pending")
		}
		return &certificate, nil
	}})
	factory := &fakeProcessFactory{}
	manager := newTestManager(t, factory, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer stopTestManager(t, manager)
	config := readinessConfig(t, "anytls", address, certificate)
	digest := sha256.Sum256(config)
	results := make(chan ApplyResult, 1)
	go func() { result, _ := manager.Apply(ctx, config, digest[:]); results <- result }()
	select {
	case <-attempted:
	case <-ctx.Done():
		t.Fatal("listener was not probed")
	}
	select {
	case result := <-results:
		t.Fatalf("reported before certificate was ready: %+v", result)
	default:
	}
	ready.Store(true)
	select {
	case result := <-results:
		if result.Status != ApplyStatusApplied || !result.Active {
			t.Fatalf("Apply = %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("ready listener was not activated")
	}
}

func TestManagerTLSReadinessFailureRollsBack(t *testing.T) {
	for _, scenario := range []string{"no-certificate", "child-exits"} {
		t.Run(scenario, func(t *testing.T) {
			certificate := readinessCertificate(t, false)
			address := readinessTLSServer(t, &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, errors.New("issuance failed: secret diagnostic")
			}})
			factory := &fakeProcessFactory{}
			if scenario == "child-exits" {
				factory.plans = []fakeProcessPlan{{}, {autoExit: true, exitAfter: 60 * time.Millisecond}, {}}
			}
			manager := newTestManager(t, factory, nil)
			previous := []byte(`{"inbounds":[]}`)
			writeActiveConfig(t, manager, previous)
			if _, err := manager.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer stopTestManager(t, manager)
			ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
			defer cancel()
			config := readinessConfig(t, "anytls", address, certificate)
			digest := sha256.Sum256(config)
			result, err := manager.Apply(ctx, config, digest[:])
			if err != nil || result.Status != ApplyStatusActivationFailed || !result.RolledBack || !result.Active {
				t.Fatalf("Apply = %+v, %v", result, err)
			}
			if scenario == "no-certificate" && !strings.Contains(result.Diagnostic, "TLS readiness") {
				t.Fatalf("missing actionable diagnostic: %s", result.Diagnostic)
			}
			if strings.Contains(result.Diagnostic, "secret") {
				t.Fatal("leaked probe diagnostic")
			}
			persisted, err := os.ReadFile(manager.ActiveConfigPath())
			if err != nil || string(persisted) != string(previous) {
				t.Fatalf("rollback = %s, %v", persisted, err)
			}
			processes, _ := factory.snapshot()
			if len(processes) != 3 || (scenario == "no-certificate" && processes[1].signalCount() == 0) {
				t.Fatal("candidate was not stopped and previous profile restarted")
			}
		})
	}
}
