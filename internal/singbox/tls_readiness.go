package singbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/quic-go"
)

const tlsReadinessTimeout = 60 * time.Second

type tlsReadinessTarget struct {
	protocol, address, obfsType, obfsSecret string
	config                                  *tls.Config
}

// readinessTargets uses the local listener address, never public DNS, to
// avoid NAT hairpin requirements. SNI and certificate verification still use
// the configured certificate identity.
func readinessTargets(config []byte, stateDirectory string) ([]tlsReadinessTarget, error) {
	var document struct {
		Inbounds []struct {
			Type   string `json:"type"`
			Listen string `json:"listen"`
			Port   uint16 `json:"listen_port"`
			TLS    struct {
				Enabled         bool            `json:"enabled"`
				ServerName      string          `json:"server_name"`
				Provider        string          `json:"certificate_provider"`
				CertificatePath string          `json:"certificate_path"`
				Certificate     json.RawMessage `json:"certificate"`
				ALPN            []string        `json:"alpn"`
			} `json:"tls"`
			Obfs struct {
				Type     string `json:"type"`
				Password string `json:"password"`
			} `json:"obfs"`
		} `json:"inbounds"`
		Providers []struct {
			Tag    string   `json:"tag"`
			Domain []string `json:"domain"`
		} `json:"certificate_providers"`
	}
	if err := json.Unmarshal(config, &document); err != nil {
		return nil, errors.New("TLS readiness: invalid configuration")
	}
	var targets []tlsReadinessTarget
	for index, inbound := range document.Inbounds {
		if (inbound.Type != "anytls" && inbound.Type != "hysteria2") || !inbound.TLS.Enabled {
			continue
		}
		address := inbound.Listen
		if address == "" || address == "0.0.0.0" {
			address = "127.0.0.1"
		}
		if address == "::" {
			address = "::1"
		}
		if _, err := netip.ParseAddr(address); err != nil || inbound.Port == 0 {
			return nil, fmt.Errorf("TLS readiness: inbound %d has no probeable local socket", index+1)
		}
		names := []string{inbound.TLS.ServerName}
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: inbound.TLS.ALPN}
		if inbound.TLS.Provider != "" {
			for _, provider := range document.Providers {
				if provider.Tag == inbound.TLS.Provider && len(provider.Domain) > 0 {
					names = append([]string(nil), provider.Domain...)
					if inbound.TLS.ServerName != "" {
						names = append(names, inbound.TLS.ServerName)
					}
				}
			}
			if names[0] == "" {
				return nil, errors.New("TLS readiness: certificate provider has no verifiable server identity")
			}
		} else {
			var certificatePEM []byte
			if inbound.TLS.CertificatePath != "" {
				path := inbound.TLS.CertificatePath
				if !filepath.IsAbs(path) {
					path = filepath.Join(stateDirectory, path)
				}
				var err error
				certificatePEM, err = readReadinessCertificate(path)
				if err != nil {
					return nil, errors.New("TLS readiness: configured certificate could not be read")
				}
			} else {
				var lines []string
				if err := json.Unmarshal(inbound.TLS.Certificate, &lines); err != nil {
					var single string
					if err := json.Unmarshal(inbound.TLS.Certificate, &single); err != nil {
						return nil, errors.New("TLS readiness: configured certificate is missing")
					}
					lines = []string{single}
				}
				certificatePEM = []byte(strings.Join(lines, "\n"))
			}
			block, _ := pem.Decode(certificatePEM)
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, errors.New("TLS readiness: configured certificate is invalid")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.New("TLS readiness: configured certificate is invalid")
			}
			tlsConfig.RootCAs = x509.NewCertPool()
			tlsConfig.RootCAs.AddCert(leaf)
			// Trust the explicitly configured certificate, including managed
			// self-signed certificates, without disabling TLS verification.
			tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, leaf.Raw) {
					return errors.New("listener is serving a different certificate")
				}
				return nil
			}
			if names[0] == "" {
				if len(leaf.DNSNames) > 0 {
					names[0] = leaf.DNSNames[0]
				} else if len(leaf.IPAddresses) > 0 {
					names[0] = leaf.IPAddresses[0].String()
				} else {
					return nil, errors.New("TLS readiness: configured certificate has no server identity")
				}
			}
		}
		if inbound.Type == "hysteria2" {
			tlsConfig.MinVersion = tls.VersionTLS13
			if len(tlsConfig.NextProtos) == 0 {
				tlsConfig.NextProtos = []string{"h3"}
			}
		}
		for _, name := range names {
			probeTLS := tlsConfig.Clone()
			// A wildcard is a certificate pattern, not an SNI hostname.
			probeTLS.ServerName = strings.Replace(name, "*.", "theatropolis-readiness.", 1)
			targets = append(targets, tlsReadinessTarget{
				protocol: inbound.Type, address: net.JoinHostPort(address, strconv.Itoa(int(inbound.Port))),
				obfsType: inbound.Obfs.Type, obfsSecret: inbound.Obfs.Password, config: probeTLS,
			})
		}
	}
	return targets, nil
}

func probeTLSReadiness(ctx context.Context, target tlsReadinessTarget) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if target.protocol == "anytls" {
		connection, err := (&tls.Dialer{Config: target.config}).DialContext(ctx, "tcp", target.address)
		if err != nil {
			return err
		}
		_ = connection.Close()
		return nil
	}
	remote, err := net.ResolveUDPAddr("udp", target.address)
	if err != nil {
		return err
	}
	network := "udp6"
	if remote.IP.To4() != nil {
		network = "udp4"
	}
	packet, err := net.ListenPacket(network, ":0")
	if err != nil {
		return err
	}
	defer packet.Close()
	var wrapped net.PacketConn = packet
	switch target.obfsType {
	case "":
	case "salamander":
		wrapped, err = obfs.WrapPacketConnSalamander(packet, []byte(target.obfsSecret))
	case "gecko":
		wrapped, err = obfs.WrapPacketConnGecko(packet, obfs.GeckoOptions{Password: []byte(target.obfsSecret)})
	default:
		return errors.New("unsupported Hysteria2 obfuscation")
	}
	if err != nil {
		return err
	}
	connection, err := quic.Dial(ctx, wrapped, remote, target.config, &quic.Config{HandshakeIdleTimeout: 2 * time.Second})
	if err != nil {
		return err
	}
	_ = connection.CloseWithError(0, "readiness check complete")
	return nil
}

func waitTLSReadiness(ctx context.Context, targets []tlsReadinessTarget, ownsListener func(tlsReadinessTarget) bool) error {
	// Retain successful probes so multiple listeners share one overall
	// deadline rather than each consuming a full certificate issuance window.
	for len(targets) > 0 {
		// Bound simultaneous handshakes without letting a slow first listener
		// prevent other certificate identities from being checked.
		type outcome struct {
			target tlsReadinessTarget
			ready  bool
		}
		jobs := make(chan tlsReadinessTarget)
		results := make(chan outcome, len(targets))
		for range min(8, len(targets)) {
			go func() {
				for target := range jobs {
					ready := probeTLSReadiness(ctx, target) == nil
					if ready && ownsListener != nil {
						ready = ownsListener(target)
					}
					results <- outcome{target, ready}
				}
			}()
		}
		go func(batch []tlsReadinessTarget) {
			defer close(jobs)
			for _, target := range batch {
				select {
				case jobs <- target:
				case <-ctx.Done():
					return
				}
			}
		}(targets)
		remaining := make([]tlsReadinessTarget, 0, len(targets))
		for range targets {
			select {
			case result := <-results:
				if !result.ready {
					remaining = append(remaining, result.target)
				}
			case <-ctx.Done():
				// Never copy raw TLS/network errors: those can contain configured
				// hostnames, certificate contents, or obfuscation material.
				return errors.New("TLS readiness timed out: listeners did not complete verified handshakes; check certificate issuance, validity, and listener settings")
			}
		}
		targets = remaining
		if len(targets) == 0 {
			return nil
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
		}
	}
	return nil
}

func readReadinessCertificate(path string) ([]byte, error) {
	// Do not let a certificate path block startup on a FIFO or consume
	// unbounded memory. Managed certificates are private regular files.
	if exists, err := regularFileExists(path); err != nil || !exists {
		return nil, errors.New("certificate path is missing or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	certificate, err := io.ReadAll(io.LimitReader(file, DefaultMaxConfigBytes+1))
	if err != nil || len(certificate) > DefaultMaxConfigBytes {
		return nil, errors.New("certificate could not be read within the size limit")
	}
	return certificate, nil
}
