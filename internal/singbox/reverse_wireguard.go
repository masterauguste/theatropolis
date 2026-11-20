package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func (m *Manager) ReverseWireGuardSupported() bool {
	ctx, cancel := context.WithTimeout(context.Background(), executableCheckTimeout)
	defer cancel()
	output := newLimitedBuffer(DefaultMaxDiagnosticBytes)
	command := exec.CommandContext(ctx, m.binaryPath, "version")
	command.Stdout, command.Stderr = output, output
	return command.Run() == nil && versionOutputHasTag(output.String(), "with_wireguard") && versionOutputHasTag(output.String(), "with_gvisor")
}

// CheckReverseTunnels runs only after the fleet has installed both sides. It
// authenticates to each child SOCKS service through a generated loopback bridge
// and the real WireGuard endpoint, without needing a public test destination.
func (m *Manager) CheckReverseTunnels(ctx context.Context, expected []byte) error {
	config, exists, err := m.loadActiveConfig()
	if err != nil || !exists {
		return errors.New("reverse tunnel active profile is unavailable")
	}
	defer clear(config)
	variant, err := BuildManagedUserAuthorityVariant(config)
	if err != nil || !bytes.Equal(expected, variant.TopologySHA256[:]) {
		return errors.New("reverse tunnel profile changed")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := checkReverseTunnels(ctx, config); err != nil {
		return err
	}
	// Recheck after the network operation, including when a reconnect or update
	// changed the active transport during probing. User-only updates are safe.
	active, exists, err := m.loadActiveConfig()
	defer clear(active)
	if err != nil || !exists {
		return errors.New("reverse tunnel active profile is unavailable")
	}
	current, err := BuildManagedUserAuthorityVariant(active)
	if err != nil || !bytes.Equal(expected, current.TopologySHA256[:]) {
		return errors.New("reverse tunnel profile changed")
	}
	return nil
}

func checkReverseTunnels(ctx context.Context, config []byte) error {
	var document struct {
		Inbounds []struct {
			Type, Tag, Listen string
			Port              int `json:"listen_port"`
		} `json:"inbounds"`
		Outbounds []struct{ Type, Tag, Username, Password, Detour string } `json:"outbounds"`
	}
	if json.Unmarshal(config, &document) != nil {
		return errors.New("invalid reverse tunnel configuration")
	}
	credentials := map[string][2]string{}
	for _, out := range document.Outbounds {
		if out.Type == "socks" && strings.HasPrefix(out.Tag, "tp-out-") && strings.HasPrefix(out.Detour, "tp-wg-parent-") {
			credentials[strings.TrimPrefix(out.Tag, "tp-out-")] = [2]string{out.Username, out.Password}
		}
	}
	for _, inbound := range document.Inbounds {
		if !strings.HasPrefix(inbound.Tag, "tp-wg-probe-") {
			continue
		}
		credentials, exists := credentials[strings.TrimPrefix(inbound.Tag, "tp-wg-probe-")]
		if !exists || inbound.Type != "direct" || inbound.Listen != "::1" || inbound.Port < 1024 || inbound.Port > 65535 {
			return errors.New("invalid reverse readiness bridge")
		}
		for {
			probeCtx, cancel := context.WithTimeout(ctx, time.Second)
			err := probeReverseSOCKS(probeCtx, net.JoinHostPort(inbound.Listen, strconv.Itoa(inbound.Port)), credentials[0], credentials[1])
			cancel()
			if err == nil {
				break
			}
			timer := time.NewTimer(150 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return errors.New("reverse WireGuard tunnel is not ready; check parent UDP reachability")
			case <-timer.C:
			}
		}
	}
	return nil
}

func probeReverseSOCKS(ctx context.Context, address, username, password string) error {
	if len(username) < 1 || len(username) > 255 || len(password) < 1 || len(password) > 255 {
		return errors.New("invalid SOCKS credentials")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, []byte{5, 2}) {
		return errors.New("SOCKS authentication method rejected")
	}
	auth := append([]byte{1, byte(len(username))}, []byte(username)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)
	if _, err := conn.Write(auth); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, []byte{1, 0}) {
		return errors.New("SOCKS authentication rejected")
	}
	return nil
}
