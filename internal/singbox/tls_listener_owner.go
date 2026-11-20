package singbox

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Linux is the deployment platform. Inspect the child's network namespace and
// open socket descriptors as the same unprivileged Agent user. A successful
// handshake with Caddy (or another process) must not pass sing-box readiness
// while its own startup is still blocked on certificate issuance.
func processOwnsTLSListener(procDirectory string, pid int, target tlsReadinessTarget) bool {
	address, err := netip.ParseAddrPort(target.address)
	if err != nil || pid <= 0 {
		return false
	}
	directory := filepath.Join(procDirectory, strconv.Itoa(pid))
	descriptors, err := os.ReadDir(filepath.Join(directory, "fd"))
	if err != nil {
		return false
	}
	owned := make(map[string]bool)
	for _, descriptor := range descriptors {
		link, err := os.Readlink(filepath.Join(directory, "fd", descriptor.Name()))
		if err == nil && strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			owned[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	if len(owned) == 0 {
		return false
	}
	network, state := "tcp", "0A" // TCP_LISTEN
	if target.protocol == "hysteria2" {
		network, state = "udp", "07" // unconnected UDP server socket
	}
	for _, table := range []string{network, network + "6"} {
		file, err := os.Open(filepath.Join(directory, "net", table))
		if err != nil {
			continue
		}
		matches := socketTableOwnsListener(bufio.NewScanner(file), address, state, owned)
		_ = file.Close()
		if matches {
			return true
		}
	}
	return false
}

func socketTableOwnsListener(scanner *bufio.Scanner, target netip.AddrPort, state string, owned map[string]bool) bool {
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != state || !owned[fields[9]] {
			continue
		}
		local, port, found := strings.Cut(fields[1], ":")
		portNumber, err := strconv.ParseUint(port, 16, 16)
		if !found || err != nil || uint16(portNumber) != target.Port() {
			continue
		}
		address, ok := procSocketAddress(local)
		if ok && (address.IsUnspecified() || address.Unmap() == target.Addr().Unmap()) {
			return true
		}
	}
	return false
}

func procSocketAddress(value string) (netip.Addr, bool) {
	decoded, err := hex.DecodeString(value)
	if err != nil || (len(decoded) != 4 && len(decoded) != 16) {
		return netip.Addr{}, false
	}
	// proc prints each native-endian 32-bit word, including IPv6's four
	// words. Convert to network order on both supported Linux architectures.
	for offset := 0; offset < len(decoded); offset += 4 {
		word := binary.BigEndian.Uint32(decoded[offset:])
		binary.NativeEndian.PutUint32(decoded[offset:], word)
	}
	return netip.AddrFromSlice(decoded)
}
