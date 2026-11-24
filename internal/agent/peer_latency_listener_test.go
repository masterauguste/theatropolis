package agent

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
)

func TestPeerLatencyListenerAcceptsAndClosesQuietly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listener := startPeerLatencyListener(ctx, "127.0.0.1:0")
	if listener == nil {
		t.Fatal("startPeerLatencyListener() returned nil")
	}
	defer listener.Close()

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || tcpAddr.Port == 0 {
		t.Fatalf("listener.Addr() = %v", listener.Addr())
	}

	conn, err := net.DialTimeout("tcp", tcpAddr.String(), time.Second)
	if err != nil {
		t.Fatalf("DialTimeout() error = %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	n, readErr := conn.Read(buf)
	_ = conn.Close()
	if n != 0 || readErr != io.EOF {
		t.Fatalf("Read() = (%d, %v), want (0, io.EOF)", n, readErr)
	}

	status, duration := probeTCPPath(context.Background(), linkLatencyProbeTarget{
		address:   "127.0.0.1",
		port:      uint16(tcpAddr.Port),
		probeType: controlv1.LinkLatencyProbeType_LINK_LATENCY_PROBE_TYPE_TCP,
	})
	if status != controlv1.LinkLatencyStatus_LINK_LATENCY_STATUS_REACHABLE {
		t.Fatalf("probeTCPPath() status = %v, want REACHABLE (duration=%v)", status, duration)
	}

	cancel()
	listener.Close()
}
