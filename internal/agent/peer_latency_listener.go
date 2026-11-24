package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

type peerLatencyListener struct {
	listener net.Listener
	done     chan struct{}
	once     sync.Once
}

// startPeerLatencyListener opens the dedicated TCP port used for inter-server
// RTT probes. Every accepted connection is closed immediately after the TCP
// handshake completes so no banner or application data is ever exchanged.
func startPeerLatencyListener(ctx context.Context, listenAddr string) *peerLatencyListener {
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		return nil
	}
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		slog.Warn("peer latency TCP probe listener is unavailable", "listen", listenAddr, "error", err)
		return nil
	}
	active := &peerLatencyListener{
		listener: listener,
		done:     make(chan struct{}),
	}
	slog.Info("peer latency TCP probe listener started", "listen", listener.Addr().String())
	go active.serve()
	go func() {
		<-ctx.Done()
		active.Close()
	}()
	return active
}

func (l *peerLatencyListener) Addr() net.Addr {
	if l == nil || l.listener == nil {
		return nil
	}
	return l.listener.Addr()
}

func (l *peerLatencyListener) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		_ = l.listener.Close()
	})
	<-l.done
}

func (l *peerLatencyListener) serve() {
	defer close(l.done)
	var backoff time.Duration
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else if backoff < time.Second {
					backoff *= 2
				}
				time.Sleep(backoff)
				continue
			}
			slog.Warn("peer latency TCP probe listener stopped", "error", err)
			return
		}
		backoff = 0
		_ = conn.Close()
	}
}
