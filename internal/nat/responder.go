package nat

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
)

// Responder is a tiny UDP echo server that Gmesh runs on a dedicated port
// (default 51822). Remote peers send hole-punch probe packets here; the
// responder bounces them back, opening a NAT pinhole in the process.
//
// Protocol: the first byte must be 0x7E (a "Gmesh probe" magic), followed
// by an opaque nonce. The server replies with the same bytes. Non-matching
// packets are dropped silently so we don't become a reflector for DDoS.
type Responder struct {
	Port uint16
	Log  *slog.Logger

	mu      sync.Mutex
	conn    *net.UDPConn
	stop    chan struct{}
	running atomic.Bool
	echoed  atomic.Int64
}

// MagicByte is the first byte of every Gmesh probe packet.
const MagicByte = 0x7E

// NewResponder returns a Responder that will listen on port when Start is called.
func NewResponder(port uint16, log *slog.Logger) *Responder {
	if log == nil {
		log = slog.Default()
	}
	return &Responder{Port: port, Log: log}
}

// Start binds the UDP socket and launches the read loop. Idempotent.
func (r *Responder) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running.Load() {
		return nil
	}

	addr := &net.UDPAddr{IP: net.IPv4zero, Port: int(r.Port)}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp :%d: %w", r.Port, err)
	}
	r.conn = conn
	r.stop = make(chan struct{})
	r.running.Store(true)

	go r.loop(ctx)
	r.Log.Info("udp responder started", "port", r.Port)
	return nil
}

// Stop closes the listening socket. Safe to call multiple times.
func (r *Responder) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running.Load() {
		return
	}
	close(r.stop)
	_ = r.conn.Close()
	r.running.Store(false)
	r.Log.Info("udp responder stopped", "echoed", r.echoed.Load())
}

// EchoCount returns how many probes have been answered since start.
func (r *Responder) EchoCount() int64 { return r.echoed.Load() }

func (r *Responder) loop(ctx context.Context) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		default:
		}

		n, from, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			// Closed or unrecoverable.
			select {
			case <-r.stop:
				return
			default:
			}
			r.Log.Debug("udp responder read error", "error", err)
			return
		}
		if n < 2 || buf[0] != MagicByte {
			continue // silently drop non-Gmesh traffic
		}
		if _, err := r.conn.WriteToUDP(buf[:n], from); err != nil {
			r.Log.Debug("udp responder write error", "error", err, "peer", from.String())
			continue
		}
		r.echoed.Add(1)
	}
}
