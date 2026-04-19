package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ── Public API ──────────────────────────────────────────────────────────

// Session is one active relay connection inside gmeshd. It owns:
//   - the upstream UDP socket to gmesh-relay
//   - a local loopback UDP forwarder (127.0.0.1:alloc) that WireGuard dials
//
// WG → local forwarder → wrapped in DATA frame → relay → remote peer.
// Remote peer → relay → our upstream socket → unwrapped → local forwarder
// → WireGuard's listen socket.
type Session struct {
	PeerID    int64
	SessionID [16]byte
	Relay     *net.UDPAddr // gmesh-relay address
	Log       *slog.Logger

	upstream     *net.UDPConn // our connection to the relay
	localForward *net.UDPConn // 127.0.0.1:? — what WG dials
	wgEndpoint   *net.UDPAddr // WG's listen socket (the local WG port)

	startedAt time.Time
	closed    atomic.Bool

	stats struct {
		sync.Mutex
		txFrames, rxFrames uint64
		txBytes, rxBytes   uint64
	}
}

// Config bundles the knobs for DialSession.
type Config struct {
	PeerID      int64
	SessionID   [16]byte
	AuthToken   AuthToken
	RelayAddr   string       // host:port
	WGEndpoint  *net.UDPAddr // the WireGuard interface's listen UDP address (e.g. 127.0.0.1:51820)
	DialTimeout time.Duration
	Log         *slog.Logger
}

// DialSession connects to gmesh-relay, authenticates, allocates a local
// loopback UDP port to expose as the WG endpoint, and begins forwarding
// both directions.
func DialSession(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 3 * time.Second
	}
	if cfg.WGEndpoint == nil {
		return nil, errors.New("relay: WGEndpoint is required")
	}

	relayAddr, err := net.ResolveUDPAddr("udp", cfg.RelayAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve relay: %w", err)
	}
	upstream, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial relay: %w", err)
	}

	// Send AUTH frame.
	if _, err := upstream.Write(EncodeFrame(FrameAUTH, cfg.AuthToken.Encode())); err != nil {
		_ = upstream.Close()
		return nil, fmt.Errorf("write auth: %w", err)
	}

	// Wait for AUTH_OK / AUTH_FAIL.
	_ = upstream.SetReadDeadline(time.Now().Add(cfg.DialTimeout))
	buf := make([]byte, MaxFrameSize)
	n, err := upstream.Read(buf)
	if err != nil {
		_ = upstream.Close()
		return nil, fmt.Errorf("read auth reply: %w", err)
	}
	typ, payload, err := DecodeFrame(buf[:n])
	if err != nil {
		_ = upstream.Close()
		return nil, fmt.Errorf("decode auth reply: %w", err)
	}
	switch typ {
	case FrameAUTHOK:
	case FrameAUTHFail:
		_ = upstream.Close()
		return nil, fmt.Errorf("relay: auth fail: %s", string(payload))
	default:
		_ = upstream.Close()
		return nil, fmt.Errorf("relay: unexpected reply: %s", typ)
	}
	_ = upstream.SetReadDeadline(time.Time{}) // clear deadline

	// Allocate the local forwarder socket.
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = upstream.Close()
		return nil, fmt.Errorf("listen local: %w", err)
	}

	s := &Session{
		PeerID:       cfg.PeerID,
		SessionID:    cfg.SessionID,
		Relay:        relayAddr,
		Log:          cfg.Log,
		upstream:     upstream,
		localForward: local,
		wgEndpoint:   cfg.WGEndpoint,
		startedAt:    time.Now(),
	}
	go s.wgToRelayLoop()
	go s.relayToWGLoop()
	go s.keepaliveLoop(ctx)

	cfg.Log.Info("relay session established",
		"peer_id", cfg.PeerID,
		"relay", cfg.RelayAddr,
		"local_endpoint", local.LocalAddr().String(),
	)
	return s, nil
}

// LocalEndpoint returns the 127.0.0.1:PORT address WireGuard should dial
// as its peer endpoint to route traffic through the relay.
func (s *Session) LocalEndpoint() *net.UDPAddr {
	return s.localForward.LocalAddr().(*net.UDPAddr)
}

// Stats returns a snapshot.
func (s *Session) Stats() Stats {
	s.stats.Lock()
	defer s.stats.Unlock()
	return Stats{
		TxFrames:   s.stats.txFrames,
		RxFrames:   s.stats.rxFrames,
		BytesTx:    s.stats.txBytes,
		BytesRx:    s.stats.rxBytes,
		ConnectedS: int64(time.Since(s.startedAt).Seconds()),
	}
}

// Close tears the session down. Idempotent.
func (s *Session) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = s.upstream.Close()
	_ = s.localForward.Close()
	return nil
}

// ── Loops ──────────────────────────────────────────────────────────────

// wgToRelayLoop reads from the local forwarder (WG traffic) and ships
// DATA frames upstream. Must also remember the WG source address so the
// reverse loop can deliver packets back to it.
func (s *Session) wgToRelayLoop() {
	buf := make([]byte, MaxFrameSize)
	for {
		if s.closed.Load() {
			return
		}
		n, src, err := s.localForward.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Remember the WG source (for reverse direction).
		// WireGuard dials us from its own listen port (usually 51820) so
		// this is stable.
		s.wgEndpoint = src

		frame := EncodeFrame(FrameDATA, buf[:n])
		if _, err := s.upstream.Write(frame); err != nil {
			s.Log.Debug("relay write error", "error", err)
			return
		}
		s.stats.Lock()
		s.stats.txFrames++
		s.stats.txBytes += uint64(n) //nolint:gosec
		s.stats.Unlock()
	}
}

// relayToWGLoop reads from the upstream relay socket and writes the
// payload of DATA frames back to WireGuard via the local forwarder.
func (s *Session) relayToWGLoop() {
	buf := make([]byte, MaxFrameSize)
	for {
		if s.closed.Load() {
			return
		}
		n, err := s.upstream.Read(buf)
		if err != nil {
			return
		}
		typ, payload, err := DecodeFrame(buf[:n])
		if err != nil {
			continue
		}
		switch typ {
		case FrameDATA:
			if s.wgEndpoint == nil {
				continue
			}
			if _, err := s.localForward.WriteToUDP(payload, s.wgEndpoint); err != nil {
				s.Log.Debug("local write error", "error", err)
				continue
			}
			s.stats.Lock()
			s.stats.rxFrames++
			s.stats.rxBytes += uint64(len(payload)) //nolint:gosec
			s.stats.Unlock()
		case FramePONG:
			// keepalive reply; nothing to do
		case FramePeerOffline:
			s.Log.Warn("relay reports peer offline", "peer_id", s.PeerID)
		default:
			// Ignore
		}
	}
}

// keepaliveLoop sends a PING every 15s so any stateful middlebox between
// us and the relay doesn't evict our mapping.
func (s *Session) keepaliveLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.closed.Load() {
				return
			}
			_, _ = s.upstream.Write(EncodeFrame(FramePING, nil))
		}
	}
}

// ── Types satisfying internal/relay.Client ────────────────────────────

// Stats (overrides the stub in internal/relay). Fields match the protocol
// reference in docs/protocol.md and the gmeshv1.Peer stats fields.
//
// The embedded Stats struct from the pre-existing stub file is replaced
// here; Phase 0's stub defined the same shape so no callers break.
