package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Session is one relay connection for one peer. It owns
//   - the upstream UDP socket to gmesh-relay, and
//   - a loopback UDP socket (127.0.0.1:port) WireGuard uses as the peer's
//     endpoint when traffic goes through the relay.
//
// WG → forwarder → DATA frame → relay → the peer's session → the peer's WG.
// A session can stand by unused: WireGuard roams to whichever endpoint the
// peer's packets last came from, so the moment the other side sends through
// the relay, our WG answers through it too.
type Session struct {
	Peer  Key
	Relay *net.UDPAddr
	Log   *slog.Logger

	auth         atomic.Pointer[[]byte]
	upstream     *net.UDPConn
	localForward *net.UDPConn
	wgEndpoint   atomic.Pointer[net.UDPAddr]

	startedAt time.Time
	lastHeard atomic.Int64 // unix nano of the last frame from the relay
	authFail  atomic.Pointer[string]
	closed    atomic.Bool
	cancel    context.CancelFunc
	muteUntil atomic.Int64 // unix nano; relayed DATA is dropped until then

	stats struct {
		sync.Mutex
		txFrames, rxFrames uint64
		txBytes, rxBytes   uint64
	}
}

// Config bundles the knobs for DialSession.
type Config struct {
	Auth        Auth
	RelayAddr   string       // host:port, optionally "udp://host:port"
	WGEndpoint  *net.UDPAddr // where WireGuard listens, e.g. 127.0.0.1:51820
	DialTimeout time.Duration
	Refresh     time.Duration // AUTH re-sent this often; default 20s
	Log         *slog.Logger
}

// DialSession connects to gmesh-relay, authenticates, opens the loopback
// forwarder, and keeps the registration fresh until Close.
func DialSession(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 3 * time.Second
	}
	if cfg.Refresh == 0 {
		cfg.Refresh = 20 * time.Second
	}
	if cfg.WGEndpoint == nil {
		return nil, errors.New("relay: WGEndpoint is required")
	}
	relayAddr, err := net.ResolveUDPAddr("udp", strings.TrimPrefix(cfg.RelayAddr, "udp://"))
	if err != nil {
		return nil, fmt.Errorf("resolve relay: %w", err)
	}
	upstream, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial relay: %w", err)
	}
	auth := EncodeFrame(FrameAUTH, cfg.Auth.Encode())
	if err := handshake(upstream, auth, cfg.DialTimeout); err != nil {
		_ = upstream.Close()
		return nil, err
	}
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = upstream.Close()
		return nil, fmt.Errorf("listen local: %w", err)
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s := &Session{
		Peer: cfg.Auth.Peer, Relay: relayAddr, Log: cfg.Log,
		upstream: upstream, localForward: local, startedAt: time.Now(), cancel: cancel,
	}
	s.auth.Store(&auth)
	s.wgEndpoint.Store(cfg.WGEndpoint)
	s.lastHeard.Store(time.Now().UnixNano())
	go s.wgToRelayLoop()
	go s.relayToWGLoop()
	go s.refreshLoop(ctx, cfg.Refresh)
	return s, nil
}

// handshake sends AUTH (three tries) and waits for the answer.
func handshake(c *net.UDPConn, auth []byte, timeout time.Duration) error {
	buf := make([]byte, MaxFrameSize)
	per := timeout / 3
	var last error = errors.New("relay: no answer")
	for i := 0; i < 3; i++ {
		if _, err := c.Write(auth); err != nil {
			return fmt.Errorf("write auth: %w", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(per))
		n, err := c.Read(buf)
		if err != nil {
			last = fmt.Errorf("relay: no answer: %w", err)
			continue
		}
		typ, payload, _ := DecodeFrame(buf[:n])
		_ = c.SetReadDeadline(time.Time{})
		switch typ {
		case FrameAUTHOK:
			return nil
		case FrameAUTHFail:
			return fmt.Errorf("relay: auth fail: %s", string(payload))
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	return last
}

// LocalEndpoint is the 127.0.0.1:PORT address WireGuard dials to send
// through the relay.
func (s *Session) LocalEndpoint() *net.UDPAddr {
	return s.localForward.LocalAddr().(*net.UDPAddr)
}

// Healthy reports whether the relay answered within the last minute.
func (s *Session) Healthy() bool {
	return !s.closed.Load() && time.Since(time.Unix(0, s.lastHeard.Load())) < time.Minute && s.authFail.Load() == nil
}

// AuthError is the relay's last refusal, if any.
func (s *Session) AuthError() string {
	if p := s.authFail.Load(); p != nil {
		return *p
	}
	return ""
}

// Stats returns a snapshot.
func (s *Session) Stats() Stats {
	s.stats.Lock()
	defer s.stats.Unlock()
	return Stats{
		TxFrames: s.stats.txFrames, RxFrames: s.stats.rxFrames,
		BytesTx: s.stats.txBytes, BytesRx: s.stats.rxBytes,
		ConnectedS: int64(time.Since(s.startedAt).Seconds()),
	}
}

// Close tears the session down. Idempotent.
func (s *Session) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.cancel()
	_ = s.upstream.Close()
	_ = s.localForward.Close()
	return nil
}

// wgToRelayLoop ships what WireGuard sends to the forwarder up to the relay.
func (s *Session) wgToRelayLoop() {
	buf := make([]byte, MaxFrameSize)
	for !s.closed.Load() {
		n, src, err := s.localForward.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() {
				return
			}
			continue
		}
		if !src.IP.IsLoopback() {
			continue
		}
		s.wgEndpoint.Store(src) // WG's own port — where answers go
		if _, err := s.upstream.Write(EncodeFrame(FrameDATA, buf[:n])); err != nil {
			continue // relay unreachable for now; refreshLoop keeps trying
		}
		s.stats.Lock()
		s.stats.txFrames++
		s.stats.txBytes += uint64(n)
		s.stats.Unlock()
	}
}

// relayToWGLoop hands DATA from the relay to WireGuard.
func (s *Session) relayToWGLoop() {
	buf := make([]byte, MaxFrameSize)
	for !s.closed.Load() {
		n, err := s.upstream.Read(buf)
		if err != nil {
			if s.closed.Load() {
				return
			}
			// ICMP unreachable surfaces here as ECONNREFUSED on a connected
			// UDP socket; the relay may just be restarting.
			time.Sleep(500 * time.Millisecond)
			continue
		}
		typ, payload, err := DecodeFrame(buf[:n])
		if err != nil {
			continue
		}
		s.lastHeard.Store(time.Now().UnixNano())
		switch typ {
		case FrameDATA:
			if time.Now().UnixNano() < s.muteUntil.Load() {
				continue
			}
			if _, err := s.localForward.WriteToUDP(payload, s.wgEndpoint.Load()); err != nil {
				continue
			}
			s.stats.Lock()
			s.stats.rxFrames++
			s.stats.rxBytes += uint64(len(payload))
			s.stats.Unlock()
		case FrameAUTHOK:
			s.authFail.Store(nil)
		case FrameAUTHFail:
			r := string(payload)
			s.authFail.Store(&r)
			s.Log.Warn("relay refused us", "peer", s.Peer.String(), "reason", r)
		}
	}
}

// refreshLoop re-sends AUTH: keeps the NAT mapping and the relay's slot
// alive, and re-registers after a relay restart or our address changing.
func (s *Session) refreshLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.upstream.Write(*s.auth.Load())
		}
	}
}

// Mute drops what the relay delivers for d. While trying a direct path,
// packets the peer had already sent through the relay would otherwise make
// WireGuard roam straight back to the relay.
func (s *Session) Mute(d time.Duration) {
	s.muteUntil.Store(time.Now().Add(d).UnixNano())
}

// SetAuth replaces the AUTH frame (a renewed credential) and sends it.
func (s *Session) SetAuth(a Auth) {
	f := EncodeFrame(FrameAUTH, a.Encode())
	s.auth.Store(&f)
	_, _ = s.upstream.Write(f)
}
