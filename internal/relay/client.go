package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Session is the relay side of one peer. It owns a loopback UDP socket
// (127.0.0.1:port) that WireGuard uses as the peer's endpoint when traffic
// goes through a relay, and one link per relay server.
//
// WG → forwarder → DATA frame → a relay → the peer's session → the peer's WG.
//
// Two sides only meet on a relay both of them reach, so a session keeps a
// link to every relay it can: it receives from all of them and sends on the
// one the peer last sent through (else the first healthy one). A session
// can stand by unused: WireGuard roams to wherever the peer's packets last
// came from, so the moment the other side sends through a relay, our WG
// answers through it too.
type Session struct {
	Peer Key
	Log  *slog.Logger

	auth         atomic.Pointer[[]byte]
	localForward *net.UDPConn
	wgEndpoint   atomic.Pointer[net.UDPAddr]

	mu    sync.Mutex
	links map[int]*link // by relay index (group) in the node's relay list

	startedAt time.Time
	closed    atomic.Bool
	ctx       context.Context
	cancel    context.CancelFunc
	refresh   time.Duration
	muteUntil atomic.Int64 // unix nano; relayed DATA is dropped until then
	onInfo    atomic.Pointer[func([]byte)]

	stats struct {
		sync.Mutex
		txFrames, rxFrames uint64
		txBytes, rxBytes   uint64
	}
}

// link is one upstream to one relay server (UDP or WebSocket).
type link struct {
	group     int
	addr      string
	up        upstream
	cancel    context.CancelFunc
	lastHeard atomic.Int64 // unix nano of the last frame from the relay
	lastData  atomic.Int64 // unix nano of the last DATA from the peer
	authFail  atomic.Pointer[string]
	closed    atomic.Bool
}

// linkDeadAfter: AUTH is refreshed every 10 s and answered, so 25 s of
// silence means the relay (or the way to it) is gone.
const linkDeadAfter = 25 * time.Second

func (l *link) healthy() bool {
	return !l.closed.Load() && time.Since(time.Unix(0, l.lastHeard.Load())) < linkDeadAfter && l.authFail.Load() == nil
}

func (l *link) close() {
	if l.closed.CompareAndSwap(false, true) {
		l.cancel()
		_ = l.up.Close()
	}
}

// Config bundles the knobs for DialSession / AddLink.
type Config struct {
	Auth        Auth
	RelayAddr   string       // host:port ("udp://" optional), or a wss:// URL
	WGEndpoint  *net.UDPAddr // where WireGuard listens, e.g. 127.0.0.1:51820
	DialTimeout time.Duration
	Refresh     time.Duration // AUTH re-sent this often; default 10s
	Log         *slog.Logger
}

// NewSession opens the loopback forwarder for one peer; links are added
// with AddLink.
func NewSession(a Auth, wg *net.UDPAddr, refresh time.Duration, log *slog.Logger) (*Session, error) {
	if log == nil {
		log = slog.Default()
	}
	if refresh == 0 {
		refresh = 10 * time.Second
	}
	if wg == nil {
		return nil, errors.New("relay: WGEndpoint is required")
	}
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen local: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{Peer: a.Peer, Log: log, localForward: local, links: map[int]*link{},
		startedAt: time.Now(), ctx: ctx, cancel: cancel, refresh: refresh}
	f := EncodeFrame(FrameAUTH, a.Encode())
	s.auth.Store(&f)
	s.wgEndpoint.Store(wg)
	go s.wgToRelayLoop()
	return s, nil
}

// DialSession is NewSession plus one link (group 0).
func DialSession(ctx context.Context, cfg Config) (*Session, error) {
	s, err := NewSession(cfg.Auth, cfg.WGEndpoint, cfg.Refresh, cfg.Log)
	if err != nil {
		return nil, err
	}
	if err := s.AddLink(ctx, 0, cfg.RelayAddr, cfg.DialTimeout); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// AddLink connects to one relay (replacing the link of that group).
func (s *Session) AddLink(ctx context.Context, group int, addr string, timeout time.Duration) error {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	up, _, err := dialUpstream(ctx, addr, timeout)
	if err != nil {
		return err
	}
	auth := *s.auth.Load()
	if err := handshake(up, auth, timeout); err != nil {
		_ = up.Close()
		return err
	}
	lctx, cancel := context.WithCancel(s.ctx)
	l := &link{group: group, addr: addr, up: up, cancel: cancel}
	l.lastHeard.Store(time.Now().UnixNano())
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		l.close()
		return net.ErrClosed
	}
	old := s.links[group]
	s.links[group] = l
	s.mu.Unlock()
	if old != nil {
		old.close()
	}
	go s.relayToWGLoop(l)
	go s.refreshLoop(lctx, l)
	return nil
}

// DropLink closes the link of a group (to redial it).
func (s *Session) DropLink(group int) {
	s.mu.Lock()
	l := s.links[group]
	delete(s.links, group)
	s.mu.Unlock()
	if l != nil {
		l.close()
	}
}

// LinkInfo describes one link.
type LinkInfo struct {
	Group     int
	Addr      string
	Healthy   bool
	LastData  time.Time
	AuthError string
}

// Links lists the links, by group.
func (s *Session) Links() []LinkInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LinkInfo, 0, len(s.links))
	for g, l := range s.links {
		li := LinkInfo{Group: g, Addr: l.addr, Healthy: l.healthy()}
		if t := l.lastData.Load(); t > 0 {
			li.LastData = time.Unix(0, t)
		}
		if p := l.authFail.Load(); p != nil {
			li.AuthError = *p
		}
		out = append(out, li)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Group < out[j].Group })
	return out
}

// pick is where to send: the link the peer's data last came through
// (within 30 s); before that is known, every healthy link — the peer may
// reach only one of the relays, and WireGuard drops the duplicates.
func (s *Session) pick() []*link {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best *link
	var healthy []*link
	open := make([]*link, 0, len(s.links))
	cutoff := time.Now().Add(-30 * time.Second).UnixNano()
	for _, l := range s.links {
		if l.closed.Load() {
			continue
		}
		open = append(open, l)
		if l.healthy() {
			healthy = append(healthy, l)
		}
		if d := l.lastData.Load(); d > cutoff && l.healthy() && (best == nil || d > best.lastData.Load()) {
			best = l
		}
	}
	switch {
	case best != nil:
		return []*link{best}
	case len(healthy) > 0:
		return healthy
	}
	return open
}

// handshake sends AUTH (three tries) and waits for the answer.
func handshake(c upstream, auth []byte, timeout time.Duration) error {
	buf := make([]byte, MaxFrameSize)
	per := timeout / 3
	last := errors.New("relay: no answer")
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

// Healthy reports whether any relay answered recently (linkDeadAfter).
func (s *Session) Healthy() bool {
	if s.closed.Load() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.links {
		if l.healthy() {
			return true
		}
	}
	return false
}

// AuthError is the last refusal of any relay, if any.
func (s *Session) AuthError() string {
	for _, l := range s.Links() {
		if l.AuthError != "" {
			return l.AuthError
		}
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
	s.mu.Lock()
	links := s.links
	s.links = map[int]*link{}
	s.mu.Unlock()
	for _, l := range links {
		l.close()
	}
	_ = s.localForward.Close()
	return nil
}

// wgToRelayLoop ships what WireGuard sends to the forwarder up to a relay.
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
		f := EncodeFrame(FrameDATA, buf[:n])
		sent := false
		for _, l := range s.pick() {
			if _, err := l.up.Write(f); err == nil {
				sent = true
			}
		}
		if !sent {
			continue // no relay reachable for now; the owner redials
		}
		s.stats.Lock()
		s.stats.txFrames++
		s.stats.txBytes += uint64(n)
		s.stats.Unlock()
	}
}

// relayToWGLoop hands what one relay delivers to WireGuard.
func (s *Session) relayToWGLoop(l *link) {
	buf := make([]byte, MaxFrameSize)
	for !l.closed.Load() {
		n, err := l.up.Read(buf)
		if err != nil {
			if l.closed.Load() || errors.Is(err, errWSClosed) {
				return
			}
			if IsWS(l.addr) {
				// A WebSocket that failed stays failed: let the link go
				// unhealthy so the owner redials.
				l.lastHeard.Store(0)
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
		now := time.Now().UnixNano()
		l.lastHeard.Store(now)
		switch typ {
		case FrameDATA:
			l.lastData.Store(now)
			if now < s.muteUntil.Load() {
				continue
			}
			if _, err := s.localForward.WriteToUDP(payload, s.wgEndpoint.Load()); err != nil {
				continue
			}
			s.stats.Lock()
			s.stats.rxFrames++
			s.stats.rxBytes += uint64(len(payload))
			s.stats.Unlock()
		case FramePeerInfo:
			if h := s.onInfo.Load(); h != nil {
				(*h)(append([]byte(nil), payload...))
			}
		case FrameAUTHOK:
			l.authFail.Store(nil)
		case FrameAUTHFail:
			r := string(payload)
			l.authFail.Store(&r)
			s.Log.Warn("relay refused us", "peer", s.Peer.String(), "relay", l.addr, "reason", r)
		}
	}
}

// refreshLoop re-sends AUTH on one link: keeps the NAT mapping and the
// relay's slot alive, and re-registers after a relay restart or our address
// changing.
func (s *Session) refreshLoop(ctx context.Context, l *link) {
	t := time.NewTicker(s.refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = l.up.Write(*s.auth.Load())
		}
	}
}

// OnPeerInfo sets what handles PEERINFO frames from the peer.
func (s *Session) OnPeerInfo(h func([]byte)) { s.onInfo.Store(&h) }

// SendPeerInfo sends a PEERINFO frame to the peer through every healthy
// relay (it can't know which ones the peer reaches).
func (s *Session) SendPeerInfo(b []byte) error {
	f := EncodeFrame(FramePeerInfo, b)
	s.mu.Lock()
	links := make([]*link, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	s.mu.Unlock()
	err := errors.New("relay: no link")
	for _, l := range links {
		if !l.healthy() {
			continue
		}
		if _, e := l.up.Write(f); e == nil {
			err = nil
		}
	}
	return err
}

// Mute drops what the relays deliver for d. While trying a direct path,
// packets the peer had already sent through a relay would otherwise make
// WireGuard roam straight back to the relay.
func (s *Session) Mute(d time.Duration) {
	s.muteUntil.Store(time.Now().Add(d).UnixNano())
}

// SetAuth replaces the AUTH frame (a renewed credential) and sends it on
// every link.
func (s *Session) SetAuth(a Auth) {
	f := EncodeFrame(FrameAUTH, a.Encode())
	s.auth.Store(&f)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.links {
		_, _ = l.up.Write(f)
	}
}
