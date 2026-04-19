// Package main (cmd/gmesh-relay) is the DERP-style UDP relay.
//
// Two clients that share a session_id and each authenticate with a valid
// HMAC-signed token get paired; thereafter any DATA frame from one is
// forwarded to the other. Sessions idle out after SessionIdleTTL.
package main

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/relay"
)

// peerConn is one authenticated client's state inside a Session.
type peerConn struct {
	peerID   uint64
	addr     *net.UDPAddr
	lastSeen time.Time
}

// Session tracks the (up to 2) peers that share a session_id.
type Session struct {
	mu      sync.Mutex
	id      [16]byte
	peers   [2]*peerConn
	created time.Time
}

// find returns the slot holding addr (by source address), or -1 if missing.
func (s *Session) find(addr *net.UDPAddr) int {
	for i, p := range s.peers {
		if p == nil {
			continue
		}
		if p.addr.IP.Equal(addr.IP) && p.addr.Port == addr.Port {
			return i
		}
	}
	return -1
}

// insert registers a (peerID, addr) pair. If the session already has two
// peers with different addrs, insert replaces the oldest. Returns the slot
// index (0 or 1) and the OTHER slot's pointer (may be nil).
func (s *Session) insert(peerID uint64, addr *net.UDPAddr) (self, other *peerConn) {
	now := time.Now()
	p := &peerConn{peerID: peerID, addr: addr, lastSeen: now}

	// If peerID already in a slot, refresh.
	for i, slot := range s.peers {
		if slot != nil && slot.peerID == peerID {
			s.peers[i] = p
			self = p
			other = s.peers[1-i]
			return
		}
	}
	// Empty slot?
	for i, slot := range s.peers {
		if slot == nil {
			s.peers[i] = p
			self = p
			other = s.peers[1-i]
			return
		}
	}
	// Both full — replace the one with older lastSeen.
	victim := 0
	if s.peers[1].lastSeen.Before(s.peers[0].lastSeen) {
		victim = 1
	}
	s.peers[victim] = p
	self = p
	other = s.peers[1-victim]
	return
}

// idle returns true if both slots have been silent for > ttl.
func (s *Session) idle(ttl time.Duration, now time.Time) bool {
	for _, p := range s.peers {
		if p != nil && now.Sub(p.lastSeen) < ttl {
			return false
		}
	}
	return true
}

// Server is the relay UDP server.
type Server struct {
	Addr            string        // e.g. ":4500"
	Secret          []byte        // HMAC key shared with the backend
	SessionIdleTTL  time.Duration // default 60s
	Log             *slog.Logger

	mu       sync.Mutex
	sessions map[[16]byte]*Session
	conn     *net.UDPConn

	stats struct {
		sync.Mutex
		authOK, authFail uint64
		framesForwarded  uint64
		bytesForwarded   uint64
		sessionsCreated  uint64
	}
}

// NewServer builds a Server with defaults applied.
func NewServer(addr string, secret []byte, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		Addr:           addr,
		Secret:         secret,
		SessionIdleTTL: 60 * time.Second,
		Log:            log,
		sessions:       make(map[[16]byte]*Session),
	}
}

// ListenAndServe binds the UDP socket and runs the forwarding loop until
// ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	laddr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	s.conn = conn
	defer func() { _ = conn.Close() }()

	s.Log.Info("gmesh-relay listening", "addr", conn.LocalAddr().String())

	// Janitor goroutine: sweep idle sessions.
	go s.janitor(ctx)

	// Read loop.
	buf := make([]byte, relay.MaxFrameSize)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			s.Log.Warn("read error", "error", err)
			continue
		}
		s.handle(from, append([]byte(nil), buf[:n]...))
	}
}

// handle processes one incoming frame.
func (s *Server) handle(from *net.UDPAddr, buf []byte) {
	typ, payload, err := relay.DecodeFrame(buf)
	if err != nil {
		return
	}

	switch typ {
	case relay.FrameAUTH:
		s.handleAuth(from, payload)
	case relay.FrameDATA:
		s.handleData(from, payload)
	case relay.FramePING:
		// Respond with PONG; also refresh session bookkeeping.
		s.touch(from)
		_, _ = s.conn.WriteToUDP(relay.EncodeFrame(relay.FramePONG, nil), from)
	default:
		// Unknown / unexpected frame from client — ignore.
	}
}

func (s *Server) handleAuth(from *net.UDPAddr, payload []byte) {
	tok, err := relay.DecodeAuthToken(payload)
	if err != nil {
		s.sendAuthFail(from, "malformed token")
		s.bumpAuthFail()
		return
	}
	if err := tok.Verify(s.Secret); err != nil {
		s.sendAuthFail(from, "hmac mismatch")
		s.bumpAuthFail()
		return
	}

	s.mu.Lock()
	sess, ok := s.sessions[tok.SessionID]
	if !ok {
		sess = &Session{id: tok.SessionID, created: time.Now()}
		s.sessions[tok.SessionID] = sess
		s.stats.Lock()
		s.stats.sessionsCreated++
		s.stats.Unlock()
	}
	s.mu.Unlock()

	sess.mu.Lock()
	self, _ := sess.insert(tok.PeerID, from)
	_ = self
	sess.mu.Unlock()

	s.bumpAuthOK()
	_, _ = s.conn.WriteToUDP(relay.EncodeFrame(relay.FrameAUTHOK, nil), from)
	s.Log.Debug("auth ok", "peer_id", tok.PeerID, "from", from.String())
}

func (s *Server) handleData(from *net.UDPAddr, payload []byte) {
	// Find the session containing this source address.
	s.mu.Lock()
	var sess *Session
	var self, other *peerConn
	for _, sn := range s.sessions {
		sn.mu.Lock()
		i := sn.find(from)
		if i != -1 {
			sess = sn
			self = sn.peers[i]
			other = sn.peers[1-i]
			sn.mu.Unlock()
			break
		}
		sn.mu.Unlock()
	}
	s.mu.Unlock()

	if sess == nil || self == nil {
		// Unauthenticated.
		return
	}
	self.lastSeen = time.Now()

	if other == nil {
		// Pair hasn't joined yet — drop.
		return
	}

	forward := relay.EncodeFrame(relay.FrameDATA, payload)
	n, err := s.conn.WriteToUDP(forward, other.addr)
	if err != nil {
		s.Log.Debug("forward failed", "error", err)
		return
	}
	s.stats.Lock()
	s.stats.framesForwarded++
	s.stats.bytesForwarded += uint64(n) //nolint:gosec
	s.stats.Unlock()
}

func (s *Server) sendAuthFail(to *net.UDPAddr, reason string) {
	_, _ = s.conn.WriteToUDP(relay.EncodeFrame(relay.FrameAUTHFail, []byte(reason)), to)
}

func (s *Server) touch(from *net.UDPAddr) {
	s.mu.Lock()
	for _, sn := range s.sessions {
		sn.mu.Lock()
		if i := sn.find(from); i != -1 {
			sn.peers[i].lastSeen = time.Now()
		}
		sn.mu.Unlock()
	}
	s.mu.Unlock()
}

// janitor runs once per SessionIdleTTL and removes idle sessions.
func (s *Server) janitor(ctx context.Context) {
	ttl := s.SessionIdleTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	t := time.NewTicker(ttl / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			for id, sess := range s.sessions {
				sess.mu.Lock()
				if sess.idle(ttl, now) {
					delete(s.sessions, id)
				}
				sess.mu.Unlock()
			}
			s.mu.Unlock()
		}
	}
}

// Stats is a read-only snapshot of relay counters.
type Stats struct {
	AuthOK, AuthFail, FramesForwarded, BytesForwarded, SessionsCreated uint64
	ActiveSessions                                                     int
}

// Stats returns current counters.
func (s *Server) Stats() Stats {
	s.stats.Lock()
	out := Stats{
		AuthOK:          s.stats.authOK,
		AuthFail:        s.stats.authFail,
		FramesForwarded: s.stats.framesForwarded,
		BytesForwarded:  s.stats.bytesForwarded,
		SessionsCreated: s.stats.sessionsCreated,
	}
	s.stats.Unlock()
	s.mu.Lock()
	out.ActiveSessions = len(s.sessions)
	s.mu.Unlock()
	return out
}

func (s *Server) bumpAuthOK()   { s.stats.Lock(); s.stats.authOK++; s.stats.Unlock() }
func (s *Server) bumpAuthFail() { s.stats.Lock(); s.stats.authFail++; s.stats.Unlock() }
