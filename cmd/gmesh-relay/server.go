// Package main (cmd/gmesh-relay) is the UDP relay.
//
// A session is a pair of WireGuard keys (relay.PairSessionID). Each side
// authenticates with its own credential and takes the slot of its own key;
// DATA from one slot goes to the other. A slot moves to a new source address
// only when the same key authenticates again from there (NAT rebinding), so
// nobody can take over someone else's slot. Sessions idle out.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/relay"
	"github.com/mohammad2000/Gmesh/internal/stunlite"
)

// sink is where a client's frames go back to: a UDP source address, or a
// WebSocket connection (relay over TCP/443 for networks that block UDP).
// It is comparable, so it doubles as the lookup key.
type sink struct {
	addr netip.AddrPort // UDP
	ws   *wsClient      // WebSocket
}

func (k sink) valid() bool { return k.addr.IsValid() || k.ws != nil }

type slot struct {
	key      relay.Key
	addr     sink
	lastSeen time.Time
	sess     *Session
}

// Session holds the two slots of one key pair.
type Session struct {
	id    [16]byte
	slots [2]*slot // indexed by which key sorts first
	keys  [2]relay.Key
}

func (s *Session) other(sl *slot) *slot {
	if s.slots[0] == sl {
		return s.slots[1]
	}
	return s.slots[0]
}

// Server is the relay UDP server.
type Server struct {
	Addr           string
	Secret         []byte
	SessionIdleTTL time.Duration // default 90s; clients refresh every 20s
	MaxPerKey      int           // sessions one key may hold; default 2048
	Log            *slog.Logger

	mu       sync.Mutex
	sessions map[[16]byte]*Session
	byAddr   map[sink]*slot
	perKey   map[relay.Key]int
	conn     *net.UDPConn

	stats struct {
		authOK, authFail, framesForwarded, bytesForwarded, sessionsCreated, dropped, stun uint64
	}
}

// NewServer builds a Server with defaults applied.
func NewServer(addr string, secret []byte, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		Addr: addr, Secret: secret, SessionIdleTTL: 90 * time.Second, MaxPerKey: 2048, Log: log,
		sessions: map[[16]byte]*Session{}, byAddr: map[sink]*slot{}, perKey: map[relay.Key]int{},
	}
}

// ListenAndServe binds the UDP socket and forwards until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	laddr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)
	s.conn = conn
	defer func() { _ = conn.Close() }()
	s.Log.Info("gmesh-relay listening", "addr", conn.LocalAddr().String())

	go s.janitor(ctx)
	go func() { <-ctx.Done(); _ = conn.Close() }()

	buf := make([]byte, relay.MaxFrameSize)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			s.Log.Warn("read error", "error", err)
			continue
		}
		s.handle(sink{addr: netip.AddrPortFrom(from.Addr().Unmap(), from.Port())}, buf[:n])
	}
}

// send delivers one frame to a sink.
func (s *Server) send(to sink, frame []byte) (int, error) {
	if to.ws != nil {
		return len(frame), to.ws.send(frame)
	}
	return s.conn.WriteToUDPAddrPort(frame, to.addr)
}

func (s *Server) handle(from sink, buf []byte) {
	if from.addr.IsValid() {
		if tx, ok := stunlite.ParseRequest(buf); ok {
			s.mu.Lock()
			s.stats.stun++
			s.mu.Unlock()
			_, _ = s.conn.WriteToUDPAddrPort(stunlite.Response(tx, from.addr), from.addr)
			return
		}
	}
	typ, payload, err := relay.DecodeFrame(buf)
	if err != nil {
		return
	}
	switch typ {
	case relay.FrameAUTH:
		s.handleAuth(from, payload)
	case relay.FrameDATA, relay.FramePeerInfo:
		s.handleData(from, typ, payload)
	case relay.FramePING:
		s.mu.Lock()
		sl := s.byAddr[from]
		if sl != nil {
			sl.lastSeen = time.Now()
		}
		s.mu.Unlock()
		if sl != nil {
			_, _ = s.send(from, relay.EncodeFrame(relay.FramePONG, nil))
		}
	}
}

func (s *Server) handleAuth(from sink, payload []byte) {
	a, err := relay.DecodeAuth(payload)
	if err == nil {
		err = a.Cred.Verify(s.Secret, time.Now())
	}
	if err != nil {
		s.mu.Lock()
		s.stats.authFail++
		s.mu.Unlock()
		reason := "bad credential"
		if errors.Is(err, relay.ErrExpired) {
			reason = "credential expired"
		}
		_, _ = s.send(from, relay.EncodeFrame(relay.FrameAUTHFail, []byte(reason)))
		return
	}
	self := a.Cred.PublicKey
	id := relay.PairSessionID(self, a.Peer)
	now := time.Now()

	s.mu.Lock()
	sess := s.sessions[id]
	if sess == nil {
		if s.perKey[self] >= s.MaxPerKey {
			s.stats.authFail++
			s.mu.Unlock()
			_, _ = s.send(from, relay.EncodeFrame(relay.FrameAUTHFail, []byte("too many sessions")))
			return
		}
		sess = &Session{id: id}
		if string(self[:]) < string(a.Peer[:]) {
			sess.keys = [2]relay.Key{self, a.Peer}
		} else {
			sess.keys = [2]relay.Key{a.Peer, self}
		}
		s.sessions[id] = sess
		s.perKey[sess.keys[0]]++
		s.perKey[sess.keys[1]]++
		s.stats.sessionsCreated++
	}
	i := 0
	if sess.keys[1] == self {
		i = 1
	}
	sl := sess.slots[i]
	if sl == nil {
		sl = &slot{key: self, sess: sess}
		sess.slots[i] = sl
	}
	if sl.addr != from {
		// The same key from a new address: NAT rebinding or a restart. The
		// address may have belonged to another slot before; it's ours now.
		if sl.addr.valid() && s.byAddr[sl.addr] == sl {
			delete(s.byAddr, sl.addr)
		}
		if old := s.byAddr[from]; old != nil && old != sl {
			old.addr = sink{}
		}
		sl.addr = from
		s.byAddr[from] = sl
	}
	sl.lastSeen = now
	s.stats.authOK++
	s.mu.Unlock()
	_, _ = s.send(from, relay.EncodeFrame(relay.FrameAUTHOK, nil))
}

func (s *Server) handleData(from sink, typ relay.FrameType, payload []byte) {
	s.mu.Lock()
	sl := s.byAddr[from]
	if sl == nil {
		s.stats.dropped++
		s.mu.Unlock()
		return
	}
	sl.lastSeen = time.Now()
	o := sl.sess.other(sl)
	if o == nil || !o.addr.valid() {
		s.stats.dropped++
		s.mu.Unlock()
		return
	}
	to := o.addr
	s.mu.Unlock()

	n, err := s.send(to, relay.EncodeFrame(typ, payload))
	if err != nil {
		return
	}
	s.mu.Lock()
	s.stats.framesForwarded++
	s.stats.bytesForwarded += uint64(n)
	s.mu.Unlock()
}

// forget drops a WebSocket client's slot when its connection ends.
func (s *Server) forget(k sink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sl := s.byAddr[k]; sl != nil {
		delete(s.byAddr, k)
		sl.addr = sink{}
	}
}

// janitor drops slots and sessions nobody refreshed within the TTL, and logs
// the counters once a minute.
func (s *Server) janitor(ctx context.Context) {
	ttl := s.SessionIdleTTL
	if ttl <= 0 {
		ttl = 90 * time.Second
	}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	var ticks int
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			for id, sess := range s.sessions {
				live := 0
				for i, sl := range sess.slots {
					if sl == nil {
						continue
					}
					if now.Sub(sl.lastSeen) > ttl {
						if s.byAddr[sl.addr] == sl {
							delete(s.byAddr, sl.addr)
						}
						sess.slots[i] = nil
						continue
					}
					live++
				}
				if live == 0 {
					delete(s.sessions, id)
					for _, k := range sess.keys {
						if s.perKey[k]--; s.perKey[k] <= 0 {
							delete(s.perKey, k)
						}
					}
				}
			}
			s.mu.Unlock()
			if ticks++; ticks%4 == 0 {
				st := s.Stats()
				s.Log.Info("relay stats", "sessions", st.ActiveSessions, "paired", st.PairedSessions, "auth_ok", st.AuthOK,
					"auth_fail", st.AuthFail, "frames", st.FramesForwarded, "bytes", st.BytesForwarded, "dropped", st.Dropped, "stun", st.STUN)
			}
		}
	}
}

// Stats is a read-only snapshot of relay counters.
type Stats struct {
	AuthOK, AuthFail, FramesForwarded, BytesForwarded, SessionsCreated, Dropped, STUN uint64
	ActiveSessions, PairedSessions                                                    int
}

// Stats returns current counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Stats{
		AuthOK: s.stats.authOK, AuthFail: s.stats.authFail, FramesForwarded: s.stats.framesForwarded,
		BytesForwarded: s.stats.bytesForwarded, SessionsCreated: s.stats.sessionsCreated, Dropped: s.stats.dropped, STUN: s.stats.stun,
		ActiveSessions: len(s.sessions),
	}
	for _, sess := range s.sessions {
		if sess.slots[0] != nil && sess.slots[1] != nil {
			out.PairedSessions++
		}
	}
	return out
}
