package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/mohammad2000/Gmesh/internal/relay"
)

func TestServerPairsAndForwards(t *testing.T) {
	secret := []byte("integration-secret")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Start the real gmesh-relay.
	srv := NewServer("127.0.0.1:0", secret, log)
	// Grab listener port by binding before ListenAndServe.
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.Addr = conn.LocalAddr().String()
	_ = conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	time.Sleep(100 * time.Millisecond) // let it bind

	exp := time.Now().Add(time.Hour)
	kA, kB := relay.Key{1}, relay.Key{2}
	authA := relay.Auth{Cred: relay.IssueCredential(secret, kA, exp), Peer: kB}
	authB := relay.Auth{Cred: relay.IssueCredential(secret, kB, exp), Peer: kA}

	// Two WG stand-ins listening on different ephemeral ports.
	wgA, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer wgA.Close()
	wgB, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer wgB.Close()

	sA, err := relay.DialSession(ctx, relay.Config{
		Auth:       authA,
		RelayAddr:  srv.Addr,
		WGEndpoint: wgA.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatalf("DialSession A: %v", err)
	}
	defer sA.Close()
	sB, err := relay.DialSession(ctx, relay.Config{
		Auth:       authB,
		RelayAddr:  srv.Addr,
		WGEndpoint: wgB.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatalf("DialSession B: %v", err)
	}
	defer sB.Close()

	// Give the server a moment to see both AUTHs.
	time.Sleep(50 * time.Millisecond)

	// Round trip A → B.
	if _, err := wgA.WriteToUDP([]byte("ping"), sA.LocalEndpoint()); err != nil {
		t.Fatalf("wgA write: %v", err)
	}
	buf := make([]byte, 1500)
	_ = wgB.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := wgB.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("wgB read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Errorf("A→B payload = %q", string(buf[:n]))
	}

	// Round trip B → A.
	if _, err := wgB.WriteToUDP([]byte("pong"), sB.LocalEndpoint()); err != nil {
		t.Fatalf("wgB write: %v", err)
	}
	_ = wgA.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = wgA.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("wgA read: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Errorf("B→A payload = %q", string(buf[:n]))
	}

	// Assert stats on the server. The counters are bumped after the frame
	// is sent on, so the receiver can see the packet first — wait briefly.
	st := srv.Stats()
	for deadline := time.Now().Add(time.Second); st.FramesForwarded < 2 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		st = srv.Stats()
	}
	if st.AuthOK < 2 {
		t.Errorf("AuthOK = %d; want ≥ 2", st.AuthOK)
	}
	if st.FramesForwarded < 2 {
		t.Errorf("FramesForwarded = %d; want ≥ 2", st.FramesForwarded)
	}
	if st.ActiveSessions < 1 {
		t.Errorf("ActiveSessions = %d; want ≥ 1", st.ActiveSessions)
	}
}

func TestServerRejectsBadAuth(t *testing.T) {
	secret := []byte("good")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer("127.0.0.1:0", secret, log)
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	srv.Addr = conn.LocalAddr().String()
	conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// Wrong secret → HMAC mismatch.
	wg, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer wg.Close()
	bad := relay.Auth{Cred: relay.IssueCredential([]byte("bad"), relay.Key{1}, time.Now().Add(time.Hour)), Peer: relay.Key{2}}
	_, err := relay.DialSession(ctx, relay.Config{
		Auth:       bad,
		RelayAddr:  srv.Addr,
		WGEndpoint: wg.LocalAddr().(*net.UDPAddr),
	})
	if err == nil {
		t.Fatal("expected auth failure")
	}

	time.Sleep(50 * time.Millisecond)
	st := srv.Stats()
	if st.AuthFail < 1 {
		t.Errorf("AuthFail = %d; want ≥ 1", st.AuthFail)
	}
}

// A key can't take another key's slot, and a third key can't join a pair.
func TestServerSlotsBelongToKeys(t *testing.T) {
	secret := []byte("k")
	srv := NewServer("127.0.0.1:0", secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	srv.Addr = c.LocalAddr().String()
	c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	time.Sleep(100 * time.Millisecond)

	exp := time.Now().Add(time.Hour)
	kA, kB, kE := relay.Key{1}, relay.Key{2}, relay.Key{9}
	wgA, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	wgB, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	wgE, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer wgA.Close()
	defer wgB.Close()
	defer wgE.Close()
	dial := func(self, peer relay.Key, wg *net.UDPConn) *relay.Session {
		s, err := relay.DialSession(ctx, relay.Config{Auth: relay.Auth{Cred: relay.IssueCredential(secret, self, exp), Peer: peer},
			RelayAddr: srv.Addr, WGEndpoint: wg.LocalAddr().(*net.UDPAddr)})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return s
	}
	sA := dial(kA, kB, wgA)
	defer sA.Close()
	sB := dial(kB, kA, wgB)
	defer sB.Close()
	// E holds a valid credential of its own and asks for A↔B's peer B: it
	// lands in the E↔B session, not in A↔B.
	sE := dial(kE, kB, wgE)
	defer sE.Close()
	time.Sleep(50 * time.Millisecond)

	_, _ = wgA.WriteToUDP([]byte("for B"), sA.LocalEndpoint())
	buf := make([]byte, 64)
	_ = wgB.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _, err := wgB.ReadFromUDP(buf); err != nil || string(buf[:n]) != "for B" {
		t.Fatalf("B didn't get A's packet: %v", err)
	}
	_ = wgE.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := wgE.ReadFromUDP(buf); err == nil {
		t.Fatal("E received traffic of the A↔B pair")
	}
	if st := srv.Stats(); st.ActiveSessions != 2 || st.PairedSessions != 1 {
		t.Fatalf("sessions %+v", st)
	}
}

// One side behind a UDP-blocking network uses the WebSocket; the other
// stays on UDP. Same session, packets both ways.
func TestServerMixedUDPAndWebSocket(t *testing.T) {
	secret := []byte("mix")
	srv := NewServer("127.0.0.1:0", secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	srv.Addr = c.LocalAddr().String()
	c.Close()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	wsAddr := l.Addr().String()
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	go func() { _ = srv.ServeWS(ctx, wsAddr) }()
	time.Sleep(150 * time.Millisecond)

	exp := time.Now().Add(time.Hour)
	kA, kB := relay.Key{1}, relay.Key{2}
	wgA, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	wgB, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer wgA.Close()
	defer wgB.Close()
	sA, err := relay.DialSession(ctx, relay.Config{Auth: relay.Auth{Cred: relay.IssueCredential(secret, kA, exp), Peer: kB},
		RelayAddr: srv.Addr, WGEndpoint: wgA.LocalAddr().(*net.UDPAddr)})
	if err != nil {
		t.Fatalf("udp side: %v", err)
	}
	defer sA.Close()
	sB, err := relay.DialSession(ctx, relay.Config{Auth: relay.Auth{Cred: relay.IssueCredential(secret, kB, exp), Peer: kA},
		RelayAddr: "ws://" + wsAddr + WSPath, WGEndpoint: wgB.LocalAddr().(*net.UDPAddr)})
	if err != nil {
		t.Fatalf("websocket side: %v", err)
	}
	defer sB.Close()
	time.Sleep(50 * time.Millisecond)

	buf := make([]byte, 64)
	_, _ = wgA.WriteToUDP([]byte("udp→ws"), sA.LocalEndpoint())
	_ = wgB.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _, err := wgB.ReadFromUDP(buf); err != nil || string(buf[:n]) != "udp→ws" {
		t.Fatalf("A→B: %v", err)
	}
	_, _ = wgB.WriteToUDP([]byte("ws→udp"), sB.LocalEndpoint())
	_ = wgA.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _, err := wgA.ReadFromUDP(buf); err != nil || string(buf[:n]) != "ws→udp" {
		t.Fatalf("B→A: %v", err)
	}
	if !sB.Healthy() {
		t.Error("websocket session not healthy")
	}
	// A dropped WebSocket frees its slot.
	sB.Close()
	time.Sleep(100 * time.Millisecond)
	srv.mu.Lock()
	n := len(srv.byAddr)
	srv.mu.Unlock()
	if n != 1 {
		t.Errorf("byAddr has %d entries after the websocket closed, want 1", n)
	}
}
