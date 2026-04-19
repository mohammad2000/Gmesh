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

	sid := [16]byte{0xDE, 0xAD, 0xBE, 0xEF}
	tokA := relay.SignToken(secret, sid, 100)
	tokB := relay.SignToken(secret, sid, 200)

	// Two WG stand-ins listening on different ephemeral ports.
	wgA, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer wgA.Close()
	wgB, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer wgB.Close()

	sA, err := relay.DialSession(ctx, relay.Config{
		PeerID:     100,
		SessionID:  sid,
		AuthToken:  tokA,
		RelayAddr:  srv.Addr,
		WGEndpoint: wgA.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatalf("DialSession A: %v", err)
	}
	defer sA.Close()
	sB, err := relay.DialSession(ctx, relay.Config{
		PeerID:     200,
		SessionID:  sid,
		AuthToken:  tokB,
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

	// Assert stats on the server.
	st := srv.Stats()
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
	badTok := relay.SignToken([]byte("bad"), [16]byte{}, 1)
	_, err := relay.DialSession(ctx, relay.Config{
		PeerID:     1,
		AuthToken:  badTok,
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
