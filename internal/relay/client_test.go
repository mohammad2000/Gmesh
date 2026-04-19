package relay

import (
	"context"
	"net"
	"testing"
	"time"
)

// tinyRelay is a minimal in-process implementation of gmesh-relay used
// only by these tests. Accepts any auth token (ignores HMAC) and pairs
// the first two senders.
type tinyRelay struct {
	conn  *net.UDPConn
	peers [2]*net.UDPAddr
}

func startTinyRelay(t *testing.T) *tinyRelay {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	tr := &tinyRelay{conn: conn}
	go func() {
		buf := make([]byte, MaxFrameSize)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			typ, payload, err := DecodeFrame(buf[:n])
			if err != nil {
				continue
			}
			switch typ {
			case FrameAUTH:
				// Accept any; remember sender slot.
				slot := -1
				for i, p := range tr.peers {
					if p != nil && p.IP.Equal(from.IP) && p.Port == from.Port {
						slot = i
						break
					}
				}
				if slot == -1 {
					for i, p := range tr.peers {
						if p == nil {
							tr.peers[i] = from
							slot = i
							break
						}
					}
				}
				_, _ = conn.WriteToUDP(EncodeFrame(FrameAUTHOK, nil), from)
			case FrameDATA:
				// Forward to the other peer.
				for _, p := range tr.peers {
					if p == nil {
						continue
					}
					if p.IP.Equal(from.IP) && p.Port == from.Port {
						continue
					}
					_, _ = conn.WriteToUDP(EncodeFrame(FrameDATA, payload), p)
				}
			case FramePING:
				_, _ = conn.WriteToUDP(EncodeFrame(FramePONG, nil), from)
			}
		}
	}()
	return tr
}

func (r *tinyRelay) Addr() string { return r.conn.LocalAddr().String() }
func (r *tinyRelay) Close()       { _ = r.conn.Close() }

func TestSessionAuthAndForward(t *testing.T) {
	tr := startTinyRelay(t)
	defer tr.Close()

	secret := []byte("s")
	sid := [16]byte{0xAA}
	tok1 := SignToken(secret, sid, 1)
	tok2 := SignToken(secret, sid, 2)

	// Client 1: pretends to be WireGuard on an ephemeral port.
	wg1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("wg1 listen: %v", err)
	}
	defer wg1.Close()

	wg2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("wg2 listen: %v", err)
	}
	defer wg2.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s1, err := DialSession(ctx, Config{
		PeerID:     1,
		SessionID:  sid,
		AuthToken:  tok1,
		RelayAddr:  tr.Addr(),
		WGEndpoint: wg1.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatalf("DialSession 1: %v", err)
	}
	defer s1.Close()

	s2, err := DialSession(ctx, Config{
		PeerID:     2,
		SessionID:  sid,
		AuthToken:  tok2,
		RelayAddr:  tr.Addr(),
		WGEndpoint: wg2.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatalf("DialSession 2: %v", err)
	}
	defer s2.Close()

	// Simulate real WG behavior: wg1 sends from its listen socket to
	// s1's local forwarder. Reading replies happens on the same socket.
	if _, err := wg1.WriteToUDP([]byte("hello from peer 1"), s1.LocalEndpoint()); err != nil {
		t.Fatalf("wg1 write: %v", err)
	}

	_ = wg2.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := wg2.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("wg2 read: %v", err)
	}
	if string(buf[:n]) != "hello from peer 1" {
		t.Errorf("payload = %q; want hello", string(buf[:n]))
	}

	// Reverse direction: wg2 → wg1.
	if _, err := wg2.WriteToUDP([]byte("and hi back"), s2.LocalEndpoint()); err != nil {
		t.Fatalf("wg2 write: %v", err)
	}
	_ = wg1.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = wg1.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("wg1 read: %v", err)
	}
	if string(buf[:n]) != "and hi back" {
		t.Errorf("reverse payload = %q", string(buf[:n]))
	}

	// Stats sanity.
	st1 := s1.Stats()
	if st1.TxFrames == 0 || st1.RxFrames == 0 {
		t.Errorf("stats empty: %+v", st1)
	}
}

func TestSessionAuthFailClosesConn(t *testing.T) {
	// A tinyRelay that always rejects auth.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, MaxFrameSize)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			typ, _, _ := DecodeFrame(buf[:n])
			if typ == FrameAUTH {
				_, _ = conn.WriteToUDP(EncodeFrame(FrameAUTHFail, []byte("nope")), from)
			}
		}
	}()

	wg, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("wg listen: %v", err)
	}
	defer wg.Close()

	_, err = DialSession(context.Background(), Config{
		PeerID:     1,
		AuthToken:  SignToken([]byte("x"), [16]byte{}, 1),
		RelayAddr:  conn.LocalAddr().String(),
		WGEndpoint: wg.LocalAddr().(*net.UDPAddr),
	})
	if err == nil {
		t.Fatal("expected auth fail error")
	}
}
