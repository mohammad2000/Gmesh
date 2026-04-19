package traversal

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// fakeProber returns a pre-canned RTT or error.
type fakeProber struct {
	rtt time.Duration
	err error
}

func (f *fakeProber) Probe(_ context.Context, _ string, _ time.Duration) (time.Duration, error) {
	return f.rtt, f.err
}

func TestDirectStrategySuccess(t *testing.T) {
	s := &DirectStrategy{
		Probe: &fakeProber{rtt: 15 * time.Millisecond},
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	out, err := s.Attempt(context.Background(), &PeerContext{PeerID: 1, RemoteEndpoint: "1.2.3.4:51820"})
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if !out.Success {
		t.Errorf("Success = false; error = %q", out.Error)
	}
	if out.Method != MethodDirect {
		t.Errorf("Method = %v; want MethodDirect", out.Method)
	}
	if out.LatencyMS != 15 {
		t.Errorf("LatencyMS = %d; want 15", out.LatencyMS)
	}
}

func TestDirectStrategyFailure(t *testing.T) {
	s := &DirectStrategy{Probe: &fakeProber{err: errors.New("timeout")}}
	out, err := s.Attempt(context.Background(), &PeerContext{PeerID: 1, RemoteEndpoint: "1.2.3.4:51820"})
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if out.Success {
		t.Error("expected Success=false")
	}
	if out.Error != "timeout" {
		t.Errorf("Error = %q; want 'timeout'", out.Error)
	}
}

func TestDirectStrategyEmptyEndpoint(t *testing.T) {
	s := &DirectStrategy{Probe: &fakeProber{rtt: 1}}
	out, _ := s.Attempt(context.Background(), &PeerContext{PeerID: 1})
	if out.Success {
		t.Error("empty endpoint should fail")
	}
}

func TestUDPProberRoundtrip(t *testing.T) {
	// Spin up a tiny echo server.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = conn.WriteToUDP(buf[:n], from)
	}()

	p := &UDPProber{}
	rtt, err := p.Probe(context.Background(), addr.String(), time.Second)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("RTT = %v; want > 0", rtt)
	}
}

func TestEngineLadderRunSuccess(t *testing.T) {
	e := NewEngine()
	e.Register(&DirectStrategy{Probe: &fakeProber{rtt: 5 * time.Millisecond}})
	out, history, err := e.Run(context.Background(), []Method{MethodDirect}, &PeerContext{RemoteEndpoint: "1.2.3.4:51820"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Success {
		t.Fatal("expected success")
	}
	if len(history) != 1 {
		t.Errorf("history len = %d; want 1", len(history))
	}
}

func TestEngineLadderExhausted(t *testing.T) {
	e := NewEngine()
	e.Register(&DirectStrategy{Probe: &fakeProber{err: errors.New("fail")}})
	_, history, err := e.Run(context.Background(), []Method{MethodDirect, MethodUPnPPortMap}, &PeerContext{RemoteEndpoint: "1.2.3.4:51820"})
	if err != ErrExhausted {
		t.Errorf("err = %v; want ErrExhausted", err)
	}
	if len(history) != 2 {
		t.Errorf("history len = %d; want 2", len(history))
	}
	if history[1].Error == "" {
		t.Error("expected error for unregistered strategy")
	}
}
