package traversal

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakePuncher returns pre-canned results, tracking how many calls + what
// destination ports were used.
type fakePuncher struct {
	mu        sync.Mutex
	calls     int
	rtt       time.Duration
	err       error
	lastCfg   PunchConfig
	delay     time.Duration // simulate punching duration
	successAt int           // success after N calls (for retry tests)
}

func (f *fakePuncher) Punch(ctx context.Context, cfg PunchConfig) (time.Duration, error) {
	f.mu.Lock()
	f.calls++
	f.lastCfg = cfg
	n := f.calls
	f.mu.Unlock()

	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(f.delay):
		}
	}
	if f.successAt > 0 && n < f.successAt {
		return 0, errors.New("not yet")
	}
	return f.rtt, f.err
}

func (f *fakePuncher) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestStunHolePunchSuccess(t *testing.T) {
	s := &StunHolePunchStrategy{Puncher: &fakePuncher{rtt: 20 * time.Millisecond}}
	out, err := s.Attempt(context.Background(), &PeerContext{PeerID: 1, RemoteEndpoint: "1.2.3.4:51820"})
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if !out.Success {
		t.Fatalf("expected success; error = %q", out.Error)
	}
	if out.Method != MethodSTUNHolePunch {
		t.Errorf("method = %v; want STUNHolePunch", out.Method)
	}
	if out.LatencyMS != 20 {
		t.Errorf("latency = %d; want 20", out.LatencyMS)
	}
}

func TestStunHolePunchFailure(t *testing.T) {
	s := &StunHolePunchStrategy{Puncher: &fakePuncher{err: errors.New("no reply")}}
	out, _ := s.Attempt(context.Background(), &PeerContext{PeerID: 1, RemoteEndpoint: "1.2.3.4:51820"})
	if out.Success {
		t.Error("expected failure")
	}
}

func TestStunHolePunchBadEndpoint(t *testing.T) {
	s := &StunHolePunchStrategy{Puncher: &fakePuncher{}}
	out, _ := s.Attempt(context.Background(), &PeerContext{PeerID: 1, RemoteEndpoint: ""})
	if out.Success {
		t.Error("empty endpoint should fail")
	}
}

func TestStunHolePunchConfigDefaults(t *testing.T) {
	fp := &fakePuncher{rtt: 5 * time.Millisecond}
	s := &StunHolePunchStrategy{Puncher: fp}
	_, _ = s.Attempt(context.Background(), &PeerContext{RemoteEndpoint: "127.0.0.1:9"})
	cfg := fp.lastCfg
	if cfg.Count != 8 {
		t.Errorf("default Count = %d; want 8", cfg.Count)
	}
	if cfg.Spacing != 100*time.Millisecond {
		t.Errorf("default Spacing = %v; want 100ms", cfg.Spacing)
	}
	if cfg.Timeout != 2*time.Second {
		t.Errorf("default Timeout = %v; want 2s", cfg.Timeout)
	}
}

func TestSimultaneousOpenWaitsForFireAt(t *testing.T) {
	fp := &fakePuncher{rtt: 10 * time.Millisecond}
	s := &SimultaneousOpenStrategy{Puncher: fp, MaxWait: time.Second}
	fireAt := time.Now().Add(200 * time.Millisecond)
	start := time.Now()
	_, _ = s.Attempt(context.Background(), &PeerContext{
		RemoteEndpoint: "127.0.0.1:9",
		FireAtUnixMS:   fireAt.UnixMilli(),
	})
	elapsed := time.Since(start)
	if elapsed < 150*time.Millisecond {
		t.Errorf("returned too early: %v; expected ≥ 200ms wait", elapsed)
	}
	if fp.Calls() != 1 {
		t.Errorf("Puncher.Punch calls = %d; want 1", fp.Calls())
	}
}

func TestSimultaneousOpenRefusesFarFutureFireAt(t *testing.T) {
	s := &SimultaneousOpenStrategy{Puncher: &fakePuncher{}, MaxWait: 500 * time.Millisecond}
	fireAt := time.Now().Add(10 * time.Second)
	out, _ := s.Attempt(context.Background(), &PeerContext{
		RemoteEndpoint: "127.0.0.1:9",
		FireAtUnixMS:   fireAt.UnixMilli(),
	})
	if out.Success {
		t.Error("expected failure for fire_at > MaxWait")
	}
}

func TestSimultaneousOpenPastFireAtRunsImmediately(t *testing.T) {
	fp := &fakePuncher{rtt: 5 * time.Millisecond}
	s := &SimultaneousOpenStrategy{Puncher: fp}
	past := time.Now().Add(-5 * time.Second).UnixMilli()
	start := time.Now()
	_, _ = s.Attempt(context.Background(), &PeerContext{
		RemoteEndpoint: "127.0.0.1:9",
		FireAtUnixMS:   past,
	})
	if time.Since(start) > 500*time.Millisecond {
		t.Errorf("past fire_at shouldn't block, took %v", time.Since(start))
	}
}

func TestBirthdayStrategyBadEndpoint(t *testing.T) {
	s := &BirthdayStrategy{Puncher: &fakePuncher{}}
	out, _ := s.Attempt(context.Background(), &PeerContext{RemoteEndpoint: ""})
	if out.Success {
		t.Error("empty endpoint should fail")
	}
}

func TestBirthdayStrategyTouchesPortRange(t *testing.T) {
	// Start a real echo server on an ephemeral port; Birthday should find it
	// if we center the port range near that port.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	// Echo.
	go func() {
		buf := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], from)
		}
	}()

	s := &BirthdayStrategy{
		Puncher:   UDPPuncher{},
		PortRange: 32,
		Timeout:   2 * time.Second,
		Spacing:   1 * time.Millisecond,
		Rng:       rand.New(rand.NewPCG(1, 2)),
	}
	// Center the range exactly on the echo server so it's found with
	// probability 1 regardless of shuffle.
	endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	out, _ := s.Attempt(context.Background(), &PeerContext{RemoteEndpoint: endpoint})
	if !out.Success {
		t.Fatalf("expected success; error = %q", out.Error)
	}
	if out.LatencyMS < 0 {
		t.Errorf("bad latency = %d", out.LatencyMS)
	}
}

func TestShuffledPortRangeSize(t *testing.T) {
	ports := shuffledPortRange(50000, 256, rand.New(rand.NewPCG(42, 42)))
	if len(ports) != 256 {
		t.Errorf("len = %d; want 256", len(ports))
	}
	// Should contain the center.
	seen := false
	for _, p := range ports {
		if p == 50000 {
			seen = true
			break
		}
	}
	if !seen {
		t.Error("center port missing from range")
	}
}

func TestShuffledPortRangeClampsAtEdges(t *testing.T) {
	ports := shuffledPortRange(100, 256, nil)
	for _, p := range ports {
		if p < 1024 {
			t.Errorf("port %d < 1024", p)
		}
	}
	ports = shuffledPortRange(65000, 2048, nil)
	for _, p := range ports {
		if p < 1024 || p > 65535 {
			t.Errorf("port %d out of bounds", p)
		}
	}
}

func TestUDPPuncherRealEcho(t *testing.T) {
	// Echo server.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 1500)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = conn.WriteToUDP(buf[:n], from)
	}()

	p := UDPPuncher{}
	rtt, err := p.Punch(context.Background(), PunchConfig{
		Remote:  addr,
		Count:   3,
		Spacing: 5 * time.Millisecond,
		Timeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Punch: %v", err)
	}
	if rtt <= 0 {
		t.Errorf("rtt = %v; want > 0", rtt)
	}
}
