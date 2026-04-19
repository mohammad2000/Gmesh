package traversal

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net"
	"time"
)

// ── STUN-assisted hole punch ───────────────────────────────────────────
//
// Both peers know each other's external endpoint (via STUN/backend
// coordination). Each side sends a short burst of UDP probes to the remote
// endpoint. The first outgoing packet creates the local NAT pinhole; once
// both sides have sent, the pinholes are open in both directions and WG
// handshakes can flow.
//
// This strategy works for cone NATs (FullCone, RestrictedCone,
// PortRestrictedCone) and for Open hosts on either side. Symmetric NATs
// fall through to BirthdayStrategy.

// StunHolePunchStrategy sends N probes to the remote's externally-visible
// endpoint and declares success if any reply is heard.
type StunHolePunchStrategy struct {
	Puncher      Puncher
	LocalAddr    *net.UDPAddr  // optional: bind to a specific local port (e.g. WG port)
	NumProbes    int           // default 8
	ProbeSpacing time.Duration // default 100ms
	Timeout      time.Duration // default 2s
	Payload      []byte        // first byte should be nat.MagicByte
	Log          *slog.Logger
}

// Method returns MethodSTUNHolePunch.
func (s *StunHolePunchStrategy) Method() Method { return MethodSTUNHolePunch }

// Attempt runs one hole-punch burst.
func (s *StunHolePunchStrategy) Attempt(ctx context.Context, pc *PeerContext) (*Outcome, error) {
	remote, err := resolveUDP(ctx, pc.RemoteEndpoint)
	if err != nil {
		return &Outcome{Method: MethodSTUNHolePunch, Error: err.Error()}, nil
	}

	cfg := s.config()
	cfg.Remote = remote
	rtt, err := s.Puncher.Punch(ctx, cfg)
	if err != nil {
		return &Outcome{Method: MethodSTUNHolePunch, Error: err.Error()}, nil
	}
	if s.Log != nil {
		s.Log.Debug("stun hole-punch succeeded", "peer_id", pc.PeerID, "rtt_ms", rtt.Milliseconds())
	}
	return &Outcome{Method: MethodSTUNHolePunch, Success: true, LatencyMS: rtt.Milliseconds()}, nil
}

func (s *StunHolePunchStrategy) config() PunchConfig {
	cfg := PunchConfig{
		LocalAddr: s.LocalAddr,
		Count:     s.NumProbes,
		Spacing:   s.ProbeSpacing,
		Timeout:   s.Timeout,
		Payload:   s.Payload,
	}
	if cfg.Count == 0 {
		cfg.Count = 8
	}
	if cfg.Spacing == 0 {
		cfg.Spacing = 100 * time.Millisecond
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}
	return cfg
}

// ── SimultaneousOpen ──────────────────────────────────────────────────
//
// The backend picks a near-future timestamp (fire_at_unix_ms) and sends it
// to both peers. Each peer waits until that moment, then fires probes in
// a tight burst. This defeats NATs that only hold outgoing state for a
// small time window and need the reverse probe to arrive "close in time".

// SimultaneousOpenStrategy waits for fire_at_unix_ms, then punches with
// tight spacing (typically 10ms * 5 probes).
type SimultaneousOpenStrategy struct {
	Puncher      Puncher
	LocalAddr    *net.UDPAddr
	NumProbes    int           // default 5
	ProbeSpacing time.Duration // default 10ms
	Timeout      time.Duration // default 1.5s
	Payload      []byte
	// MaxWait caps the pre-fire sleep (protects against runaway clocks).
	MaxWait time.Duration // default 3s
	Log     *slog.Logger
}

// Method returns MethodSimultaneousOpen.
func (s *SimultaneousOpenStrategy) Method() Method { return MethodSimultaneousOpen }

// Attempt sleeps until fire_at, then runs a tight probe burst.
func (s *SimultaneousOpenStrategy) Attempt(ctx context.Context, pc *PeerContext) (*Outcome, error) {
	remote, err := resolveUDP(ctx, pc.RemoteEndpoint)
	if err != nil {
		return &Outcome{Method: MethodSimultaneousOpen, Error: err.Error()}, nil
	}

	maxWait := s.MaxWait
	if maxWait == 0 {
		maxWait = 3 * time.Second
	}

	if pc.FireAtUnixMS > 0 {
		target := time.UnixMilli(pc.FireAtUnixMS)
		wait := time.Until(target)
		switch {
		case wait > maxWait:
			return &Outcome{Method: MethodSimultaneousOpen, Error: "fire_at too far in future"}, nil
		case wait > 0:
			select {
			case <-ctx.Done():
				return &Outcome{Method: MethodSimultaneousOpen, Error: ctx.Err().Error()}, nil
			case <-time.After(wait):
			}
		}
	}

	cfg := s.config()
	cfg.Remote = remote
	rtt, err := s.Puncher.Punch(ctx, cfg)
	if err != nil {
		return &Outcome{Method: MethodSimultaneousOpen, Error: err.Error()}, nil
	}
	if s.Log != nil {
		s.Log.Debug("simopen punch succeeded", "peer_id", pc.PeerID, "rtt_ms", rtt.Milliseconds())
	}
	return &Outcome{Method: MethodSimultaneousOpen, Success: true, LatencyMS: rtt.Milliseconds()}, nil
}

func (s *SimultaneousOpenStrategy) config() PunchConfig {
	cfg := PunchConfig{
		LocalAddr: s.LocalAddr,
		Count:     s.NumProbes,
		Spacing:   s.ProbeSpacing,
		Timeout:   s.Timeout,
		Payload:   s.Payload,
	}
	if cfg.Count == 0 {
		cfg.Count = 5
	}
	if cfg.Spacing == 0 {
		cfg.Spacing = 10 * time.Millisecond
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 1500 * time.Millisecond
	}
	return cfg
}

// ── Birthday punch ────────────────────────────────────────────────────
//
// Symmetric NATs pick a new external port per (src_port, dst_ip, dst_port)
// tuple, but ports are usually allocated from a contiguous range. The
// birthday attack: probe many destination ports near the last-seen external
// port simultaneously; statistically one probe will hit the right (future)
// port that the remote NAT is about to allocate for the return traffic.
//
// Tailscale calls this "portmap brute" / "birthday paradox". With ~256
// probes and a small allocation window, success rates above 50% are common
// on commodity symmetric NATs.

// BirthdayStrategy probes a range of destination ports near the remote's
// last-seen external port.
type BirthdayStrategy struct {
	Puncher    Puncher
	LocalAddr  *net.UDPAddr
	PortRange  int           // total ports to probe, default 256
	Timeout    time.Duration // default 3s
	Spacing    time.Duration // default 5ms (tight burst)
	Payload    []byte
	Rng        *rand.Rand // nil → nondeterministic
	Log        *slog.Logger
}

// Method returns MethodBirthdayPunch.
func (s *BirthdayStrategy) Method() Method { return MethodBirthdayPunch }

// Attempt sends probes to a shuffled port range centered on the remote port.
func (s *BirthdayStrategy) Attempt(ctx context.Context, pc *PeerContext) (*Outcome, error) {
	remote, err := resolveUDP(ctx, pc.RemoteEndpoint)
	if err != nil {
		return &Outcome{Method: MethodBirthdayPunch, Error: err.Error()}, nil
	}

	portRange := s.PortRange
	if portRange == 0 {
		portRange = 256
	}
	spacing := s.Spacing
	if spacing == 0 {
		spacing = 5 * time.Millisecond
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	center := uint16(remote.Port) //nolint:gosec
	ports := shuffledPortRange(center, portRange, s.Rng)

	// Fire probes to each port in rapid succession, awaiting the first reply.
	cfg := PunchConfig{
		LocalAddr: s.LocalAddr,
		Remote:    remote,
		Count:     1,
		Spacing:   0,
		Timeout:   timeout,
		Payload:   s.Payload,
	}

	// Open one socket, send to every port-varied destination, wait for reply.
	local := cfg.LocalAddr
	if local == nil {
		local = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		return &Outcome{Method: MethodBirthdayPunch, Error: err.Error()}, nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	type replyRes struct {
		rtt time.Duration
		err error
	}
	sent := time.Now()
	done := make(chan replyRes, 1)
	go func() {
		buf := make([]byte, 1500)
		if _, _, err := conn.ReadFromUDP(buf); err != nil {
			done <- replyRes{err: err}
			return
		}
		done <- replyRes{rtt: time.Since(sent)}
	}()

	payload := cfg.Payload
	if len(payload) == 0 {
		payload = []byte{0x7E, 0xB1, 0xB2, 0xB3}
	}
	for i, p := range ports {
		dst := &net.UDPAddr{IP: remote.IP, Port: int(p)}
		if _, err := conn.WriteToUDP(payload, dst); err != nil {
			continue // skip unreachable ports
		}
		if spacing > 0 {
			select {
			case <-ctx.Done():
				return &Outcome{Method: MethodBirthdayPunch, Error: ctx.Err().Error()}, nil
			case r := <-done:
				if r.err != nil {
					return &Outcome{Method: MethodBirthdayPunch, Error: r.err.Error()}, nil
				}
				return &Outcome{Method: MethodBirthdayPunch, Success: true, LatencyMS: r.rtt.Milliseconds()}, nil
			case <-time.After(spacing):
			}
		}
		_ = i
	}

	// Final wait for any reply to arrive.
	select {
	case <-ctx.Done():
		return &Outcome{Method: MethodBirthdayPunch, Error: ctx.Err().Error()}, nil
	case r := <-done:
		if r.err != nil {
			return &Outcome{Method: MethodBirthdayPunch, Error: r.err.Error()}, nil
		}
		return &Outcome{Method: MethodBirthdayPunch, Success: true, LatencyMS: r.rtt.Milliseconds()}, nil
	}
}
