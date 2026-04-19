package traversal

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"time"
)

// Puncher sends UDP probe bursts and waits for a reply. It's the low-level
// primitive all three hole-punch strategies (STUN-assisted, SimultaneousOpen,
// Birthday) build on top of.
//
// The same Puncher interface is also useful for DirectStrategy's RTT probe.
type Puncher interface {
	// Punch sends `count` probes to `remote` spaced by `spacing`, then waits
	// up to `deadline` for any UDP reply on the same socket. Returns the RTT
	// of the first reply, or an error.
	Punch(ctx context.Context, cfg PunchConfig) (time.Duration, error)
}

// PunchConfig bundles the parameters one punch attempt needs.
type PunchConfig struct {
	LocalAddr *net.UDPAddr // source bind; nil → kernel-picked ephemeral
	Remote    *net.UDPAddr // destination
	Payload   []byte       // first byte should be nat.MagicByte to elicit an echo
	Count     int          // number of probes to send (≥1)
	Spacing   time.Duration // gap between probes (0 → burst)
	Timeout   time.Duration // total window to hear a reply
}

// UDPPuncher is the production implementation.
type UDPPuncher struct{}

// Punch implements the Puncher interface.
func (UDPPuncher) Punch(ctx context.Context, cfg PunchConfig) (time.Duration, error) {
	if cfg.Remote == nil {
		return 0, fmt.Errorf("puncher: remote is nil")
	}
	if cfg.Count < 1 {
		cfg.Count = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}

	local := cfg.LocalAddr
	if local == nil {
		local = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		return 0, fmt.Errorf("bind local: %w", err)
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(cfg.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// Reader goroutine: the first reply wins.
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

	// Send probes.
	payload := cfg.Payload
	if len(payload) == 0 {
		payload = []byte{0x7E, 0xA1, 0xB2, 0xC3}
	}
	for i := 0; i < cfg.Count; i++ {
		if _, err := conn.WriteToUDP(payload, cfg.Remote); err != nil {
			return 0, fmt.Errorf("write probe %d: %w", i, err)
		}
		if i < cfg.Count-1 && cfg.Spacing > 0 {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case r := <-done:
				if r.err != nil {
					return 0, r.err
				}
				return r.rtt, nil
			case <-time.After(cfg.Spacing):
			}
		}
	}

	// Wait for any remaining reply window.
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case r := <-done:
		if r.err != nil {
			return 0, r.err
		}
		return r.rtt, nil
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────

// resolveUDP turns "host:port" into *net.UDPAddr.
func resolveUDP(ctx context.Context, endpoint string) (*net.UDPAddr, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("resolveUDP: endpoint empty")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", endpoint, err)
	}
	addr := conn.RemoteAddr().(*net.UDPAddr)
	_ = conn.Close()
	return addr, nil
}

// shuffledPortRange returns `count` ports near `center` in shuffled order.
// Used by BirthdayStrategy to probe a symmetric NAT's likely port space.
func shuffledPortRange(center uint16, count int, rng *rand.Rand) []uint16 {
	if count < 1 {
		count = 1
	}
	half := count / 2
	lo := int(center) - half
	if lo < 1024 {
		lo = 1024
	}
	hi := lo + count
	if hi > 65535 {
		hi = 65535
		lo = hi - count
		if lo < 1024 {
			lo = 1024
		}
	}
	out := make([]uint16, 0, hi-lo)
	for p := lo; p < hi; p++ {
		out = append(out, uint16(p)) //nolint:gosec
	}
	if rng != nil {
		rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	}
	return out
}
