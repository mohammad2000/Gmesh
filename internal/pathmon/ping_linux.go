//go:build linux

package pathmon

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LinuxPingProber shells out to `ping -c 1 -W <timeout>`. Requires the
// iputils-ping package and either CAP_NET_RAW or ping's set-uid bit.
//
// Why shell ping instead of raw ICMP sockets: matches what operators see
// from the same box, requires no additional capabilities beyond what a
// systemd service usually already has, and stays honest about Linux ICMP
// rate-limits (net.ipv4.icmp_ratelimit) which matter for failure modes.
type LinuxPingProber struct {
	PingBin string // default "ping"
}

// NewLinuxPingProber returns a ready prober.
func NewLinuxPingProber() *LinuxPingProber {
	return &LinuxPingProber{PingBin: "ping"}
}

// Name returns "ping".
func (p *LinuxPingProber) Name() string { return "ping" }

// rttRE extracts the RTT from iputils output.
//   "64 bytes from 10.250.0.20: icmp_seq=1 ttl=64 time=2.80 ms"
var rttRE = regexp.MustCompile(`time=([0-9.]+)\s*ms`)

// Probe runs one ping.
func (p *LinuxPingProber) Probe(ctx context.Context, t Target) Result {
	now := time.Now()
	bin := p.PingBin
	if bin == "" {
		bin = "ping"
	}
	// -n: numeric, -c 1: one packet, -W 1: 1-second timeout, -q: quiet-ish.
	// We don't use -q because we need the time=... line.
	cmd := exec.CommandContext(ctx, bin, "-n", "-c", "1", "-W", "1", t.MeshIP)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return Result{Up: false, When: now, Error: trimErr(out, err)}
	}
	m := rttRE.FindStringSubmatch(string(out))
	if m == nil {
		return Result{Up: false, When: now, Error: "no RTT in ping output"}
	}
	ms, perr := strconv.ParseFloat(m[1], 64)
	if perr != nil {
		return Result{Up: false, When: now, Error: "bad RTT: " + perr.Error()}
	}
	return Result{
		Up:   true,
		RTT:  time.Duration(ms * float64(time.Millisecond)),
		When: now,
	}
}

func trimErr(out []byte, err error) string {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return err.Error()
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

var _ Prober = (*LinuxPingProber)(nil)
