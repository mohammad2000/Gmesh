//go:build linux

package l7

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ConntrackCLIReader shells out to the `conntrack` binary and parses
// its output. Used as a fallback on modern kernels that no longer
// expose /proc/net/nf_conntrack (it was removed in 5.11; replaced by
// netlink-only NFCT access). The conntrack CLI itself speaks netlink
// under the hood.
//
// Line format (no leading "ipv4" field vs. the /proc file):
//
//     tcp      6 431999 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=52060 dport=443 packets=42 bytes=8432 src=10.0.0.2 dst=10.0.0.1 sport=443 dport=52060 packets=40 bytes=14600 [ASSURED] mark=0 use=1
//
// We reuse parseConntrackLine by prepending the missing "ipv4 2 " so
// the existing parser matches. That's a shortcut — a future change
// will factor the shared parser out cleanly.
type ConntrackCLIReader struct {
	Bin string // default "conntrack"
}

// NewConntrackCLIReader returns a ready CLI-backed reader.
func NewConntrackCLIReader(bin string) *ConntrackCLIReader {
	if bin == "" {
		bin = "conntrack"
	}
	return &ConntrackCLIReader{Bin: bin}
}

// Name implements Reader.
func (r *ConntrackCLIReader) Name() string { return "conntrack-cli" }

// Read implements Reader by running `conntrack -L -o extended` and
// parsing the output.
func (r *ConntrackCLIReader) Read() ([]Flow, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Bin, "-L")
	// stderr may carry a harmless summary line like "conntrack v1.4.6
	// (conntrack-tools): N flow entries have been shown." — capture
	// stdout only.
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run %s: %w", r.Bin, err)
	}
	now := time.Now()
	var flows []Flow
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 0, 128*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		// Prepend the "ipv4 2 " prefix the /proc parser expects; skip
		// ipv6 lines (they'd parse as "tcp 6 …" but the parser's
		// ipv4-only branch would still try to populate SrcIP with a
		// colon-bearing value). Detect by the leading token.
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" {
			continue
		}
		// Our parser only accepts tcp/udp first field (after ipv4 2),
		// so accept those here too.
		first := strings.Fields(trimmed)
		if len(first) == 0 {
			continue
		}
		if first[0] != "tcp" && first[0] != "udp" {
			continue
		}
		f, ok := parseConntrackLine("ipv4 2 " + trimmed)
		if !ok {
			continue
		}
		// Filter ipv6 masquerading as ipv4 by checking colons in IPs.
		if strings.Contains(f.SrcIP, ":") || strings.Contains(f.DstIP, ":") {
			continue
		}
		f.FirstSeen = now
		f.LastSeen = now
		flows = append(flows, f)
	}
	return flows, scanner.Err()
}

var _ Reader = (*ConntrackCLIReader)(nil)
