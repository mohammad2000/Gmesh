//go:build linux

package l7

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ConntrackReader parses /proc/net/nf_conntrack. The line format is
// space-separated fields; relevant lines look like:
//
//     ipv4     2 tcp      6 431999 ESTABLISHED src=10.250.0.1 dst=10.250.0.20 sport=52060 dport=443 packets=42 bytes=8432 src=10.250.0.20 dst=10.250.0.1 sport=443 dport=52060 packets=40 bytes=14600 [ASSURED] mark=0 use=1
//
// The first src=/dst= pair is the ORIGINAL direction (tx); the second
// is the REPLY direction (rx). If net.netfilter.nf_conntrack_acct=1 is
// set, the packets= / bytes= counters are populated; otherwise they
// are zero and the aggregator's deltas stay flat (flows still show up,
// just without accounting).
type ConntrackReader struct {
	Path string // default /proc/net/nf_conntrack
}

// NewConntrackReader returns a ready reader. Pass a non-empty path to
// override the default (useful in tests that fixture a proc file).
func NewConntrackReader(path string) *ConntrackReader {
	if path == "" {
		path = "/proc/net/nf_conntrack"
	}
	return &ConntrackReader{Path: path}
}

// Name implements Reader.
func (r *ConntrackReader) Name() string { return "conntrack" }

// Read implements Reader by scanning the conntrack file once.
func (r *ConntrackReader) Read() ([]Flow, error) {
	f, err := os.Open(r.Path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", r.Path, err)
	}
	defer f.Close()
	now := time.Now()
	var out []Flow
	scanner := bufio.NewScanner(f)
	// Conntrack lines can be long — bump the default 64 KB buffer.
	scanner.Buffer(make([]byte, 0, 128*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		flow, ok := parseConntrackLine(line)
		if !ok {
			continue
		}
		flow.FirstSeen = now // accurate first-seen is unknown; conntrack
		flow.LastSeen = now  // uses ageing-timer semantics we don't track.
		out = append(out, flow)
	}
	return out, scanner.Err()
}

// parseConntrackLine returns a best-effort Flow extracted from one
// conntrack row. Returns ok=false for lines we cannot interpret.
func parseConntrackLine(line string) (Flow, bool) {
	var f Flow
	// Skip non-ipv4 rows for now (gmesh is ipv4 only today).
	if !strings.HasPrefix(line, "ipv4") {
		return f, false
	}
	fields := strings.Fields(line)
	// Minimal fields:
	//   0: ipv4
	//   1: 2
	//   2: <l4proto>  (tcp|udp|icmp)
	//   3: <protonum>
	//   4: <ttl>
	//   5..: state + kv pairs
	if len(fields) < 6 {
		return f, false
	}
	l4 := fields[2]
	if l4 != "tcp" && l4 != "udp" {
		return f, false
	}
	f.L4Proto = l4

	// Parse all key=value pairs, tracking which src=/dst=/sport=/dport=
	// we see first (ORIGINAL) vs second (REPLY).
	var origSrc, origDst string
	var origSport, origDport uint16
	var replyPackets, replyBytes int64
	var origPackets, origBytes int64
	seenSrc := 0
	seenPackets := 0
	seenBytes := 0
	for _, tok := range fields[5:] {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		k, v := tok[:eq], tok[eq+1:]
		switch k {
		case "src":
			seenSrc++
			if seenSrc == 1 {
				origSrc = v
			}
		case "dst":
			if seenSrc == 1 {
				origDst = v
			}
		case "sport":
			p := parseU16(v)
			if seenSrc == 1 {
				origSport = p
			}
		case "dport":
			p := parseU16(v)
			if seenSrc == 1 {
				origDport = p
			}
		case "packets":
			seenPackets++
			n := parseI64(v)
			if seenPackets == 1 {
				origPackets = n
			} else {
				replyPackets = n
			}
		case "bytes":
			seenBytes++
			n := parseI64(v)
			if seenBytes == 1 {
				origBytes = n
			} else {
				replyBytes = n
			}
		}
	}
	if origSrc == "" || origDst == "" {
		return f, false
	}
	f.SrcIP = origSrc
	f.DstIP = origDst
	f.SrcPort = origSport
	f.DstPort = origDport
	f.TxBytes = origBytes
	f.RxBytes = replyBytes
	_ = origPackets // counters ignored for now; aggregator uses bytes only
	_ = replyPackets
	return f, true
}

func parseU16(s string) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

func parseI64(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

var _ Reader = (*ConntrackReader)(nil)
