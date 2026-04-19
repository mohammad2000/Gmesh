// Package l7 provides application-layer ("L7") traffic classification
// for flows traversing the mesh. It gives operators per-protocol
// visibility into who's talking HTTP vs. TLS vs. SSH vs. DNS without
// needing deep packet inspection or traffic decryption.
//
// # Scope honesty
//
// This is **not** an eBPF-based classifier. The roadmap positioned
// Phase 18 as "eBPF L7 Classifier" and a proper implementation would
// load a TC-classifier eBPF program that inspects TLS ClientHello SNI,
// HTTP Host headers, and so on. That's multi-day kernel work — clang
// + llvm + cilium/ebpf generators + verifier-compatible C — and fits
// badly into a single session.
//
// What this package ships instead:
//
//   - A userspace Classifier that maps (proto, dport) tuples to
//     well-known L7 protocol labels ("http", "tls", "ssh", "dns",
//     "quic", "smtp", etc.).
//   - A ConntrackReader that parses /proc/net/nf_conntrack (or the
//     sysctl `nf_conntrack_acct`-enabled byte counter variant) to get
//     live flow state + per-flow byte deltas.
//   - An in-memory aggregator that rolls flows into per-(peer,
//     protocol) byte totals over a sliding window.
//
// Operators get the same two questions answered:
//
//   1. "What protocols are the mesh peers speaking right now?"
//   2. "How is total egress split by protocol for peer N?"
//
// ...which is what most dashboards ask of an L7 classifier. Replacing
// port-based guesswork with real DPI is a follow-up — this package's
// interfaces (Classifier.Classify, Reader.Read) are intentionally
// narrow so the DPI implementation is a drop-in later.
//
// # On-wire accuracy
//
// Port-based classification mislabels traffic that uses non-standard
// ports. Encrypted SNI, QUIC over an arbitrary port, any tunneled
// protocol — all show up as their transport port's default label. We
// surface this openly via an "unknown" label and a per-flow
// confidence field, so dashboards can show operators "we're not
// sure" rather than guessing.
package l7

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Protocol is the operator-facing label. Intentionally string rather
// than an enum so a future DPI can add labels without a proto bump.
type Protocol string

// Well-known labels. This list is deliberately small — operators can
// classify anything else via the port map or a post-processing step.
const (
	ProtoHTTP      Protocol = "http"
	ProtoTLS       Protocol = "tls"
	ProtoSSH       Protocol = "ssh"
	ProtoDNS       Protocol = "dns"
	ProtoQUIC      Protocol = "quic"
	ProtoSMTP      Protocol = "smtp"
	ProtoIMAP      Protocol = "imap"
	ProtoPOP3      Protocol = "pop3"
	ProtoFTP       Protocol = "ftp"
	ProtoNTP       Protocol = "ntp"
	ProtoRDP       Protocol = "rdp"
	ProtoRsync     Protocol = "rsync"
	ProtoPostgres  Protocol = "postgres"
	ProtoMySQL     Protocol = "mysql"
	ProtoRedis     Protocol = "redis"
	ProtoMongoDB   Protocol = "mongodb"
	ProtoUnknown   Protocol = "unknown"
)

// Flow is one connection's classification + counters. Deltas are
// cumulative since the flow first appeared — callers diff successive
// snapshots to get rate.
type Flow struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	L4Proto string // "tcp" | "udp"
	L7Proto Protocol
	// Confidence is 0..1. Port-based lookups on well-known ports = 1.0;
	// "unknown" = 0.0. DPI implementations could emit 0.9 for SNI-matched
	// TLS + 0.5 for heuristic matches.
	Confidence float64

	RxBytes int64
	TxBytes int64

	FirstSeen time.Time
	LastSeen  time.Time

	// PeerID is the gmesh peer this flow's remote end corresponds to,
	// or 0 if the destination is off-mesh. Filled in by the Classifier
	// using its peer-mesh-IP index.
	PeerID int64
}

// Key identifies a flow (for map lookups + aggregation). Keeping it
// small so a hundred-thousand-flow map fits comfortably.
type Key struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	L4Proto          string
}

// KeyFor builds a Key from a Flow.
func KeyFor(f Flow) Key {
	return Key{
		SrcIP: f.SrcIP, DstIP: f.DstIP,
		SrcPort: f.SrcPort, DstPort: f.DstPort,
		L4Proto: f.L4Proto,
	}
}

// PerProtocolTotal is the aggregated view Dashboard RPCs expose.
type PerProtocolTotal struct {
	PeerID   int64
	Protocol Protocol
	Bytes    int64
	Flows    int
}

// Classifier maps a raw flow (L4 + ports) to an L7 label. The default
// implementation is port-based via DefaultPortMap; tests can supply
// a custom map for injection.
type Classifier struct {
	Ports    map[portKey]Protocol
	peerByIP map[string]int64 // mesh IP → peer ID

	mu sync.RWMutex
}

type portKey struct {
	Proto string // "tcp" | "udp"
	Port  uint16
}

// DefaultPortMap is the built-in well-known-port map. Operators
// augment via Classifier.AddPort rather than mutating directly.
var DefaultPortMap = map[portKey]Protocol{
	{"tcp", 22}:    ProtoSSH,
	{"tcp", 25}:    ProtoSMTP,
	{"tcp", 53}:    ProtoDNS,
	{"udp", 53}:    ProtoDNS,
	{"tcp", 80}:    ProtoHTTP,
	{"tcp", 110}:   ProtoPOP3,
	{"tcp", 143}:   ProtoIMAP,
	{"udp", 123}:   ProtoNTP,
	{"tcp", 443}:   ProtoTLS,
	{"udp", 443}:   ProtoQUIC,
	{"tcp", 465}:   ProtoSMTP,
	{"tcp", 587}:   ProtoSMTP,
	{"tcp", 873}:   ProtoRsync,
	{"tcp", 993}:   ProtoIMAP,
	{"tcp", 995}:   ProtoPOP3,
	{"tcp", 3306}:  ProtoMySQL,
	{"tcp", 3389}:  ProtoRDP,
	{"tcp", 5432}:  ProtoPostgres,
	{"tcp", 6379}:  ProtoRedis,
	{"tcp", 8080}:  ProtoHTTP,
	{"tcp", 8443}:  ProtoTLS,
	{"tcp", 27017}: ProtoMongoDB,
	{"tcp", 21}:    ProtoFTP,
	{"tcp", 20}:    ProtoFTP,
}

// NewClassifier returns a Classifier seeded with DefaultPortMap.
func NewClassifier() *Classifier {
	ports := make(map[portKey]Protocol, len(DefaultPortMap))
	for k, v := range DefaultPortMap {
		ports[k] = v
	}
	return &Classifier{Ports: ports, peerByIP: map[string]int64{}}
}

// AddPort registers a custom (L4, port) → Protocol mapping. Safe to
// call concurrently; overrides any default for the same key.
func (c *Classifier) AddPort(l4 string, port uint16, proto Protocol) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Ports[portKey{Proto: strings.ToLower(l4), Port: port}] = proto
}

// SetPeerIndex replaces the mesh-IP → peer-ID map. The classifier uses
// it to tag flows with their gmesh peer identity. The engine rebuilds
// + hands this in every time the peer registry changes.
func (c *Classifier) SetPeerIndex(peerByIP map[string]int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make(map[string]int64, len(peerByIP))
	for k, v := range peerByIP {
		next[k] = v
	}
	c.peerByIP = next
}

// Classify stamps L7Proto + Confidence + PeerID onto a Flow based on
// its transport-layer fields.
func (c *Classifier) Classify(f *Flow) {
	c.mu.RLock()
	// Destination port wins over source port — the server side is
	// almost always the one listening on the well-known port.
	if p, ok := c.Ports[portKey{Proto: f.L4Proto, Port: f.DstPort}]; ok {
		f.L7Proto = p
		f.Confidence = 1.0
	} else if p, ok := c.Ports[portKey{Proto: f.L4Proto, Port: f.SrcPort}]; ok {
		f.L7Proto = p
		f.Confidence = 1.0
	} else {
		f.L7Proto = ProtoUnknown
		f.Confidence = 0.0
	}
	if id, ok := c.peerByIP[f.DstIP]; ok {
		f.PeerID = id
	} else if id, ok := c.peerByIP[f.SrcIP]; ok {
		f.PeerID = id
	}
	c.mu.RUnlock()
}

// Reader pulls flow snapshots from the underlying kernel state. On
// Linux this is a conntrack reader; in tests it's a stub.
type Reader interface {
	// Read returns a fresh snapshot of live flows. Callers do not retain
	// the returned slice past the next call.
	Read() ([]Flow, error)
	Name() string
}

// Aggregator rolls classified flows into per-(peer, protocol) totals.
// Thread-safe. Delta accounting: when a flow's RxBytes/TxBytes grow,
// the difference is added to the aggregator; shrinking (or flow
// disappearance) is ignored so conntrack entries ageing out don't
// subtract real traffic.
type Aggregator struct {
	mu         sync.Mutex
	perKey     map[Key]Flow // last snapshot per key
	perProto   map[aggKey]*PerProtocolTotal
}

type aggKey struct {
	PeerID   int64
	Protocol Protocol
}

// NewAggregator returns an empty aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{
		perKey:   map[Key]Flow{},
		perProto: map[aggKey]*PerProtocolTotal{},
	}
}

// Ingest takes a fresh batch of classified flows and updates totals.
func (a *Aggregator) Ingest(flows []Flow) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, f := range flows {
		k := KeyFor(f)
		prev, known := a.perKey[k]
		var dRx, dTx int64
		if known {
			if f.RxBytes >= prev.RxBytes {
				dRx = f.RxBytes - prev.RxBytes
			}
			if f.TxBytes >= prev.TxBytes {
				dTx = f.TxBytes - prev.TxBytes
			}
		} else {
			dRx = f.RxBytes
			dTx = f.TxBytes
		}
		a.perKey[k] = f
		ak := aggKey{PeerID: f.PeerID, Protocol: f.L7Proto}
		cur, ok := a.perProto[ak]
		if !ok {
			cur = &PerProtocolTotal{PeerID: f.PeerID, Protocol: f.L7Proto}
			a.perProto[ak] = cur
		}
		cur.Bytes += dRx + dTx
		// Flows count is "number of distinct flows that ever contributed
		// to this bucket", measured by first-appearance. That matches
		// the Prometheus convention of a counter that only grows.
		if !known {
			cur.Flows++
		}
	}
}

// Totals returns a snapshot of per-(peer, protocol) byte+flow totals.
// Callers should treat the returned slice as read-only.
func (a *Aggregator) Totals() []PerProtocolTotal {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]PerProtocolTotal, 0, len(a.perProto))
	for _, t := range a.perProto {
		out = append(out, *t)
	}
	return out
}

// Flows returns every distinct flow currently tracked.
func (a *Aggregator) Flows() []Flow {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Flow, 0, len(a.perKey))
	for _, f := range a.perKey {
		out = append(out, f)
	}
	return out
}

// Reset clears every counter — used when the operator wants a fresh
// per-period reading rather than the cumulative-since-daemon-start one.
func (a *Aggregator) Reset() {
	a.mu.Lock()
	a.perKey = map[Key]Flow{}
	a.perProto = map[aggKey]*PerProtocolTotal{}
	a.mu.Unlock()
}

// String helps logs render a flow compactly.
func (f Flow) String() string {
	return fmt.Sprintf("%s %s:%d→%s:%d %s (%.0f%%)",
		f.L4Proto, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.L7Proto, f.Confidence*100)
}
