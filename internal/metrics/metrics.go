// Package metrics is gmeshd's Prometheus surface. Counters and histograms
// live here; the HTTP handler (http.go) exposes them over a dedicated Unix
// socket so scrapers can curl --unix-socket.
//
// Import cycle note: metrics can be imported from anywhere (internal/rpc,
// internal/engine, cmd/gmeshd) because it depends on nothing internal.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Registry is the global registry every gmesh counter registers on.
// Callers can pass this to promhttp.HandlerFor to serve /metrics.
var Registry = prometheus.NewRegistry()

var (
	// RPCRequests counts every gRPC request by method + code.
	RPCRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "rpc",
			Name:      "requests_total",
			Help:      "Number of gRPC requests handled, labeled by method and gRPC status code.",
		},
		[]string{"method", "code"},
	)

	// RPCLatency is a histogram of gRPC request duration.
	RPCLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "gmesh",
			Subsystem: "rpc",
			Name:      "latency_seconds",
			Help:      "gRPC request latency in seconds.",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2.5, 12),
		},
		[]string{"method"},
	)

	// PeersGauge exposes the current peer count.
	PeersGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gmesh",
		Name:      "peers_total",
		Help:      "Number of peers currently in the registry.",
	})

	// ScopesGauge exposes the current scope count.
	ScopesGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gmesh",
		Name:      "scopes_total",
		Help:      "Number of connected scopes.",
	})

	// HolePunchAttempts counts every hole-punch attempt by method + outcome.
	HolePunchAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "traversal",
			Name:      "holepunch_attempts_total",
			Help:      "Hole-punch attempts labeled by method and outcome (success|fail).",
		},
		[]string{"method", "outcome"},
	)

	// FirewallApplies counts ApplyFirewall calls by outcome.
	FirewallApplies = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "firewall",
			Name:      "applies_total",
			Help:      "Number of firewall apply operations labeled by outcome.",
		},
		[]string{"outcome"}, // "ok" | "partial" | "fail"
	)

	// FirewallRulesActive is the number of rules in the current ruleset.
	FirewallRulesActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gmesh",
		Subsystem: "firewall",
		Name:      "rules_active",
		Help:      "Active firewall rule count.",
	})

	// RelayBytesForwarded is the cumulative bytes forwarded through the
	// UDP relay client (sum over all sessions).
	RelayBytesForwarded = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gmesh",
		Subsystem: "relay",
		Name:      "bytes_forwarded_total",
		Help:      "Cumulative bytes forwarded through the UDP relay client.",
	})

	// WSTunnelBytes is the same for the WS tunnel client.
	WSTunnelBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gmesh",
		Subsystem: "wstunnel",
		Name:      "bytes_total",
		Help:      "Cumulative bytes forwarded through WS tunnel clients.",
	})

	// EventsPublished is the total events published on the in-proc bus.
	EventsPublished = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "events",
			Name:      "published_total",
			Help:      "Events published on the internal event bus, labeled by type.",
		},
		[]string{"type"},
	)

	// EventsDropped counts events dropped because a subscriber was slow.
	EventsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gmesh",
		Subsystem: "events",
		Name:      "dropped_total",
		Help:      "Events dropped due to slow subscribers.",
	})

	// HealthScoreHist captures per-tick health scores (sample ≤ 100 points).
	HealthScoreHist = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "gmesh",
		Subsystem: "health",
		Name:      "score",
		Help:      "Distribution of per-peer health scores (0..100).",
		Buckets:   []float64{10, 30, 50, 70, 85, 90, 95, 100},
	})

	// NATDiscovery counts NAT discovery cycles by outcome.
	NATDiscovery = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "nat",
			Name:      "discovery_total",
			Help:      "NAT discovery cycles labeled by outcome (ok|fail) + resulting NAT type.",
		},
		[]string{"outcome", "nat_type"},
	)

	// BuildInfo is a single-label series carrying version + commit strings.
	BuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "gmesh",
			Name:      "build_info",
			Help:      "gmeshd build identity; value is always 1.",
		},
		[]string{"version", "commit", "build_date"},
	)

	// ── Phase 14 — Path Monitor ───────────────────────────────────────

	// PathTransitions counts pathmon up/down edge events per peer.
	// Labels keep cardinality bounded: peer_id is high-cardinality but
	// the number of peers is typically small and known to operators.
	PathTransitions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "pathmon",
			Name:      "transitions_total",
			Help:      "Pathmon transitions labeled by type (up|down) and peer_id.",
		},
		[]string{"type", "peer_id"},
	)

	// PathFailovers counts auto-failover swaps triggered by path_down.
	PathFailovers = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "pathmon",
			Name:      "failovers_total",
			Help:      "Engine auto-failover swaps labeled by action (swap|restore).",
		},
		[]string{"action"},
	)

	// ── Phase 13 / 13.5 — Quota ───────────────────────────────────────

	// QuotaEdges counts per-threshold edge crossings. Labels: type =
	// warn | shift | stop | reset, quota_id stays raw for per-quota
	// dashboards. hard_stop=true alerts also emit the stop edge and
	// additionally increment the QuotaBlocks counter below.
	QuotaEdges = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "quota",
			Name:      "edges_total",
			Help:      "Quota threshold edge crossings labeled by type and quota_id.",
		},
		[]string{"type", "quota_id"},
	)

	// QuotaBlocks counts hard-stop DROP installs + unblocks.
	QuotaBlocks = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "quota",
			Name:      "blocks_total",
			Help:      "Quota hard-stop enforcer actions labeled by action (block|unblock).",
		},
		[]string{"action"},
	)

	// ── Phase 19 — Circuit ────────────────────────────────────────────

	// CircuitInstalls counts per-role Create calls on the circuit
	// manager. Labels: role = source | transit | exit | none. A no-op
	// "none" install still increments so operators can see mis-scoped
	// circuit pushes.
	CircuitInstalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "circuit",
			Name:      "installs_total",
			Help:      "Circuit installs on this node labeled by local role.",
		},
		[]string{"role"},
	)

	// ── Phase 20 — mTLS CA ────────────────────────────────────────────

	// MTLSCertsIssued counts successful cert issuances since daemon
	// start (per-peer cardinality is bounded and useful for dashboards).
	MTLSCertsIssued = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gmesh",
		Subsystem: "mtls",
		Name:      "certs_issued_total",
		Help:      "Total peer certificates issued by the embedded CA.",
	})

	// MTLSCertsRevoked counts revocations.
	MTLSCertsRevoked = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "gmesh",
		Subsystem: "mtls",
		Name:      "certs_revoked_total",
		Help:      "Total peer certificates revoked via the CRL.",
	})

	// ── Phase 21 — Anomaly detectors ──────────────────────────────────

	// AnomalyAlerts counts alerts by detector + severity. Peer_id is
	// deliberately NOT a label to keep cardinality bounded under
	// flapping conditions; dashboards that need per-peer rollups query
	// the observability log instead.
	AnomalyAlerts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "anomaly",
			Name:      "alerts_total",
			Help:      "Anomaly detector alerts labeled by detector and severity.",
		},
		[]string{"detector", "severity"},
	)

	// ── Phase 18 — L7 Classifier ──────────────────────────────────────

	// L7BytesTotal counts bytes per L7 protocol since daemon start.
	// Labels: protocol + peer_id. Peer_id is bounded by mesh size.
	// Operators that care about per-destination breakdowns use the
	// ListL7Flows RPC, not this counter.
	L7BytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gmesh",
			Subsystem: "l7",
			Name:      "bytes_total",
			Help:      "Cumulative bytes per L7 protocol and peer_id.",
		},
		[]string{"protocol", "peer_id"},
	)

	// L7FlowsActive is the current distinct-flow count in the aggregator.
	L7FlowsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "gmesh",
		Subsystem: "l7",
		Name:      "flows_active",
		Help:      "Distinct flows currently tracked by the L7 classifier.",
	})
)

// MustRegister is called once at process start to wire every collector
// into the Registry. Safe to call multiple times (panic on duplicate is
// caught with a re-register no-op).
func MustRegister() {
	cols := []prometheus.Collector{
		RPCRequests, RPCLatency, PeersGauge, ScopesGauge,
		HolePunchAttempts, FirewallApplies, FirewallRulesActive,
		RelayBytesForwarded, WSTunnelBytes, EventsPublished, EventsDropped,
		HealthScoreHist, NATDiscovery, BuildInfo,
		// Phase 14 + 18 + 19 + 20 + 21:
		PathTransitions, PathFailovers,
		QuotaEdges, QuotaBlocks,
		CircuitInstalls,
		MTLSCertsIssued, MTLSCertsRevoked,
		AnomalyAlerts,
		L7BytesTotal, L7FlowsActive,
	}
	for _, c := range cols {
		if err := Registry.Register(c); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				panic(err)
			}
		}
	}
}
