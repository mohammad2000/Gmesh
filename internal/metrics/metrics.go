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
	}
	for _, c := range cols {
		if err := Registry.Register(c); err != nil {
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				panic(err)
			}
		}
	}
}
