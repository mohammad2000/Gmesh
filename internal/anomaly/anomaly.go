// Package anomaly is a lightweight, stat-based connection-anomaly
// detector for the mesh. It consumes peer samples (bandwidth,
// handshake counts, up/down transitions) and emits Alerts when values
// fall outside a rolling-window baseline.
//
// # Scope for Phase 21
//
// No machine learning, no time-series database, no external
// dependencies beyond Go's stdlib. The design goal is "a handful of
// operator-meaningful signals a SRE can reason about", not
// state-of-the-art detection. Three detectors ship today:
//
//   - BandwidthZ: z-score of per-peer bytes/sec over a 5-min window.
//     Alert fires when the current sample is N standard deviations
//     above or below the mean — catches exfil spikes and hung peers.
//   - HandshakeStorm: rate of new WG handshakes per peer per window.
//     Alert fires when rate > threshold — catches key-churn bugs and
//     retry storms.
//   - PeerFlap: count of path_up/path_down transitions per peer within
//     a short window. Alert fires when count > threshold — catches
//     flaky underlays without waiting for a sustained outage.
//
// Each detector exposes an Observe method that accepts a typed sample
// and returns an optional Alert. Callers drive them from the engine's
// peer-stats + pathmon subscriptions.
//
// # Why rolling windows, not raw thresholds
//
// A hard "alert if bytes/sec > 1e9" is cheap but ages badly — an hour
// of YouTube watching triggers it; 3 AM backup windows trigger it;
// legitimate growth triggers it. Rolling stats + z-scores adapt to
// each peer's own baseline, so a spike that doubles your normal
// evening traffic fires regardless of whether normal = 1 MB/s or
// 1 GB/s.
//
// # Alert lifecycle
//
// Alerts are edge-triggered by default: once a detector emits an
// Alert, it enters a per-peer cooldown (configurable, default 60 s)
// during which it will not re-emit. This matches pathmon's debouncing
// ethos and prevents oscillating detectors from flooding the bus.
package anomaly

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Severity is a coarse ordinal the UI can colour on.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarn
	SeverityCritical
)

// String renders the severity as a lowercase label.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Alert is one detector's output. Higher layers wrap it into events.Event.
type Alert struct {
	Detector  string
	PeerID    int64
	Severity  Severity
	Message   string
	Metrics   map[string]float64
	Observed  time.Time
}

// Detector is the narrow contract every anomaly detector implements.
// Observe is called with a concrete sample type per detector; the
// detector computes whether the current state is anomalous and
// returns an Alert or nil.
type Detector interface {
	Name() string
	Reset() // zero history (e.g. after a long gap)
}

// rollingStats maintains a fixed-size sliding window of float64 samples
// and exposes running mean + stddev. Not thread-safe on its own; owner
// takes mu.
type rollingStats struct {
	window []float64
	next   int
	count  int
}

func newRollingStats(windowSize int) *rollingStats {
	if windowSize <= 0 {
		windowSize = 1
	}
	return &rollingStats{window: make([]float64, windowSize)}
}

func (r *rollingStats) push(v float64) {
	r.window[r.next] = v
	r.next = (r.next + 1) % len(r.window)
	if r.count < len(r.window) {
		r.count++
	}
}

// meanStddev returns (mean, stddev) over the current window.
// stddev is 0 when fewer than 2 samples have landed (z-score undefined).
func (r *rollingStats) meanStddev() (float64, float64) {
	if r.count == 0 {
		return 0, 0
	}
	var sum float64
	for i := 0; i < r.count; i++ {
		sum += r.window[i]
	}
	mean := sum / float64(r.count)
	if r.count < 2 {
		return mean, 0
	}
	var sq float64
	for i := 0; i < r.count; i++ {
		d := r.window[i] - mean
		sq += d * d
	}
	variance := sq / float64(r.count-1)
	return mean, math.Sqrt(variance)
}

// fillRatio reports how full the window is (0.0..1.0). Callers use
// this to skip alerting while a detector is still "cold" and hasn't
// seen enough baseline data.
func (r *rollingStats) fillRatio() float64 {
	return float64(r.count) / float64(len(r.window))
}

// zScore returns (value - mean) / stddev when stddev > 0; 0 otherwise.
// A positive z means value > mean; negative means below.
func zScore(value, mean, stddev float64) float64 {
	if stddev <= 0 {
		return 0
	}
	return (value - mean) / stddev
}

// cooldown tracks per-peer edge-triggered alert throttling.
type cooldown struct {
	mu    sync.Mutex
	until map[int64]time.Time
	dur   time.Duration
}

func newCooldown(d time.Duration) *cooldown {
	return &cooldown{until: map[int64]time.Time{}, dur: d}
}

// allow returns true if the peer is outside its cooldown. When true,
// the call also arms the next cooldown window — callers should treat
// a successful allow as "I'm about to fire an alert".
func (c *cooldown) allow(peer int64, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.until[peer]; ok && now.Before(t) {
		return false
	}
	c.until[peer] = now.Add(c.dur)
	return true
}

// Publisher sinks Alerts. The engine implements this with a bridge into
// the events.Bus; tests use the StubPublisher below.
type Publisher interface {
	Publish(Alert)
}

// ── StubPublisher for tests ───────────────────────────────────────────

// StubPublisher records every Alert passed to Publish. Thread-safe.
type StubPublisher struct {
	mu     sync.Mutex
	alerts []Alert
}

// NewStubPublisher returns an empty publisher.
func NewStubPublisher() *StubPublisher { return &StubPublisher{} }

// Publish records the alert.
func (p *StubPublisher) Publish(a Alert) {
	p.mu.Lock()
	p.alerts = append(p.alerts, a)
	p.mu.Unlock()
}

// All returns a copy of every alert recorded so far.
func (p *StubPublisher) All() []Alert {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Alert, len(p.alerts))
	copy(out, p.alerts)
	return out
}

// ByDetector filters alerts by Detector name.
func (p *StubPublisher) ByDetector(name string) []Alert {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Alert
	for _, a := range p.alerts {
		if a.Detector == name {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Observed.Before(out[j].Observed) })
	return out
}

var _ Publisher = (*StubPublisher)(nil)
