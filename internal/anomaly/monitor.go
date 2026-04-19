package anomaly

import (
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Monitor owns the set of detectors and a small in-memory log of the
// last N alerts per peer so operators can see what recently fired
// without subscribing to the event bus.
type Monitor struct {
	Log *slog.Logger

	Bandwidth *BandwidthZ
	Storm     *HandshakeStorm
	Flap      *PeerFlap
	Pub       Publisher

	mu     sync.Mutex
	recent []Alert // capped ring of alerts; newest last
	cap    int
}

// Config bundles per-detector knobs.
type Config struct {
	Bandwidth     BandwidthConfig
	Storm         HandshakeStormConfig
	Flap          PeerFlapConfig
	RecentHistory int // default 200
}

func (c Config) defaults() Config {
	if c.RecentHistory <= 0 {
		c.RecentHistory = 200
	}
	return c
}

// New wires a Monitor + its detectors. The publisher is shared so every
// detector's Publish goes to the same sink — tests can pass a
// StubPublisher; the engine passes an events.Bus adapter.
func New(log *slog.Logger, cfg Config, pub Publisher) *Monitor {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.defaults()
	m := &Monitor{
		Log: log, cap: cfg.RecentHistory,
		recent: make([]Alert, 0, cfg.RecentHistory),
	}
	// Detectors share a single publisher that also records into the
	// Monitor's ring buffer. This two-step pattern (detector → m.Pub →
	// caller pub + m.recent) keeps the detectors ignorant of the
	// recent-history feature.
	m.Pub = &teePublisher{outer: pub, inner: m}
	m.Bandwidth = NewBandwidthZ(cfg.Bandwidth, m.Pub)
	m.Storm = NewHandshakeStorm(cfg.Storm, m.Pub)
	m.Flap = NewPeerFlap(cfg.Flap, m.Pub)
	return m
}

// teePublisher fans out to a downstream publisher AND records the
// alert in the monitor's recent ring.
type teePublisher struct {
	outer Publisher
	inner *Monitor
}

func (t *teePublisher) Publish(a Alert) {
	t.inner.remember(a)
	if t.outer != nil {
		t.outer.Publish(a)
	}
	if t.inner.Log != nil {
		t.inner.Log.Info("anomaly alert",
			"detector", a.Detector, "peer", a.PeerID,
			"severity", a.Severity, "msg", a.Message)
	}
}

func (m *Monitor) remember(a Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.recent) >= m.cap {
		copy(m.recent, m.recent[1:])
		m.recent = m.recent[:m.cap-1]
	}
	m.recent = append(m.recent, a)
}

// Recent returns up to n most-recent alerts (newest first). n=0 → all.
func (m *Monitor) Recent(n int) []Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := len(m.recent)
	if n <= 0 || n > total {
		n = total
	}
	out := make([]Alert, n)
	for i := 0; i < n; i++ {
		out[i] = m.recent[total-1-i]
	}
	return out
}

// ForPeer returns recent alerts scoped to one peer ID.
func (m *Monitor) ForPeer(peerID int64) []Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Alert
	for i := len(m.recent) - 1; i >= 0; i-- {
		if m.recent[i].PeerID == peerID {
			out = append(out, m.recent[i])
		}
	}
	return out
}

// Reset wipes every detector's state + the recent ring. Useful after a
// mesh-wide config change when a stale baseline would produce false
// positives.
func (m *Monitor) Reset() {
	m.Bandwidth.Reset()
	m.Storm.Reset()
	m.Flap.Reset()
	m.mu.Lock()
	m.recent = m.recent[:0]
	m.mu.Unlock()
}

// BandwidthSampleFor is a convenience used by callers who have
// rx/tx counters and an elapsed wall-clock window. Returns a
// bytes-per-second figure suitable for Bandwidth.Observe.
func BandwidthSampleFor(rxDelta, txDelta int64, window time.Duration) float64 {
	if window <= 0 {
		return 0
	}
	return float64(rxDelta+txDelta) / window.Seconds()
}

// RecentSortedByTime returns the recent ring as a copy sorted oldest
// first (useful for renderers that want a chronological feed).
func (m *Monitor) RecentSortedByTime() []Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Alert, len(m.recent))
	copy(out, m.recent)
	sort.Slice(out, func(i, j int) bool { return out[i].Observed.Before(out[j].Observed) })
	return out
}
