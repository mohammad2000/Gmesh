package l7

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/metrics"
)

// Monitor ties a Reader + Classifier + Aggregator together and runs a
// periodic Tick to keep per-protocol totals fresh.
type Monitor struct {
	Log        *slog.Logger
	Reader     Reader
	Classifier *Classifier
	Agg        *Aggregator
	Interval   time.Duration

	// watermarks remembers the last-published byte total per
	// (peer, protocol) key so Tick can Add only the positive delta to
	// the Prometheus counter. Prometheus counters must never decrease;
	// the aggregator's own totals are already monotonic, but we still
	// need this per-label memory so restart of a label's bucket isn't
	// double-counted against an earlier total.
	watermarkMu sync.Mutex
	watermarks  map[string]int64
}

// New wires a Monitor with the platform-default reader + a fresh
// classifier + aggregator. Interval defaults to 10s if zero.
func New(log *slog.Logger, interval time.Duration) *Monitor {
	if log == nil {
		log = slog.Default()
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &Monitor{
		Log: log, Interval: interval,
		Reader:     NewPlatformReader(),
		Classifier: NewClassifier(),
		Agg:        NewAggregator(),
		watermarks: map[string]int64{},
	}
}

// Tick runs one pull + classify + ingest cycle. Returns the number of
// flows observed (zero is fine — conntrack acct may be off).
//
// Publishes Prometheus counters after the ingest so dashboards + rate
// alerts see per-protocol byte growth between scrapes. L7FlowsActive
// gauge reflects the aggregator's distinct-flow count.
func (m *Monitor) Tick() (int, error) {
	if m.Reader == nil {
		return 0, nil
	}
	flows, err := m.Reader.Read()
	if err != nil {
		return 0, err
	}
	for i := range flows {
		m.Classifier.Classify(&flows[i])
	}
	m.Agg.Ingest(flows)

	// Publish current totals as counter DELTAS (counters only ever grow;
	// the aggregator's totals are already monotonic so we Add the
	// difference between the current total and whatever has already
	// been Counted.) A simpler alternative is to reset the counter each
	// tick, but Prometheus counters must not reset — so we track an
	// internal watermark per (peer, protocol) and Add only the growth.
	for _, t := range m.Agg.Totals() {
		key := fmt.Sprintf("%d|%s", t.PeerID, string(t.Protocol))
		m.watermarkMu.Lock()
		prev := m.watermarks[key]
		delta := t.Bytes - prev
		if delta > 0 {
			m.watermarks[key] = t.Bytes
		}
		m.watermarkMu.Unlock()
		if delta > 0 {
			metrics.L7BytesTotal.
				WithLabelValues(string(t.Protocol), fmt.Sprintf("%d", t.PeerID)).
				Add(float64(delta))
		}
	}
	metrics.L7FlowsActive.Set(float64(len(m.Agg.Flows())))
	return len(flows), nil
}

// Run starts a ticker that calls Tick on the configured Interval until
// ctx is canceled.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	// Fire once so callers don't wait a full interval for first data.
	if _, err := m.Tick(); err != nil {
		m.Log.Debug("l7 tick failed", "error", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := m.Tick(); err != nil {
				m.Log.Debug("l7 tick failed", "error", err)
			}
		}
	}
}

// Totals exposes the aggregator snapshot.
func (m *Monitor) Totals() []PerProtocolTotal { return m.Agg.Totals() }

// Flows exposes the live flow set.
func (m *Monitor) Flows() []Flow { return m.Agg.Flows() }
