package l7

import (
	"context"
	"log/slog"
	"time"
)

// Monitor ties a Reader + Classifier + Aggregator together and runs a
// periodic Tick to keep per-protocol totals fresh.
type Monitor struct {
	Log        *slog.Logger
	Reader     Reader
	Classifier *Classifier
	Agg        *Aggregator
	Interval   time.Duration
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
	}
}

// Tick runs one pull + classify + ingest cycle. Returns the number of
// flows observed (zero is fine — conntrack acct may be off).
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
