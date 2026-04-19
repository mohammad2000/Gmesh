package pathmon

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// history is a ring buffer of the last N probe Results for one target.
// On transition we use it to compute LossPct.
type history struct {
	ring  []Result
	next  int
	count int
}

func newHistory(size int) *history {
	return &history{ring: make([]Result, size)}
}

func (h *history) push(r Result) {
	h.ring[h.next] = r
	h.next = (h.next + 1) % len(h.ring)
	if h.count < len(h.ring) {
		h.count++
	}
}

func (h *history) lossPct() float64 {
	if h.count == 0 {
		return 0
	}
	var losses int
	for i := 0; i < h.count; i++ {
		if !h.ring[i].Up {
			losses++
		}
	}
	return float64(losses) / float64(h.count) * 100
}

// Monitor owns a set of targets and runs their probes on a ticker.
// Thread-safe: every accessor takes mu.
type Monitor struct {
	Log    *slog.Logger
	Cfg    Config
	Prober Prober
	Pub    Publisher

	mu        sync.Mutex
	targets   map[int64]*State
	histories map[int64]*history
	listeners []Listener
	running   bool
	cancelFn  context.CancelFunc
}

// New builds a Monitor. Pass nil publisher/prober for tests that want
// defaults (StubPublisher / StubProber). Prober is REQUIRED in practice.
func New(log *slog.Logger, cfg Config, prober Prober, pub Publisher) *Monitor {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.defaults()
	return &Monitor{
		Log: log, Cfg: cfg, Prober: prober, Pub: pub,
		targets:   map[int64]*State{},
		histories: map[int64]*history{},
	}
}

// AddTarget registers (or replaces) a target. Safe to call while Run is
// active — the next tick will pick it up.
func (m *Monitor) AddTarget(t Target) error {
	if err := t.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.targets[t.PeerID] = &State{Target: t, Status: StatusUnknown}
	m.histories[t.PeerID] = newHistory(m.Cfg.WindowSize)
	return nil
}

// RemoveTarget stops probing a target.
func (m *Monitor) RemoveTarget(peerID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.targets, peerID)
	delete(m.histories, peerID)
}

// Get returns a copy of the current state for peerID.
func (m *Monitor) Get(peerID int64) (State, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.targets[peerID]
	if !ok {
		return State{}, false
	}
	return *st, true
}

// List returns a snapshot of all states.
func (m *Monitor) List() []State {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]State, 0, len(m.targets))
	for _, s := range m.targets {
		out = append(out, *s)
	}
	return out
}

// AddListener registers a callback fired on every Up↔Down transition.
func (m *Monitor) AddListener(l Listener) {
	m.mu.Lock()
	m.listeners = append(m.listeners, l)
	m.mu.Unlock()
}

// Tick runs one probe pass across every registered target. Exposed for
// deterministic tests; Run invokes it on the configured interval.
func (m *Monitor) Tick(ctx context.Context) {
	if m.Prober == nil {
		return
	}
	m.mu.Lock()
	targets := make([]*State, 0, len(m.targets))
	for _, s := range m.targets {
		targets = append(targets, s)
	}
	m.mu.Unlock()

	for _, st := range targets {
		pctx, cancel := context.WithTimeout(ctx, m.Cfg.Timeout)
		res := m.Prober.Probe(pctx, st.Target)
		cancel()
		m.record(ctx, st.Target.PeerID, res)
	}
}

// record integrates one probe Result into state and fires transitions.
func (m *Monitor) record(ctx context.Context, peerID int64, res Result) {
	m.mu.Lock()
	st, ok := m.targets[peerID]
	hist := m.histories[peerID]
	if !ok || hist == nil {
		m.mu.Unlock()
		return
	}
	hist.push(res)
	st.LastSampleAt = res.When
	st.LastRTT = res.RTT
	st.Samples = hist.count
	st.LossPct = hist.lossPct()

	var ev *Event
	if res.Up {
		st.ConsecutiveOK++
		st.ConsecutiveFail = 0
		st.LastUpAt = res.When
		if st.Status != StatusUp && st.ConsecutiveOK >= m.Cfg.UpThreshold {
			st.Status = StatusUp
			ev = &Event{
				Type: "path_up", PeerID: peerID,
				MeshIP: st.Target.MeshIP, RTT: res.RTT,
				LossPct: st.LossPct, At: res.When,
			}
		}
	} else {
		st.ConsecutiveFail++
		st.ConsecutiveOK = 0
		st.LastDownAt = res.When
		if st.Status != StatusDown && st.ConsecutiveFail >= m.Cfg.DownThreshold {
			st.Status = StatusDown
			ev = &Event{
				Type: "path_down", PeerID: peerID,
				MeshIP: st.Target.MeshIP, RTT: res.RTT,
				LossPct: st.LossPct, At: res.When,
			}
		}
	}
	listeners := make([]Listener, len(m.listeners))
	copy(listeners, m.listeners)
	m.mu.Unlock()

	if ev == nil {
		return
	}
	if m.Pub != nil {
		m.Pub.Publish(*ev)
	}
	m.Log.Info("pathmon transition",
		"type", ev.Type, "peer", peerID, "mesh_ip", ev.MeshIP,
		"rtt_ms", ev.RTT.Milliseconds(), "loss_pct", ev.LossPct)
	for _, fn := range listeners {
		fn(ctx, *ev)
	}
}

// Run ticks on Cfg.Interval until ctx is canceled. Safe to call once.
func (m *Monitor) Run(ctx context.Context) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	m.running = true
	m.cancelFn = cancel
	m.mu.Unlock()

	t := time.NewTicker(m.Cfg.Interval)
	defer t.Stop()
	// Fire one probe at startup so callers don't wait for the first interval.
	m.Tick(ctx)
	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			return
		case <-t.C:
			m.Tick(ctx)
		}
	}
}

// Stop cancels the Run loop (if any). Idempotent.
func (m *Monitor) Stop() {
	m.mu.Lock()
	fn := m.cancelFn
	m.cancelFn = nil
	m.mu.Unlock()
	if fn != nil {
		fn()
	}
}
