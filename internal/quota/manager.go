package quota

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// coreManager is the shared lifecycle logic — it relies on CounterReader
// + Switcher + Publisher to do actual I/O, so the same struct is used for
// both stub tests and the real Linux wiring.
type coreManager struct {
	Log       *slog.Logger
	Reader    CounterReader
	Switcher  Switcher
	Publisher Publisher
	// Label used in Name() — "stub" or "linux".
	name string

	mu     sync.Mutex
	quotas map[int64]*Quota
}

func newCore(name string, log *slog.Logger, r CounterReader, s Switcher, p Publisher) *coreManager {
	if log == nil {
		log = slog.Default()
	}
	return &coreManager{
		Log: log, Reader: r, Switcher: s, Publisher: p,
		name: name, quotas: make(map[int64]*Quota),
	}
}

func (m *coreManager) Name() string { return m.name }

// SetSwitcher wires the engine-level Switcher once the engine is fully
// constructed. Safe to call at any time.
func (m *coreManager) SetSwitcher(sw Switcher) {
	m.mu.Lock()
	m.Switcher = sw
	m.mu.Unlock()
}

// Switch-setter is exposed on the Manager interface for the engine.
type SwitcherSetter interface {
	SetSwitcher(Switcher)
}

func (m *coreManager) Create(_ context.Context, q *Quota) (*Quota, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.quotas[q.ID]; ok {
		return nil, ErrExists
	}
	now := time.Now()
	q.CreatedAt = now
	q.UpdatedAt = now
	q.PeriodStart, q.PeriodEnd = periodWindow(q.Period, now)
	q.UsedBytes = 0
	q.WarnFired = false
	q.ShiftFired = false
	q.StopFired = false
	m.quotas[q.ID] = q
	m.Log.Info("quota created",
		"id", q.ID, "name", q.Name,
		"egress_profile", q.EgressProfileID, "period", q.Period,
		"limit_bytes", q.LimitBytes)
	return q, nil
}

func (m *coreManager) Update(_ context.Context, q *Quota) (*Quota, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.quotas[q.ID]
	if !ok {
		return nil, ErrNotFound
	}
	q.CreatedAt = old.CreatedAt
	q.UpdatedAt = time.Now()
	// Preserve live counters across updates.
	q.UsedBytes = old.UsedBytes
	q.PeriodStart = old.PeriodStart
	q.PeriodEnd = old.PeriodEnd
	q.WarnFired = old.WarnFired
	q.ShiftFired = old.ShiftFired
	q.StopFired = old.StopFired
	m.quotas[q.ID] = q
	return q, nil
}

func (m *coreManager) Delete(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.quotas, id)
	return nil
}

func (m *coreManager) List() []*Quota {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Quota, 0, len(m.quotas))
	for _, q := range m.quotas {
		cp := *q
		out = append(out, &cp)
	}
	return out
}

func (m *coreManager) Get(id int64) (*Quota, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	q, ok := m.quotas[id]
	if !ok {
		return nil, false
	}
	cp := *q
	return &cp, true
}

// Reset zeroes the live counter and clears latches.
func (m *coreManager) Reset(ctx context.Context, id int64) error {
	m.mu.Lock()
	q, ok := m.quotas[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	q.UsedBytes = 0
	q.WarnFired = false
	q.ShiftFired = false
	q.StopFired = false
	q.PeriodStart, q.PeriodEnd = periodWindow(q.Period, time.Now())
	q.UpdatedAt = time.Now()
	m.mu.Unlock()

	if m.Reader != nil {
		_ = m.Reader.Reset(ctx, q.EgressProfileID)
	}
	if m.Publisher != nil {
		m.Publisher.Publish(Event{
			Type: "quota_reset", QuotaID: id,
			Payload: map[string]any{
				"egress_profile_id": q.EgressProfileID,
				"period":            string(q.Period),
			},
		})
	}
	return nil
}

// Tick runs one evaluation pass. Idempotent; safe to invoke directly.
func (m *coreManager) Tick(ctx context.Context) error {
	// Copy the live set under lock so we don't hold m.mu while doing I/O.
	m.mu.Lock()
	active := make([]*Quota, 0, len(m.quotas))
	for _, q := range m.quotas {
		if q.Enabled {
			active = append(active, q)
		}
	}
	m.mu.Unlock()

	now := time.Now()
	for _, q := range active {
		m.evalOne(ctx, q, now)
	}
	return nil
}

// evalOne runs one quota's counter poll + threshold checks.
func (m *coreManager) evalOne(ctx context.Context, q *Quota, now time.Time) {
	// Period rollover first.
	if !q.PeriodEnd.IsZero() && now.After(q.PeriodEnd) {
		m.mu.Lock()
		q.UsedBytes = 0
		q.WarnFired = false
		q.ShiftFired = false
		q.StopFired = false
		q.PeriodStart, q.PeriodEnd = periodWindow(q.Period, now)
		q.UpdatedAt = now
		m.mu.Unlock()
		if m.Reader != nil {
			_ = m.Reader.Reset(ctx, q.EgressProfileID)
		}
		if m.Publisher != nil {
			m.Publisher.Publish(Event{
				Type: "quota_reset", QuotaID: q.ID,
				Payload: map[string]any{"reason": "period_rollover"},
			})
		}
	}

	// Read counter.
	var used int64
	if m.Reader != nil {
		n, _, err := m.Reader.ReadProfileBytes(ctx, q.EgressProfileID)
		if err != nil {
			m.Log.Debug("quota: reader failed", "id", q.ID, "error", err)
			return
		}
		used = n
	}

	m.mu.Lock()
	q.UsedBytes = used
	frac := q.UsedFraction()
	// Evaluate edges; latch each event once.
	var fires []Event
	if q.WarnAt > 0 && frac >= q.WarnAt && !q.WarnFired {
		q.WarnFired = true
		fires = append(fires, Event{
			Type: "quota_warning", QuotaID: q.ID,
			Payload: map[string]any{
				"egress_profile_id": q.EgressProfileID,
				"used_bytes":        used, "limit_bytes": q.LimitBytes,
				"fraction":          frac,
			},
		})
	}
	if q.ShiftAt > 0 && frac >= q.ShiftAt && !q.ShiftFired {
		q.ShiftFired = true
		fires = append(fires, Event{
			Type: "quota_shift", QuotaID: q.ID,
			Payload: map[string]any{
				"egress_profile_id": q.EgressProfileID,
				"backup_profile_id": q.BackupProfileID,
				"used_bytes":        used, "limit_bytes": q.LimitBytes,
				"fraction":          frac,
			},
		})
	}
	if q.StopAt > 0 && frac >= q.StopAt && !q.StopFired {
		q.StopFired = true
		fires = append(fires, Event{
			Type: "quota_stop", QuotaID: q.ID,
			Payload: map[string]any{
				"egress_profile_id": q.EgressProfileID,
				"used_bytes":        used, "limit_bytes": q.LimitBytes,
				"fraction":          frac,
			},
		})
	}
	shiftTo := int64(0)
	if q.ShiftFired && q.BackupProfileID != 0 && m.Switcher != nil {
		shiftTo = q.BackupProfileID
	}
	m.mu.Unlock()

	for _, ev := range fires {
		if m.Publisher != nil {
			m.Publisher.Publish(ev)
		}
	}

	// Automatic shift happens OUTSIDE the lock.
	if shiftTo != 0 {
		if err := m.Switcher.SwapExitPeer(ctx, q.EgressProfileID, shiftTo); err != nil {
			m.Log.Warn("quota shift swap failed",
				"quota_id", q.ID, "profile", q.EgressProfileID,
				"backup", shiftTo, "error", err)
		} else {
			m.Log.Info("quota auto-shifted egress profile",
				"quota_id", q.ID, "profile", q.EgressProfileID, "backup", shiftTo)
		}
	}
}

// Run loops Tick forever at interval.
func (m *coreManager) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Tick(ctx); err != nil {
				m.Log.Debug("quota tick", "error", err)
			}
		}
	}
}
