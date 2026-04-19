package quota

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// collector records every Event published.
type collector struct {
	mu sync.Mutex
	ev []Event
}

func (c *collector) Publish(e Event) {
	c.mu.Lock()
	c.ev = append(c.ev, e)
	c.mu.Unlock()
}

func (c *collector) byType(t string) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Event
	for _, e := range c.ev {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// switcherRecorder captures SwapExitPeer calls and returns a scripted
// previous-peer value so auto_rollback tests can assert the capture.
type switcherRecorder struct {
	mu          sync.Mutex
	calls       []struct{ profile, backup int64 }
	currentPeer int64 // what SwapExitPeer reports as prev; updated on swap
	err         error
}

func (s *switcherRecorder) SwapExitPeer(_ context.Context, profile, backup int64) (int64, error) {
	s.mu.Lock()
	prev := s.currentPeer
	s.calls = append(s.calls, struct{ profile, backup int64 }{profile, backup})
	if s.err == nil {
		s.currentPeer = backup
	}
	s.mu.Unlock()
	return prev, s.err
}

func (s *switcherRecorder) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		q       Quota
		wantErr bool
	}{
		{"missing name", Quota{EgressProfileID: 1, LimitBytes: 1}, true},
		{"missing egress", Quota{Name: "x", LimitBytes: 1}, true},
		{"zero limit", Quota{Name: "x", EgressProfileID: 1}, true},
		{"bad period", Quota{Name: "x", EgressProfileID: 1, LimitBytes: 1, Period: "nope"}, true},
		{"ok daily", Quota{Name: "x", EgressProfileID: 1, LimitBytes: 1, Period: "daily"}, false},
		{"bad warn", Quota{Name: "x", EgressProfileID: 1, LimitBytes: 1, Period: "daily", WarnAt: 1.5}, true},
		{"shift without backup", Quota{Name: "x", EgressProfileID: 1, LimitBytes: 1, Period: "daily", ShiftAt: 0.9}, true},
		{"ok shift + backup", Quota{Name: "x", EgressProfileID: 1, LimitBytes: 1, Period: "daily", ShiftAt: 0.9, BackupProfileID: 2}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.q.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestCreateListDelete(t *testing.T) {
	m := NewStub(silent(), &collector{}, nil)
	ctx := context.Background()
	q, err := m.Create(ctx, &Quota{
		ID: 1, Name: "q1", Enabled: true, EgressProfileID: 10,
		Period: "daily", LimitBytes: 1000, WarnAt: 0.8,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if q.PeriodEnd.IsZero() {
		t.Error("PeriodEnd not set")
	}
	if _, err := m.Create(ctx, q); err != ErrExists {
		t.Errorf("duplicate → %v", err)
	}
	if len(m.List()) != 1 {
		t.Errorf("list len")
	}
	if _, ok := m.Get(1); !ok {
		t.Error("Get returned false")
	}
	if err := m.Delete(ctx, 1); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(m.List()) != 0 {
		t.Errorf("list after delete")
	}
}

func TestTickFiresWarnOnceAndShift(t *testing.T) {
	p := &collector{}
	sw := &switcherRecorder{}
	m := NewStub(silent(), p, sw)
	ctx := context.Background()
	_, err := m.Create(ctx, &Quota{
		ID: 1, Name: "q", Enabled: true, EgressProfileID: 10,
		Period: "daily", LimitBytes: 1000,
		WarnAt: 0.8, ShiftAt: 0.9, BackupProfileID: 20,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Below warn: no events.
	m.Reader().Set(10, 500)
	_ = m.Tick(ctx)
	if len(p.byType("quota_warning")) != 0 {
		t.Errorf("premature warn")
	}

	// Cross warn only.
	m.Reader().Set(10, 850)
	_ = m.Tick(ctx)
	if n := len(p.byType("quota_warning")); n != 1 {
		t.Errorf("warn fires = %d; want 1", n)
	}
	// Re-tick — latch keeps us quiet.
	_ = m.Tick(ctx)
	if n := len(p.byType("quota_warning")); n != 1 {
		t.Errorf("warn re-fired: %d", n)
	}

	// Cross shift — triggers swap.
	m.Reader().Set(10, 950)
	_ = m.Tick(ctx)
	if n := len(p.byType("quota_shift")); n != 1 {
		t.Errorf("shift events = %d; want 1", n)
	}
	if sw.count() != 1 {
		t.Errorf("switcher called %d times; want 1", sw.count())
	}
}

func TestTickFiresStop(t *testing.T) {
	p := &collector{}
	m := NewStub(silent(), p, nil)
	ctx := context.Background()
	_, _ = m.Create(ctx, &Quota{
		ID: 1, Name: "q", Enabled: true, EgressProfileID: 10,
		Period: "daily", LimitBytes: 1000, StopAt: 1.0,
	})
	m.Reader().Set(10, 1100)
	_ = m.Tick(ctx)
	if n := len(p.byType("quota_stop")); n != 1 {
		t.Errorf("stop fires = %d", n)
	}
}

func TestHardStopBlocksAndResetUnblocks(t *testing.T) {
	p := &collector{}
	m := NewStub(silent(), p, nil)
	enf := NewStubEnforcer(silent())
	m.SetEnforcer(enf)
	ctx := context.Background()
	_, _ = m.Create(ctx, &Quota{
		ID: 1, Name: "q", Enabled: true, EgressProfileID: 10,
		Period: "daily", LimitBytes: 1000, StopAt: 1.0, HardStop: true,
	})
	m.Reader().Set(10, 1100)
	_ = m.Tick(ctx)
	if !enf.IsBlocked(10) {
		t.Fatal("hard-stop Block not called")
	}
	wantMark := fwmarkForProfile(10)
	if got := enf.Snapshot()[10]; got != wantMark {
		t.Errorf("block mark = 0x%x; want 0x%x", got, wantMark)
	}
	// Ticking again must not double-call Block (latch prevents it).
	_ = m.Tick(ctx)
	if n := len(p.byType("quota_stop")); n != 1 {
		t.Errorf("stop re-fired: %d", n)
	}

	if err := m.Reset(ctx, 1); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if enf.IsBlocked(10) {
		t.Error("reset did not unblock")
	}
}

func TestHardStopFalseStaysEventOnly(t *testing.T) {
	p := &collector{}
	m := NewStub(silent(), p, nil)
	enf := NewStubEnforcer(silent())
	m.SetEnforcer(enf)
	ctx := context.Background()
	_, _ = m.Create(ctx, &Quota{
		ID: 1, Name: "q", Enabled: true, EgressProfileID: 10,
		Period: "daily", LimitBytes: 1000, StopAt: 1.0,
		// HardStop left false — default behaviour.
	})
	m.Reader().Set(10, 1100)
	_ = m.Tick(ctx)
	if enf.IsBlocked(10) {
		t.Error("Block was called without HardStop=true")
	}
	if n := len(p.byType("quota_stop")); n != 1 {
		t.Errorf("stop event missing: %d", n)
	}
}

func TestAutoRollbackOnReset(t *testing.T) {
	p := &collector{}
	sw := &switcherRecorder{currentPeer: 7}
	m := NewStub(silent(), p, sw)
	ctx := context.Background()
	_, _ = m.Create(ctx, &Quota{
		ID: 1, Name: "q", Enabled: true, EgressProfileID: 10,
		Period: "daily", LimitBytes: 1000,
		ShiftAt: 0.9, BackupProfileID: 99, AutoRollback: true,
	})
	m.Reader().Set(10, 950)
	_ = m.Tick(ctx)
	if sw.count() != 1 {
		t.Fatalf("shift did not swap: calls=%d", sw.count())
	}
	if got, _ := m.Get(1); got.ShiftedFromPeerID != 7 {
		t.Errorf("captured prev = %d; want 7", got.ShiftedFromPeerID)
	}
	if err := m.Reset(ctx, 1); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if sw.count() != 2 {
		t.Errorf("rollback did not swap: calls=%d", sw.count())
	}
	sw.mu.Lock()
	last := sw.calls[len(sw.calls)-1]
	sw.mu.Unlock()
	if last.backup != 7 {
		t.Errorf("rollback peer = %d; want 7", last.backup)
	}
	if got, _ := m.Get(1); got.ShiftedFromPeerID != 0 {
		t.Errorf("ShiftedFromPeerID not cleared: %d", got.ShiftedFromPeerID)
	}
}

func TestAutoRollbackOffLeavesShifted(t *testing.T) {
	p := &collector{}
	sw := &switcherRecorder{currentPeer: 7}
	m := NewStub(silent(), p, sw)
	ctx := context.Background()
	_, _ = m.Create(ctx, &Quota{
		ID: 1, Name: "q", Enabled: true, EgressProfileID: 10,
		Period: "daily", LimitBytes: 1000,
		ShiftAt: 0.9, BackupProfileID: 99, AutoRollback: false,
	})
	m.Reader().Set(10, 950)
	_ = m.Tick(ctx)
	if err := m.Reset(ctx, 1); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if sw.count() != 1 {
		t.Errorf("extra swap after reset without AutoRollback: %d", sw.count())
	}
}

func TestShiftDoesNotRepeatEveryTick(t *testing.T) {
	p := &collector{}
	sw := &switcherRecorder{currentPeer: 5}
	m := NewStub(silent(), p, sw)
	ctx := context.Background()
	_, _ = m.Create(ctx, &Quota{
		ID: 1, Name: "q", Enabled: true, EgressProfileID: 10,
		Period: "daily", LimitBytes: 1000,
		ShiftAt: 0.9, BackupProfileID: 99,
	})
	m.Reader().Set(10, 950)
	for i := 0; i < 5; i++ {
		_ = m.Tick(ctx)
	}
	if sw.count() != 1 {
		t.Errorf("switcher called %d times across 5 ticks; want 1", sw.count())
	}
}

func TestHardStopAutoReleaseOnPeriodRollover(t *testing.T) {
	p := &collector{}
	m := NewStub(silent(), p, nil)
	enf := NewStubEnforcer(silent())
	m.SetEnforcer(enf)
	ctx := context.Background()
	_, _ = m.Create(ctx, &Quota{
		ID: 1, Name: "q", Enabled: true, EgressProfileID: 10,
		Period: "hourly", LimitBytes: 1000, StopAt: 1.0, HardStop: true,
	})
	m.Reader().Set(10, 1100)
	_ = m.Tick(ctx)
	if !enf.IsBlocked(10) {
		t.Fatal("Block not called")
	}
	// Force period end into the past and tick again.
	m.mu.Lock()
	m.quotas[1].PeriodEnd = time.Now().Add(-time.Second)
	m.mu.Unlock()
	m.Reader().Set(10, 0)
	_ = m.Tick(ctx)
	if enf.IsBlocked(10) {
		t.Error("hard-stop not released on period rollover")
	}
}

func TestResetZeroesCounterAndLatches(t *testing.T) {
	p := &collector{}
	m := NewStub(silent(), p, nil)
	ctx := context.Background()
	_, _ = m.Create(ctx, &Quota{
		ID: 1, Name: "q", Enabled: true, EgressProfileID: 10,
		Period: "daily", LimitBytes: 1000, WarnAt: 0.5,
	})
	m.Reader().Set(10, 600)
	_ = m.Tick(ctx)
	if n := len(p.byType("quota_warning")); n != 1 {
		t.Fatalf("warn didn't fire")
	}

	if err := m.Reset(ctx, 1); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	// After reset, another tick at the same level should re-fire.
	m.Reader().Set(10, 700)
	_ = m.Tick(ctx)
	if n := len(p.byType("quota_warning")); n != 2 {
		t.Errorf("warn after reset = %d; want 2", n)
	}
	if n := len(p.byType("quota_reset")); n != 1 {
		t.Errorf("quota_reset events = %d; want 1", n)
	}
}

func TestPeriodRolloverForced(t *testing.T) {
	// Rollover timing depends on the wall clock. Instead of faking time
	// across the Manager surface, we poke the live map directly — the
	// test lives in the same package so we can.
	p := &collector{}
	m := NewStub(silent(), p, nil)
	ctx := context.Background()
	_, _ = m.Create(ctx, &Quota{
		ID: 1, Name: "q", Enabled: true, EgressProfileID: 10,
		Period: "hourly", LimitBytes: 1000, WarnAt: 0.5,
	})

	m.Reader().Set(10, 800)
	_ = m.Tick(ctx)
	if n := len(p.byType("quota_warning")); n != 1 {
		t.Fatal("warn didn't fire on first crossing")
	}

	// Poke internal state to simulate period end in the past.
	m.mu.Lock()
	m.quotas[1].PeriodEnd = time.Now().Add(-time.Second)
	m.mu.Unlock()

	_ = m.Tick(ctx)
	if n := len(p.byType("quota_reset")); n != 1 {
		t.Errorf("reset events = %d; want 1", n)
	}
	// Rollover also zeroed the reader. Simulate new-period traffic and
	// verify the warn latch re-arms.
	m.Reader().Set(10, 900)
	_ = m.Tick(ctx)
	if n := len(p.byType("quota_warning")); n != 2 {
		t.Errorf("warn after rollover = %d; want 2", n)
	}
}

func TestParsePeriod(t *testing.T) {
	cases := map[string]Period{
		"": PeriodDaily, "daily": PeriodDaily, "D": PeriodDaily,
		"hourly": PeriodHourly, "H": PeriodHourly,
		"weekly": PeriodWeekly, "monthly": PeriodMonthly,
	}
	for in, want := range cases {
		got, err := ParsePeriod(in)
		if err != nil {
			t.Errorf("ParsePeriod(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParsePeriod(%q) = %q; want %q", in, got, want)
		}
	}
	if _, err := ParsePeriod("decade"); err == nil {
		t.Error("expected error for unknown period")
	}
}

func TestPeriodWindowMonthly(t *testing.T) {
	now := time.Date(2026, 4, 19, 14, 30, 0, 0, time.UTC)
	s, e := periodWindow(PeriodMonthly, now)
	if s.Day() != 1 || s.Hour() != 0 {
		t.Errorf("monthly start = %v; want Apr 1 00:00", s)
	}
	if e.Month() != time.May || e.Day() != 1 {
		t.Errorf("monthly end = %v; want May 1", e)
	}
}
