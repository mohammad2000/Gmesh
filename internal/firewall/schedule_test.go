package firewall

import (
	"testing"
	"time"
)

func mustParseSchedule(t *testing.T, raw string) *Schedule {
	t.Helper()
	s, err := ParseSchedule(raw)
	if err != nil {
		t.Fatalf("ParseSchedule: %v", err)
	}
	return s
}

func TestScheduleEmptyAlwaysActive(t *testing.T) {
	s := mustParseSchedule(t, "")
	if !s.Active(time.Now()) {
		t.Error("empty schedule should be active")
	}
}

func TestScheduleZeroWindowsAlwaysActive(t *testing.T) {
	s := mustParseSchedule(t, `{"windows": []}`)
	if !s.Active(time.Now()) {
		t.Error("zero-window schedule should be active")
	}
}

func TestScheduleBusinessHoursUTC(t *testing.T) {
	s := mustParseSchedule(t, `{"windows":[{"start":"09:00","end":"17:00","days":["mon","tue","wed","thu","fri"]}]}`)
	// Mon 2026-04-20 10:30 UTC.
	in := time.Date(2026, 4, 20, 10, 30, 0, 0, time.UTC)
	if !s.Active(in) {
		t.Error("should be active at Mon 10:30 UTC")
	}
	// Mon 2026-04-20 17:00 UTC is the boundary (exclusive end).
	bound := time.Date(2026, 4, 20, 17, 0, 0, 0, time.UTC)
	if s.Active(bound) {
		t.Error("17:00 should be exclusive")
	}
	// Saturday.
	sat := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	if s.Active(sat) {
		t.Error("should not be active on Saturday")
	}
}

func TestScheduleWrapsMidnight(t *testing.T) {
	s := mustParseSchedule(t, `{"windows":[{"start":"22:00","end":"06:00","days":["mon","tue","wed","thu","fri","sat","sun"]}]}`)
	t1 := time.Date(2026, 4, 20, 23, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 4, 21, 5, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	if !s.Active(t1) {
		t.Error("23:00 should be in window")
	}
	if !s.Active(t2) {
		t.Error("05:00 next-day should be in window")
	}
	if s.Active(t3) {
		t.Error("10:00 should NOT be in window")
	}
}

func TestScheduleMultipleWindows(t *testing.T) {
	s := mustParseSchedule(t, `{"windows":[
		{"start":"09:00","end":"12:00"},
		{"start":"13:00","end":"17:00"}
	]}`)
	mid := time.Date(2026, 4, 20, 12, 30, 0, 0, time.UTC)
	if s.Active(mid) {
		t.Error("12:30 lunch should NOT be active")
	}
	morning := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	if !s.Active(morning) {
		t.Error("10:00 should be active")
	}
}

func TestScheduleTimezone(t *testing.T) {
	s := mustParseSchedule(t, `{"windows":[{"start":"09:00","end":"17:00"}], "timezone":"America/Montreal"}`)
	// 14:00 UTC on a Monday = 10:00 EDT (UTC-4). Should be active.
	utc := time.Date(2026, 4, 20, 14, 0, 0, 0, time.UTC)
	if !s.Active(utc) {
		t.Error("10:00 Montreal should be active")
	}
	// 04:00 UTC = midnight Montreal. Should be inactive.
	midnight := time.Date(2026, 4, 20, 4, 0, 0, 0, time.UTC)
	if s.Active(midnight) {
		t.Error("00:00 Montreal should be inactive")
	}
}

func TestScheduleInvalidJSON(t *testing.T) {
	if _, err := ParseSchedule("{not json"); err == nil {
		t.Error("expected error")
	}
}

func TestScheduleBadTimeFormat(t *testing.T) {
	if _, err := ParseSchedule(`{"windows":[{"start":"9am","end":"5pm"}]}`); err == nil {
		t.Error("expected error for non-HH:MM")
	}
}

func TestRuleIsLive(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		r    Rule
		want bool
	}{
		{"disabled", Rule{Enabled: false}, false},
		{"no schedule, enabled", Rule{Enabled: true}, true},
		{"expired", Rule{Enabled: true, ExpiresAt: now.Add(-time.Hour).Unix()}, false},
		{"not expired", Rule{Enabled: true, ExpiresAt: now.Add(time.Hour).Unix()}, true},
		{"scheduled active", Rule{Enabled: true, ScheduleRaw: `{"windows":[]}`}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.IsLive(now); got != c.want {
				t.Errorf("IsLive = %v; want %v", got, c.want)
			}
		})
	}
}

func TestFilterLive(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true},
		{ID: 2, Enabled: false},
		{ID: 3, Enabled: true, ExpiresAt: 1},
	}
	live := FilterLive(rules, time.Now())
	if len(live) != 1 || live[0].ID != 1 {
		t.Errorf("live = %+v; want only rule 1", live)
	}
}
