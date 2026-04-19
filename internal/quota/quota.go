// Package quota implements byte-counter policy attached to egress profiles.
//
// A Quota watches the nftables counter that belongs to a given
// EgressProfile. Every evaluation tick (default 10s) the Manager:
//
//  1. Reads live byte counts (via a CounterReader interface backed by
//     `nft -j list table inet gmesh-egress` on Linux, or in-memory on tests).
//  2. Detects period rollover (hourly/daily/monthly) — zeroes UsedBytes
//     and clears the *_fired latches.
//  3. Compares used vs (limit × threshold) for warn/shift/stop.
//  4. Emits one-shot events on rising edge (so operators / UIs don't get
//     spammed every tick).
//  5. If ShiftAt crossed AND backup_profile_id set, calls into the
//     engine-supplied Switcher to swap exit_peer_id atomically.
//
// # Events
//
//   - quota_warning : used ≥ limit × warn_at
//   - quota_shift   : used ≥ limit × shift_at   (plus automatic profile switch)
//   - quota_stop    : used ≥ limit × stop_at
//   - quota_reset   : period rollover; counters zeroed
//
// # Why "rising edge" only
//
// If a quota stays above warn the entire day, we emit one event at the
// crossing and stay silent until a period rollover. If the operator
// wants to see live usage, they poll GetQuotaUsage or subscribe to
// the health_update stream's quota payload (Phase 13.5 hook).
package quota

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Period enumerates quota reset windows.
type Period string

const (
	PeriodHourly  Period = "hourly"
	PeriodDaily   Period = "daily"
	PeriodWeekly  Period = "weekly"
	PeriodMonthly Period = "monthly"
)

// ParsePeriod normalises + validates a user string.
func ParsePeriod(s string) (Period, error) {
	switch strings.ToLower(s) {
	case "hourly", "h", "1h":
		return PeriodHourly, nil
	case "", "daily", "d", "1d":
		return PeriodDaily, nil
	case "weekly", "w", "1w":
		return PeriodWeekly, nil
	case "monthly", "m", "1mo":
		return PeriodMonthly, nil
	default:
		return "", fmt.Errorf("quota: unknown period %q", s)
	}
}

// Quota is the in-memory state of one policy attached to an egress profile.
type Quota struct {
	ID              int64
	Name            string
	Enabled         bool
	EgressProfileID int64

	Period     Period
	LimitBytes int64
	UsedBytes  int64

	WarnAt  float64 // 0..1
	ShiftAt float64
	StopAt  float64

	BackupProfileID int64

	// HardStop asks the Enforcer to install a DROP rule for the profile's
	// fwmark once StopAt is crossed. When false (the default) crossing
	// StopAt remains event-only, so operator automation can decide what
	// to do. Reset/rollover automatically unblocks.
	HardStop bool

	// Per-period latches so we emit edge events once.
	WarnFired  bool
	ShiftFired bool
	StopFired  bool

	PeriodStart time.Time
	PeriodEnd   time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate ensures the quota is well-formed.
func (q *Quota) Validate() error {
	if q.Name == "" {
		return errors.New("quota: name required")
	}
	if q.EgressProfileID == 0 {
		return errors.New("quota: egress_profile_id required")
	}
	if q.LimitBytes <= 0 {
		return errors.New("quota: limit_bytes must be > 0")
	}
	if _, err := ParsePeriod(string(q.Period)); err != nil {
		return err
	}
	q.Period, _ = ParsePeriod(string(q.Period))
	for _, pair := range []struct {
		name string
		v    float64
	}{
		{"warn_at", q.WarnAt},
		{"shift_at", q.ShiftAt},
		{"stop_at", q.StopAt},
	} {
		if pair.v < 0 || pair.v > 1 {
			return fmt.Errorf("quota: %s out of range [0..1]: %v", pair.name, pair.v)
		}
	}
	if q.ShiftAt > 0 && q.BackupProfileID == 0 {
		return errors.New("quota: shift_at set but backup_profile_id is 0")
	}
	return nil
}

// UsedFraction is used / limit, clamped [0, +∞).
func (q *Quota) UsedFraction() float64 {
	if q.LimitBytes <= 0 {
		return 0
	}
	return float64(q.UsedBytes) / float64(q.LimitBytes)
}

// CounterReader returns the live byte count for an egress profile.
// On Linux this parses `nft -j list table inet gmesh-egress`; in tests
// an in-memory map.
type CounterReader interface {
	// ReadProfileBytes returns the cumulative RX+TX byte count for the
	// given egress profile since the last reset, plus the time the
	// counter was sampled.
	ReadProfileBytes(ctx context.Context, egressProfileID int64) (int64, time.Time, error)

	// Reset zeroes the nft counter for this profile (period rollover).
	Reset(ctx context.Context, egressProfileID int64) error
}

// Switcher swaps an egress profile's exit_peer_id. The quota package
// doesn't know about engine internals — it just calls this.
type Switcher interface {
	SwapExitPeer(ctx context.Context, egressProfileID, newExitPeerID int64) error
}

// Enforcer installs/removes nftables DROP rules keyed by an egress
// profile's fwmark. Quota Manager calls Block when StopAt is crossed
// on a quota with HardStop=true, and Unblock on reset/rollover. The
// package-level fwmarkForProfile helper produces the mark value; the
// enforcer uses it verbatim so egress and quota layers stay in sync.
type Enforcer interface {
	Block(ctx context.Context, egressProfileID int64, mark uint32) error
	Unblock(ctx context.Context, egressProfileID int64) error
	Name() string
}

// fwmarkForProfile mirrors egress.FwMark. Duplicated to avoid an
// import cycle between internal/quota and internal/egress. Must stay
// in lock-step with egress.FwMark.
func fwmarkForProfile(profileID int64) uint32 {
	return 0x10000000 | uint32(profileID&0x0FFFFFFF)
}

// Event is what the Manager publishes. Wrap into events.Event at the
// engine / rpc layer.
type Event struct {
	Type     string // "quota_warning" | "quota_shift" | "quota_stop" | "quota_reset"
	QuotaID  int64
	Payload  map[string]any
}

// Publisher consumes Events.
type Publisher interface {
	Publish(Event)
}

// Manager owns the lifecycle.
type Manager interface {
	Create(ctx context.Context, q *Quota) (*Quota, error)
	Update(ctx context.Context, q *Quota) (*Quota, error)
	Delete(ctx context.Context, id int64) error
	List() []*Quota
	Get(id int64) (*Quota, bool)
	Reset(ctx context.Context, id int64) error

	// Tick runs one evaluation pass across every quota. Exposed for tests.
	Tick(ctx context.Context) error

	// Run loops Tick on the given interval until ctx is canceled.
	Run(ctx context.Context, interval time.Duration)

	Name() string
}

// Errors.
var (
	ErrExists   = errors.New("quota: already exists")
	ErrNotFound = errors.New("quota: not found")
)

// periodWindow computes the (start, end) for the quota's current period.
// daily rolls over at 00:00 UTC; hourly on :00; weekly on Monday 00:00;
// monthly on day 1 00:00.
func periodWindow(p Period, now time.Time) (time.Time, time.Time) {
	n := now.UTC()
	switch p {
	case PeriodHourly:
		start := time.Date(n.Year(), n.Month(), n.Day(), n.Hour(), 0, 0, 0, time.UTC)
		return start, start.Add(time.Hour)
	case PeriodWeekly:
		// ISO week starts Monday.
		days := int(n.Weekday())
		if days == 0 {
			days = 7 // Sunday → treat as day 7
		}
		days--
		start := time.Date(n.Year(), n.Month(), n.Day()-days, 0, 0, 0, 0, time.UTC)
		return start, start.Add(7 * 24 * time.Hour)
	case PeriodMonthly:
		start := time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(0, 1, 0)
		return start, end
	default: // PeriodDaily
		start := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
		return start, start.Add(24 * time.Hour)
	}
}
