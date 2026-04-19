// Package pathmon actively probes each mesh peer and tracks status
// transitions so higher layers (egress switcher, health score, kill
// switch) can react to path failure instead of discovering it lazily
// from a timed-out TCP connection.
//
// The monitor is intentionally small:
//
//   - A Prober (ICMP ping on Linux, Stub in tests) measures RTT + up/down
//     per (peer, target) at a fixed interval.
//   - A sliding window of ProbeHistory retains the last N samples; a
//     hysteretic rule transitions a target between Up and Down so a
//     single dropped packet doesn't flap a production failover.
//   - Transitions emit Events via a Publisher; a Listener callback lets
//     other subsystems (egress, quota, health) react without importing
//     the pathmon package.
//
// # Why not reuse internal/health
//
// Health scoring is a cold, polled summary — it tells a UI "peer looks
// ok". Path monitoring is a hot, edge-triggered signal — it tells the
// switcher "right now, stop sending through this peer." They share
// ideas (RTT, liveness) but differ in cadence and failure mode. The
// health package keeps its slow 0..100 score; pathmon exposes binary
// up/down + consecutive-miss counters.
package pathmon

import (
	"context"
	"errors"
	"time"
)

// Target identifies one thing to probe. MeshIP is the ping destination;
// PeerID is the stable identity the engine understands.
type Target struct {
	PeerID      int64
	Name        string
	MeshIP      string
	Kind        string // "peer" | "gateway" | other labels
	IntervalSec int    // 0 → Monitor default
}

// Validate checks required fields.
func (t *Target) Validate() error {
	if t.PeerID == 0 {
		return errors.New("pathmon: peer_id required")
	}
	if t.MeshIP == "" {
		return errors.New("pathmon: mesh_ip required")
	}
	return nil
}

// Result is one probe's output.
type Result struct {
	RTT    time.Duration
	Up     bool
	When   time.Time
	Error  string // populated when Up=false with a short reason
}

// Status is the hysteretic status of a target.
type Status int

const (
	StatusUnknown Status = iota
	StatusUp
	StatusDown
)

// String returns the lowercase label.
func (s Status) String() string {
	switch s {
	case StatusUp:
		return "up"
	case StatusDown:
		return "down"
	default:
		return "unknown"
	}
}

// State is the live view of one target.
type State struct {
	Target           Target
	Status           Status
	ConsecutiveOK    int
	ConsecutiveFail  int
	LastRTT          time.Duration
	LastSampleAt     time.Time
	LastUpAt         time.Time
	LastDownAt       time.Time
	LossPct          float64 // rolling window loss percentage (0..100)
	Samples          int     // number of samples in the rolling window
}

// Event is emitted on status transitions (Up→Down, Down→Up).
// Callers wrap it into events.Event at the engine boundary.
type Event struct {
	Type    string  // "path_up" | "path_down"
	PeerID  int64
	MeshIP  string
	RTT     time.Duration
	LossPct float64
	At      time.Time
}

// Publisher sinks events.
type Publisher interface {
	Publish(Event)
}

// Listener is a narrow callback the engine registers so it can trigger
// a switcher / kill-switch without importing pathmon-internal types.
type Listener func(ctx context.Context, ev Event)

// Prober executes a single probe. Implementations must be fast (< 2s)
// and must not panic; a dead network → (0, false, nil).
type Prober interface {
	Probe(ctx context.Context, target Target) Result
	Name() string
}

// Config tunes monitor behaviour. Zero values use safe defaults.
type Config struct {
	Interval    time.Duration // default 5s
	Timeout     time.Duration // default 1s per probe
	WindowSize  int           // default 10 — rolling history size per target
	UpThreshold int           // default 2 — consecutive OKs needed to flip Down→Up
	DownThreshold int         // default 3 — consecutive fails needed to flip Up→Down
}

func (c Config) defaults() Config {
	if c.Interval <= 0 {
		c.Interval = 5 * time.Second
	}
	if c.Timeout <= 0 {
		c.Timeout = 1 * time.Second
	}
	if c.WindowSize <= 0 {
		c.WindowSize = 10
	}
	if c.UpThreshold <= 0 {
		c.UpThreshold = 2
	}
	if c.DownThreshold <= 0 {
		c.DownThreshold = 3
	}
	return c
}
