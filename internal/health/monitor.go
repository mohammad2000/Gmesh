package health

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/events"
	"github.com/mohammad2000/Gmesh/internal/peer"
)

// PeerSource is a thin abstraction over the engine's peer registry + WG
// stats refresh loop. The Monitor calls RefreshStats once per tick to pick
// up fresh WG dump data, then iterates Snapshot to compute scores.
type PeerSource interface {
	Snapshot() []*peer.Peer
	RefreshStats(ctx context.Context) error
}

// Publisher is what the Monitor emits events through. In production this
// is the engine's events.Bus; in tests it's a collector.
type Publisher interface {
	Publish(ev events.Event)
}

// Monitor polls each peer, computes a health score, detects state
// transitions, and emits events through the Publisher.
//
// State machine per peer:
//
//	                  ┌─────────────┐
//	                  │  UNKNOWN    │
//	                  └─────┬───────┘
//	                        │ first score
//	                        ▼
//	        ┌─────────────────────┐
//	        │ Excellent/Good/...  │  score buckets
//	        └─────┬───────┬──┬────┘
//	              │       │  │
//	              │ score │  │ score drops
//	              │ ↑     │  │ to FAILING
//	              │       │  │ for N ticks
//	              │       ▼  ▼
//	              │   ┌──────────────┐
//	              │   │   FAILING    │ → emit peer_disconnected
//	              │   └───────┬──────┘
//	              └───────────┘
//	              score recovers → emit peer_connected
//
// On every tick we also emit a health_update event so UIs can render
// live gauges without extra polling.
type Monitor struct {
	Source   PeerSource
	Bus      Publisher
	Log      *slog.Logger
	Interval time.Duration // normal tick (default 30s)
	// DegradedInterval is used when ≥1 peer is in the DEGRADED/POOR/FAILING
	// bucket; the loop ticks faster to detect recovery sooner.
	DegradedInterval time.Duration // default 15s
	// FailingTicksBeforeDisconnect is the number of consecutive FAILING
	// scores before we emit peer_disconnected (to absorb brief blips).
	FailingTicksBeforeDisconnect int // default 3
	// StuckThreshold is how long a peer can sit in CONNECTING/ESTABLISHING
	// before we emit peer_stuck. The signal lets the agent (and ultimately
	// the panel) tell the difference between "connection just being
	// established" and "racer has been chewing on candidates for ages and
	// nothing is winning". Default 5 minutes — long enough that a normal
	// hole-punch attempt or relay setup completes well within it, short
	// enough that operators don't sit blind for half an hour.
	StuckThreshold time.Duration // default 5m
	// StuckRepeatInterval is the minimum time between consecutive
	// peer_stuck emissions for the same peer. Without this we'd emit on
	// every tick once threshold is exceeded — noisy and crowds the event
	// channel. Default 5 minutes.
	StuckRepeatInterval time.Duration // default 5m

	mu              sync.Mutex
	failingCount    map[int64]int
	lastStatus      map[int64]Status
	stuckSince      map[int64]time.Time // first time we saw peer in connecting/establishing
	stuckLastEmit   map[int64]time.Time // last peer_stuck emit per peer
	lastPeerStatus  map[int64]peer.Status
}

// NewMonitor returns a Monitor with defaults applied.
func NewMonitor(src PeerSource, bus Publisher, log *slog.Logger) *Monitor {
	if log == nil {
		log = slog.Default()
	}
	return &Monitor{
		Source:                       src,
		Bus:                          bus,
		Log:                          log,
		Interval:                     30 * time.Second,
		DegradedInterval:             15 * time.Second,
		FailingTicksBeforeDisconnect: 3,
		StuckThreshold:               5 * time.Minute,
		StuckRepeatInterval:          5 * time.Minute,
		failingCount:                 map[int64]int{},
		lastStatus:                   map[int64]Status{},
		stuckSince:                   map[int64]time.Time{},
		stuckLastEmit:                map[int64]time.Time{},
		lastPeerStatus:               map[int64]peer.Status{},
	}
}

// Run blocks until ctx is canceled, ticking at Interval (or DegradedInterval
// when any peer is unhealthy) and emitting events.
func (m *Monitor) Run(ctx context.Context) {
	timer := time.NewTimer(m.Interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		anyDegraded := m.Tick(ctx)
		next := m.Interval
		if anyDegraded {
			next = m.DegradedInterval
		}
		timer.Reset(next)
	}
}

// Tick runs one monitoring pass. Exposed for tests. Returns true if any
// peer is below Good.
func (m *Monitor) Tick(ctx context.Context) bool {
	if err := m.Source.RefreshStats(ctx); err != nil {
		m.Log.Debug("refresh peer stats", "error", err)
	}

	any := false
	now := time.Now()
	seen := make(map[int64]struct{})
	for _, p := range m.Source.Snapshot() {
		seen[p.ID] = struct{}{}
		score := scoreForPeer(p)
		status := FromScore(score)
		if status >= StatusDegraded {
			any = true
		}
		m.emit(p, score, status)
		m.checkStuck(p, now)
	}
	// Forget peers that have disappeared from the registry so the maps
	// don't grow unbounded across long uptimes.
	m.mu.Lock()
	for id := range m.stuckSince {
		if _, ok := seen[id]; !ok {
			delete(m.stuckSince, id)
			delete(m.stuckLastEmit, id)
			delete(m.lastPeerStatus, id)
		}
	}
	m.mu.Unlock()
	return any
}

// checkStuck emits peer_stuck when a peer has been in connecting/
// establishing for longer than StuckThreshold. Re-emits at most once
// per StuckRepeatInterval so a peer that's been wedged for an hour
// shows up periodically in the event stream rather than just once at
// the threshold crossing.
func (m *Monitor) checkStuck(p *peer.Peer, now time.Time) {
	if m.StuckThreshold <= 0 {
		return
	}
	stuck := p.Status == peer.StatusConnecting || p.Status == peer.StatusEstablishing

	m.mu.Lock()
	prevStatus, hadPrev := m.lastPeerStatus[p.ID]
	m.lastPeerStatus[p.ID] = p.Status
	if !stuck {
		// Status moved out of the stuck set — clear trackers so a
		// future stall starts a fresh deadline.
		delete(m.stuckSince, p.ID)
		delete(m.stuckLastEmit, p.ID)
		m.mu.Unlock()
		return
	}
	// If the peer just transitioned INTO a stuck status (was something
	// else last tick), reset the timer to "now" so we measure the
	// current stall, not stuck time across status changes.
	if hadPrev && prevStatus != p.Status {
		delete(m.stuckSince, p.ID)
		delete(m.stuckLastEmit, p.ID)
	}
	first, ok := m.stuckSince[p.ID]
	if !ok {
		m.stuckSince[p.ID] = now
		m.mu.Unlock()
		return
	}
	stuckFor := now.Sub(first)
	if stuckFor < m.StuckThreshold {
		m.mu.Unlock()
		return
	}
	lastEmit := m.stuckLastEmit[p.ID]
	if !lastEmit.IsZero() && now.Sub(lastEmit) < m.StuckRepeatInterval {
		m.mu.Unlock()
		return
	}
	m.stuckLastEmit[p.ID] = now
	m.mu.Unlock()

	if m.Bus != nil {
		m.Bus.Publish(events.New(events.TypePeerStuck, p.ID, map[string]any{
			"status":         statusString(p.Status),
			"stuck_for_secs": int64(stuckFor.Seconds()),
			"endpoint":       p.Endpoint,
			"method":         p.Method,
			"threshold_secs": int64(m.StuckThreshold.Seconds()),
		}))
	}
	m.Log.Warn("peer stuck",
		"peer_id", p.ID,
		"status", statusString(p.Status),
		"stuck_for", stuckFor,
		"endpoint", p.Endpoint,
	)
}

func statusString(s peer.Status) string {
	switch s {
	case peer.StatusConnecting:
		return "connecting"
	case peer.StatusConnected:
		return "connected"
	case peer.StatusDisconnected:
		return "disconnected"
	case peer.StatusError:
		return "error"
	case peer.StatusEstablishing:
		return "establishing"
	default:
		return "unspecified"
	}
}

// scoreForPeer computes a score from peer.Peer's current fields.
func scoreForPeer(p *peer.Peer) int {
	methodRank := methodQualityRank(p.Method)
	return Score(Metrics{
		LastHandshake:  p.LastHandshake,
		PingRTT:        time.Duration(p.LatencyMS) * time.Millisecond,
		PingSuccess:    p.LatencyMS > 0, // no ping integration yet; proxy via latency > 0
		RxBytesPerSec:  0,               // Phase 9 adds rate integration
		TxBytesPerSec:  0,
		ConnMethodRank: methodRank,
	})
}

// methodQualityRank maps gmesh.v1.ConnectionMethod enum values to a 0–100
// quality score used as a weight in the health formula.
func methodQualityRank(m int) int {
	// Enum values (keep in sync with proto):
	//   0 unspecified → 50 (don't penalize unknown)
	//   1 direct → 100
	//   2 upnp → 90
	//   3 stun hole-punch → 70
	//   4 simopen → 65
	//   5 birthday → 55
	//   6 relay → 40
	//   7 relay tcp → 35
	//   8 ws tunnel → 25
	switch m {
	case 1:
		return 100
	case 2:
		return 90
	case 3:
		return 70
	case 4:
		return 65
	case 5:
		return 55
	case 6:
		return 40
	case 7:
		return 35
	case 8:
		return 25
	default:
		return 50
	}
}

// emit publishes a health_update event, and state-transition events when
// applicable.
func (m *Monitor) emit(p *peer.Peer, score int, now Status) {
	m.mu.Lock()
	prev := m.lastStatus[p.ID]
	if now == StatusFailing {
		m.failingCount[p.ID]++
	} else {
		m.failingCount[p.ID] = 0
	}
	failingN := m.failingCount[p.ID]
	m.lastStatus[p.ID] = now
	m.mu.Unlock()

	if m.Bus != nil {
		m.Bus.Publish(events.New(events.TypeHealthUpdate, p.ID, map[string]any{
			"score":           score,
			"status":          now.String(),
			"latency_ms":      p.LatencyMS,
			"handshake_age_s": int64(time.Since(p.LastHandshake).Seconds()),
		}))
	}

	// Rising edge: peer moved from FAILING back to OK.
	if prev == StatusFailing && now != StatusFailing && m.Bus != nil {
		m.Bus.Publish(events.New(events.TypePeerConnected, p.ID, map[string]any{
			"score":    score,
			"status":   now.String(),
			"previous": prev.String(),
		}))
	}
	// Falling edge: FAILING for N consecutive ticks.
	if failingN == m.FailingTicksBeforeDisconnect && m.Bus != nil {
		m.Bus.Publish(events.New(events.TypePeerDisconnected, p.ID, map[string]any{
			"score":    score,
			"reason":   "failing for " + intToString(failingN) + " consecutive ticks",
			"previous": prev.String(),
		}))
	}
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 6)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
