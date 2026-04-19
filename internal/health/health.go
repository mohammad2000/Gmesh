// Package health computes per-peer health scores and classifies them into
// the 5-level status enum (excellent / good / degraded / poor / failing).
//
// Scoring weights (match the Python implementation for continuity):
//
//	 30%  handshake freshness  (fresh <150s, stale >600s)
//	 30%  ping success / RTT
//	 20%  traffic volume
//	 20%  connection-method quality (DIRECT > UPnP > HOLE_PUNCH > RELAY > WS_TUNNEL)
package health

import (
	"time"
)

// Status matches gmesh.v1.HealthStatus.
type Status int

const (
	StatusUnknown Status = iota
	StatusExcellent
	StatusGood
	StatusDegraded
	StatusPoor
	StatusFailing
)

// String returns the lowercase label.
func (s Status) String() string {
	switch s {
	case StatusExcellent:
		return "excellent"
	case StatusGood:
		return "good"
	case StatusDegraded:
		return "degraded"
	case StatusPoor:
		return "poor"
	case StatusFailing:
		return "failing"
	default:
		return "unknown"
	}
}

// FromScore maps a 0..100 score to a Status.
func FromScore(score int) Status {
	switch {
	case score > 90:
		return StatusExcellent
	case score > 70:
		return StatusGood
	case score > 50:
		return StatusDegraded
	case score > 30:
		return StatusPoor
	default:
		return StatusFailing
	}
}

// Metrics is the raw input for scoring.
type Metrics struct {
	LastHandshake  time.Time
	PingRTT        time.Duration
	PingSuccess    bool
	RxBytesPerSec  int64
	TxBytesPerSec  int64
	ConnMethodRank int // 100 = direct, 80 = UPnP, 60 = hole-punch, 40 = relay, 20 = WS tunnel
}

// Score computes a 0..100 score from Metrics. Never panics on zero values.
func Score(m Metrics) int {
	// Handshake freshness: fresh <150s → 30, stale >600s → 0.
	var hsScore int
	if !m.LastHandshake.IsZero() {
		age := time.Since(m.LastHandshake).Seconds()
		switch {
		case age < 150:
			hsScore = 30
		case age > 600:
			hsScore = 0
		default:
			hsScore = int(30.0 * (600.0 - age) / (600.0 - 150.0))
		}
	}

	// Ping: 30 if success && rtt<200ms, else 0.
	var pingScore int
	if m.PingSuccess {
		switch {
		case m.PingRTT < 50*time.Millisecond:
			pingScore = 30
		case m.PingRTT < 200*time.Millisecond:
			pingScore = 20
		case m.PingRTT < 500*time.Millisecond:
			pingScore = 10
		default:
			pingScore = 5
		}
	}

	// Traffic: 20 if >1KB/s in either direction.
	var trafficScore int
	if m.RxBytesPerSec+m.TxBytesPerSec > 1024 {
		trafficScore = 20
	}

	// Connection method: direct rank of 100 → 20; WS-tunnel 20 → 4.
	methodScore := m.ConnMethodRank * 20 / 100

	total := hsScore + pingScore + trafficScore + methodScore
	if total > 100 {
		total = 100
	}
	if total < 0 {
		total = 0
	}
	return total
}
