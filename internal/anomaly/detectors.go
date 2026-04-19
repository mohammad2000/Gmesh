package anomaly

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// BandwidthConfig tunes BandwidthZ.
type BandwidthConfig struct {
	// WindowSize is the number of samples held per peer. At one sample
	// every 10 s, a window of 30 covers 5 minutes.
	WindowSize int
	// ZThreshold is the z-score absolute value at which an alert fires.
	// 3.0 = classic "3-sigma", fires roughly on top-0.3% samples if the
	// stream were Gaussian. Bandwidth is rarely Gaussian — operators
	// tend to start at 4.0 and tune down.
	ZThreshold float64
	// MinSamples is how many observations must land before the
	// detector is allowed to alert. Avoids firing on the first blip.
	MinSamples int
	// Cooldown prevents re-firing for the same peer within this window.
	Cooldown time.Duration
}

func (c BandwidthConfig) defaults() BandwidthConfig {
	if c.WindowSize <= 0 {
		c.WindowSize = 30
	}
	if c.ZThreshold <= 0 {
		c.ZThreshold = 4.0
	}
	if c.MinSamples <= 0 {
		c.MinSamples = 6
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 60 * time.Second
	}
	return c
}

// BandwidthSample is one observation for BandwidthZ.
type BandwidthSample struct {
	PeerID    int64
	BytesPerS float64
	At        time.Time
}

// BandwidthZ tracks per-peer bytes/sec and alerts when the current
// sample is further than Cfg.ZThreshold sigmas from the rolling mean.
type BandwidthZ struct {
	Cfg BandwidthConfig
	Pub Publisher

	mu    sync.Mutex
	perID map[int64]*rollingStats
	cd    *cooldown
}

// NewBandwidthZ returns a ready detector. Pass a Publisher or nil
// (alerts are computed and dropped — useful for tests of fillRatio
// behaviour).
func NewBandwidthZ(cfg BandwidthConfig, pub Publisher) *BandwidthZ {
	cfg = cfg.defaults()
	return &BandwidthZ{
		Cfg: cfg, Pub: pub,
		perID: map[int64]*rollingStats{},
		cd:    newCooldown(cfg.Cooldown),
	}
}

// Name implements Detector.
func (d *BandwidthZ) Name() string { return "bandwidth_z" }

// Reset clears history — call on a peer remove/reconnect to avoid
// false positives from stale baselines.
func (d *BandwidthZ) Reset() {
	d.mu.Lock()
	d.perID = map[int64]*rollingStats{}
	d.mu.Unlock()
}

// Observe integrates one sample. Returns the Alert if one fired
// (caller can see it in tests); the same Alert is also Published.
func (d *BandwidthZ) Observe(s BandwidthSample) *Alert {
	d.mu.Lock()
	rs, ok := d.perID[s.PeerID]
	if !ok {
		rs = newRollingStats(d.Cfg.WindowSize)
		d.perID[s.PeerID] = rs
	}
	// Capture the CURRENT mean + stddev BEFORE pushing the new sample.
	// Otherwise the new sample influences its own comparison.
	mean, stddev := rs.meanStddev()
	rs.push(s.BytesPerS)
	coldFill := float64(d.Cfg.MinSamples) / float64(d.Cfg.WindowSize)
	ratio := rs.fillRatio()
	d.mu.Unlock()
	if ratio < coldFill {
		return nil // still warming up
	}
	z := zScore(s.BytesPerS, mean, stddev)
	if math.Abs(z) < d.Cfg.ZThreshold {
		return nil
	}
	at := s.At
	if at.IsZero() {
		at = time.Now()
	}
	if !d.cd.allow(s.PeerID, at) {
		return nil
	}
	sev := SeverityWarn
	if math.Abs(z) > d.Cfg.ZThreshold*1.5 {
		sev = SeverityCritical
	}
	a := Alert{
		Detector: d.Name(), PeerID: s.PeerID, Severity: sev,
		Observed: at,
		Message: fmt.Sprintf("bandwidth z=%.2f (value=%.0f B/s, baseline mean=%.0f σ=%.0f)",
			z, s.BytesPerS, mean, stddev),
		Metrics: map[string]float64{
			"bytes_per_s": s.BytesPerS,
			"mean":        mean,
			"stddev":      stddev,
			"z":           z,
		},
	}
	if d.Pub != nil {
		d.Pub.Publish(a)
	}
	return &a
}

// ── HandshakeStorm ────────────────────────────────────────────────────

// HandshakeStormConfig tunes the detector.
type HandshakeStormConfig struct {
	// Window is the time span we count handshakes over.
	Window time.Duration
	// Threshold is the count above which we alert.
	Threshold int
	Cooldown  time.Duration
}

func (c HandshakeStormConfig) defaults() HandshakeStormConfig {
	if c.Window <= 0 {
		c.Window = 60 * time.Second
	}
	if c.Threshold <= 0 {
		c.Threshold = 10
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 120 * time.Second
	}
	return c
}

// HandshakeStorm counts per-peer handshake events in a sliding window.
// Fires when count > Threshold. Useful for spotting key-churn bugs or
// a peer hammering the local gmeshd.
type HandshakeStorm struct {
	Cfg HandshakeStormConfig
	Pub Publisher

	mu        sync.Mutex
	timestamps map[int64][]time.Time
	cd        *cooldown
}

// NewHandshakeStorm returns a ready detector.
func NewHandshakeStorm(cfg HandshakeStormConfig, pub Publisher) *HandshakeStorm {
	cfg = cfg.defaults()
	return &HandshakeStorm{
		Cfg: cfg, Pub: pub,
		timestamps: map[int64][]time.Time{},
		cd:         newCooldown(cfg.Cooldown),
	}
}

// Name implements Detector.
func (d *HandshakeStorm) Name() string { return "handshake_storm" }

// Reset implements Detector.
func (d *HandshakeStorm) Reset() {
	d.mu.Lock()
	d.timestamps = map[int64][]time.Time{}
	d.mu.Unlock()
}

// Observe records a handshake event for peerID. Returns an Alert when
// the window count exceeds the threshold.
func (d *HandshakeStorm) Observe(peerID int64, at time.Time) *Alert {
	if at.IsZero() {
		at = time.Now()
	}
	d.mu.Lock()
	list := d.timestamps[peerID]
	cutoff := at.Add(-d.Cfg.Window)
	// Drop timestamps older than the window.
	fresh := list[:0]
	for _, t := range list {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, at)
	d.timestamps[peerID] = fresh
	count := len(fresh)
	d.mu.Unlock()

	if count <= d.Cfg.Threshold {
		return nil
	}
	if !d.cd.allow(peerID, at) {
		return nil
	}
	sev := SeverityWarn
	if count > d.Cfg.Threshold*2 {
		sev = SeverityCritical
	}
	a := Alert{
		Detector: d.Name(), PeerID: peerID, Severity: sev,
		Observed: at,
		Message: fmt.Sprintf("%d handshakes in %s (threshold=%d)",
			count, d.Cfg.Window, d.Cfg.Threshold),
		Metrics: map[string]float64{
			"count":       float64(count),
			"window_sec":  d.Cfg.Window.Seconds(),
			"threshold":   float64(d.Cfg.Threshold),
		},
	}
	if d.Pub != nil {
		d.Pub.Publish(a)
	}
	return &a
}

// ── PeerFlap ──────────────────────────────────────────────────────────

// PeerFlapConfig tunes the detector.
type PeerFlapConfig struct {
	Window    time.Duration
	Threshold int
	Cooldown  time.Duration
}

func (c PeerFlapConfig) defaults() PeerFlapConfig {
	if c.Window <= 0 {
		c.Window = 5 * time.Minute
	}
	if c.Threshold <= 0 {
		c.Threshold = 4 // 4 up-down transitions in 5 min = flapping
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 5 * time.Minute
	}
	return c
}

// PeerFlap counts path_up/path_down transitions per peer within the
// window. Alerts when count exceeds the threshold.
type PeerFlap struct {
	Cfg PeerFlapConfig
	Pub Publisher

	mu        sync.Mutex
	timestamps map[int64][]time.Time
	cd        *cooldown
}

// NewPeerFlap returns a ready detector.
func NewPeerFlap(cfg PeerFlapConfig, pub Publisher) *PeerFlap {
	cfg = cfg.defaults()
	return &PeerFlap{
		Cfg: cfg, Pub: pub,
		timestamps: map[int64][]time.Time{},
		cd:         newCooldown(cfg.Cooldown),
	}
}

// Name implements Detector.
func (d *PeerFlap) Name() string { return "peer_flap" }

// Reset implements Detector.
func (d *PeerFlap) Reset() {
	d.mu.Lock()
	d.timestamps = map[int64][]time.Time{}
	d.mu.Unlock()
}

// Observe records one path_up or path_down transition and returns an
// Alert when the count in the window exceeds Threshold.
func (d *PeerFlap) Observe(peerID int64, at time.Time) *Alert {
	if at.IsZero() {
		at = time.Now()
	}
	d.mu.Lock()
	list := d.timestamps[peerID]
	cutoff := at.Add(-d.Cfg.Window)
	fresh := list[:0]
	for _, t := range list {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, at)
	d.timestamps[peerID] = fresh
	count := len(fresh)
	d.mu.Unlock()

	if count <= d.Cfg.Threshold {
		return nil
	}
	if !d.cd.allow(peerID, at) {
		return nil
	}
	sev := SeverityWarn
	if count > d.Cfg.Threshold*2 {
		sev = SeverityCritical
	}
	a := Alert{
		Detector: d.Name(), PeerID: peerID, Severity: sev,
		Observed: at,
		Message: fmt.Sprintf("%d up/down transitions in %s (threshold=%d)",
			count, d.Cfg.Window, d.Cfg.Threshold),
		Metrics: map[string]float64{
			"transitions": float64(count),
			"window_sec":  d.Cfg.Window.Seconds(),
			"threshold":   float64(d.Cfg.Threshold),
		},
	}
	if d.Pub != nil {
		d.Pub.Publish(a)
	}
	return &a
}
