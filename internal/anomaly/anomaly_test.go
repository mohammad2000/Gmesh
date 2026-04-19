package anomaly

import (
	"io"
	"log/slog"
	"math"
	"testing"
	"time"
)

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRollingStatsMeanStddev(t *testing.T) {
	r := newRollingStats(5)
	// push 1..5, expected mean=3, stddev = sqrt(2.5) ≈ 1.5811
	for _, v := range []float64{1, 2, 3, 4, 5} {
		r.push(v)
	}
	mean, sd := r.meanStddev()
	if math.Abs(mean-3) > 1e-9 {
		t.Errorf("mean = %v; want 3", mean)
	}
	want := math.Sqrt(2.5)
	if math.Abs(sd-want) > 1e-9 {
		t.Errorf("stddev = %v; want %v", sd, want)
	}
}

func TestRollingStatsSliding(t *testing.T) {
	r := newRollingStats(3)
	for _, v := range []float64{1, 2, 3, 10, 100} {
		r.push(v)
	}
	if r.count != 3 {
		t.Errorf("count = %d; want 3 (window cap)", r.count)
	}
	mean, _ := r.meanStddev()
	want := (3.0 + 10 + 100) / 3 // only last three
	if math.Abs(mean-want) > 1e-9 {
		t.Errorf("mean = %v; want %v", mean, want)
	}
}

func TestBandwidthZAlertsOnSpike(t *testing.T) {
	pub := NewStubPublisher()
	d := NewBandwidthZ(BandwidthConfig{
		WindowSize: 10, MinSamples: 5, ZThreshold: 3, Cooldown: time.Minute,
	}, pub)
	// Steady baseline with realistic jitter — a synthetic zero-variance
	// baseline gives stddev=0 and z is undefined; that's the
	// "no-signal-yet" path, covered by a separate test.
	base := time.Now()
	for i, v := range []float64{1_000_000, 1_100_000, 950_000, 1_050_000, 1_000_000, 980_000} {
		d.Observe(BandwidthSample{PeerID: 1, BytesPerS: v, At: base.Add(time.Duration(i) * time.Second)})
	}
	// Enormous spike.
	a := d.Observe(BandwidthSample{PeerID: 1, BytesPerS: 1_000_000_000, At: base.Add(7 * time.Second)})
	if a == nil {
		t.Fatal("expected alert on spike")
	}
	if a.Severity != SeverityCritical {
		t.Errorf("severity = %s; want critical (z is very high)", a.Severity)
	}
	if got := pub.ByDetector("bandwidth_z"); len(got) != 1 {
		t.Errorf("publisher recorded %d; want 1", len(got))
	}
}

func TestBandwidthZQuietDuringWarmup(t *testing.T) {
	pub := NewStubPublisher()
	d := NewBandwidthZ(BandwidthConfig{WindowSize: 20, MinSamples: 10, ZThreshold: 2, Cooldown: time.Minute}, pub)
	// Too few samples to alert even on a huge value.
	for i := 0; i < 3; i++ {
		d.Observe(BandwidthSample{PeerID: 1, BytesPerS: 1e9, At: time.Now()})
	}
	if got := pub.All(); len(got) != 0 {
		t.Errorf("alerts during warmup: %v", got)
	}
}

func TestBandwidthZCooldown(t *testing.T) {
	pub := NewStubPublisher()
	d := NewBandwidthZ(BandwidthConfig{WindowSize: 10, MinSamples: 5, ZThreshold: 3, Cooldown: time.Hour}, pub)
	t0 := time.Now()
	for i, v := range []float64{1_000_000, 1_100_000, 950_000, 1_050_000, 1_000_000, 980_000} {
		d.Observe(BandwidthSample{PeerID: 1, BytesPerS: v, At: t0.Add(time.Duration(i) * time.Second)})
	}
	for i := 0; i < 3; i++ {
		d.Observe(BandwidthSample{PeerID: 1, BytesPerS: 1e9, At: t0.Add(time.Duration(7+i) * time.Second)})
	}
	if got := pub.ByDetector("bandwidth_z"); len(got) != 1 {
		t.Errorf("cooldown failed: got %d alerts; want 1", len(got))
	}
}

func TestHandshakeStormFires(t *testing.T) {
	pub := NewStubPublisher()
	d := NewHandshakeStorm(HandshakeStormConfig{
		Window: 10 * time.Second, Threshold: 3, Cooldown: time.Hour,
	}, pub)
	base := time.Now()
	for i := 0; i < 3; i++ {
		d.Observe(1, base.Add(time.Duration(i)*time.Second))
	}
	if got := pub.All(); len(got) != 0 {
		t.Errorf("alert at threshold; want quiet (%v)", got)
	}
	if a := d.Observe(1, base.Add(4*time.Second)); a == nil {
		t.Fatal("expected alert when count exceeds threshold")
	}
}

func TestHandshakeStormWindowExpiry(t *testing.T) {
	pub := NewStubPublisher()
	d := NewHandshakeStorm(HandshakeStormConfig{
		Window: time.Second, Threshold: 2, Cooldown: time.Millisecond,
	}, pub)
	// Three handshakes well apart should NOT trip a 1-second window.
	d.Observe(1, time.Now())
	d.Observe(1, time.Now().Add(5*time.Second))
	d.Observe(1, time.Now().Add(10*time.Second))
	if got := pub.All(); len(got) != 0 {
		t.Errorf("spaced-out handshakes tripped: %v", got)
	}
}

func TestPeerFlapFires(t *testing.T) {
	pub := NewStubPublisher()
	d := NewPeerFlap(PeerFlapConfig{Window: time.Minute, Threshold: 2, Cooldown: time.Hour}, pub)
	t0 := time.Now()
	d.Observe(1, t0)
	d.Observe(1, t0.Add(time.Second))
	if a := d.Observe(1, t0.Add(2*time.Second)); a == nil {
		t.Fatal("expected flap alert")
	}
}

func TestMonitorRecent(t *testing.T) {
	pub := NewStubPublisher()
	m := New(silent(), Config{
		Bandwidth: BandwidthConfig{WindowSize: 5, MinSamples: 3, ZThreshold: 2, Cooldown: time.Hour},
		Storm:     HandshakeStormConfig{Window: time.Minute, Threshold: 1, Cooldown: time.Hour},
		Flap:      PeerFlapConfig{Window: time.Minute, Threshold: 1, Cooldown: time.Hour},
	}, pub)
	// Seed baseline.
	t0 := time.Now()
	for i := 0; i < 4; i++ {
		m.Bandwidth.Observe(BandwidthSample{PeerID: 1, BytesPerS: 1_000_000, At: t0.Add(time.Duration(i) * time.Second)})
	}
	m.Bandwidth.Observe(BandwidthSample{PeerID: 1, BytesPerS: 1e8, At: t0.Add(5 * time.Second)})
	m.Storm.Observe(2, t0)
	m.Storm.Observe(2, t0.Add(time.Second))
	m.Flap.Observe(3, t0)
	m.Flap.Observe(3, t0.Add(time.Second))

	recent := m.Recent(0)
	if len(recent) != len(pub.All()) {
		t.Errorf("recent=%d pub=%d", len(recent), len(pub.All()))
	}
	if len(m.ForPeer(2)) == 0 {
		t.Error("ForPeer(2) empty")
	}
	sorted := m.RecentSortedByTime()
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Observed.Before(sorted[i-1].Observed) {
			t.Errorf("not sorted at %d", i)
		}
	}
}

func TestMonitorResetClearsState(t *testing.T) {
	pub := NewStubPublisher()
	m := New(silent(), Config{
		Bandwidth: BandwidthConfig{WindowSize: 5, MinSamples: 3, ZThreshold: 2, Cooldown: time.Hour},
	}, pub)
	t0 := time.Now()
	for i := 0; i < 4; i++ {
		m.Bandwidth.Observe(BandwidthSample{PeerID: 1, BytesPerS: 1_000_000, At: t0.Add(time.Duration(i) * time.Second)})
	}
	m.Reset()
	// Post-reset, the spike sample has no baseline → no alert until
	// the warmup fills again.
	if a := m.Bandwidth.Observe(BandwidthSample{PeerID: 1, BytesPerS: 1e10, At: t0.Add(5 * time.Second)}); a != nil {
		t.Error("alert fired after Reset without warmup")
	}
	if len(m.Recent(0)) != 0 {
		t.Error("recent not cleared by Reset")
	}
}

func TestBandwidthSampleForHelper(t *testing.T) {
	got := BandwidthSampleFor(500, 500, 10*time.Second)
	if got != 100 {
		t.Errorf("got=%v; want 100 B/s", got)
	}
	if BandwidthSampleFor(1, 1, 0) != 0 {
		t.Error("zero window should return 0")
	}
}
