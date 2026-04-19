package pathmon

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestTargetValidate(t *testing.T) {
	cases := []struct {
		name string
		tg   Target
		err  bool
	}{
		{"missing peer_id", Target{MeshIP: "10.0.0.1"}, true},
		{"missing mesh_ip", Target{PeerID: 1}, true},
		{"ok", Target{PeerID: 1, MeshIP: "10.0.0.1"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.tg.Validate() != nil
			if got != c.err {
				t.Errorf("err=%v want=%v", got, c.err)
			}
		})
	}
}

func TestHysteresisDownThresholdNotReachedStaysUp(t *testing.T) {
	pub := NewStubPublisher()
	prober := NewStubProber()
	m := New(silent(), Config{DownThreshold: 3, UpThreshold: 2, WindowSize: 10}, prober, pub)
	_ = m.AddTarget(Target{PeerID: 1, MeshIP: "10.0.0.1"})

	// 2 ups to go into Up state, then 2 fails (below DownThreshold).
	prober.PushUp(1, 5*time.Millisecond)
	prober.PushUp(1, 5*time.Millisecond)
	prober.PushDown(1, "icmp timeout")
	prober.PushDown(1, "icmp timeout")
	for i := 0; i < 4; i++ {
		m.Tick(context.Background())
	}
	st, _ := m.Get(1)
	if st.Status != StatusUp {
		t.Errorf("status = %s; want up (2 fails < 3 DownThreshold)", st.Status)
	}
	if len(pub.ByType("path_down")) != 0 {
		t.Error("path_down fired below threshold")
	}
}

func TestTransitionUpThenDown(t *testing.T) {
	pub := NewStubPublisher()
	prober := NewStubProber()
	m := New(silent(), Config{DownThreshold: 3, UpThreshold: 2, WindowSize: 10}, prober, pub)
	_ = m.AddTarget(Target{PeerID: 1, MeshIP: "10.0.0.1"})

	prober.PushUp(1, 10*time.Millisecond)
	prober.PushUp(1, 10*time.Millisecond)
	m.Tick(context.Background())
	m.Tick(context.Background())

	ups := pub.ByType("path_up")
	if len(ups) != 1 {
		t.Fatalf("path_up fires = %d; want 1", len(ups))
	}

	prober.PushDown(1, "x")
	prober.PushDown(1, "x")
	prober.PushDown(1, "x")
	m.Tick(context.Background())
	m.Tick(context.Background())
	m.Tick(context.Background())
	downs := pub.ByType("path_down")
	if len(downs) != 1 {
		t.Fatalf("path_down fires = %d; want 1", len(downs))
	}
	st, _ := m.Get(1)
	if st.Status != StatusDown {
		t.Errorf("status = %s; want down", st.Status)
	}
}

func TestListenerCalledOnTransition(t *testing.T) {
	pub := NewStubPublisher()
	prober := NewStubProber()
	m := New(silent(), Config{DownThreshold: 2, UpThreshold: 1, WindowSize: 5}, prober, pub)
	_ = m.AddTarget(Target{PeerID: 1, MeshIP: "10.0.0.1"})

	var got []string
	m.AddListener(func(_ context.Context, ev Event) {
		got = append(got, ev.Type)
	})

	prober.PushUp(1, 1*time.Millisecond)
	m.Tick(context.Background())
	if len(got) != 1 || got[0] != "path_up" {
		t.Errorf("listener got = %v; want [path_up]", got)
	}
}

func TestLossPctTracked(t *testing.T) {
	prober := NewStubProber()
	m := New(silent(), Config{WindowSize: 4, DownThreshold: 10, UpThreshold: 10}, prober, nil)
	_ = m.AddTarget(Target{PeerID: 1, MeshIP: "10.0.0.1"})

	prober.PushUp(1, 1*time.Millisecond)
	prober.PushDown(1, "x")
	prober.PushDown(1, "x")
	prober.PushUp(1, 1*time.Millisecond)
	for i := 0; i < 4; i++ {
		m.Tick(context.Background())
	}
	st, _ := m.Get(1)
	if st.LossPct != 50 {
		t.Errorf("loss_pct = %v; want 50", st.LossPct)
	}
	if st.Samples != 4 {
		t.Errorf("samples = %d; want 4", st.Samples)
	}
}

func TestAddRemoveTarget(t *testing.T) {
	m := New(silent(), Config{}, NewStubProber(), nil)
	_ = m.AddTarget(Target{PeerID: 1, MeshIP: "10.0.0.1"})
	_ = m.AddTarget(Target{PeerID: 2, MeshIP: "10.0.0.2"})
	if len(m.List()) != 2 {
		t.Errorf("list len = %d; want 2", len(m.List()))
	}
	m.RemoveTarget(1)
	if _, ok := m.Get(1); ok {
		t.Error("Get(1) should be false after Remove")
	}
	if len(m.List()) != 1 {
		t.Errorf("list len after remove = %d; want 1", len(m.List()))
	}
}
