package health

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/mohammad2000/Gmesh/internal/events"
	"github.com/mohammad2000/Gmesh/internal/peer"
)

// fakeSource backs a Monitor with a controllable peer list.
type fakeSource struct {
	mu    sync.Mutex
	peers []*peer.Peer
}

func (f *fakeSource) Snapshot() []*peer.Peer {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*peer.Peer, len(f.peers))
	copy(out, f.peers)
	return out
}
func (f *fakeSource) RefreshStats(_ context.Context) error { return nil }
func (f *fakeSource) set(ps []*peer.Peer) {
	f.mu.Lock()
	f.peers = ps
	f.mu.Unlock()
}

// collector implements Publisher by buffering every Event.
type collector struct {
	mu     sync.Mutex
	events []events.Event
}

func (c *collector) Publish(ev events.Event) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
}
func (c *collector) byType(t string) []events.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []events.Event
	for _, e := range c.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}
func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func silentLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestMonitorEmitsHealthUpdate(t *testing.T) {
	src := &fakeSource{peers: []*peer.Peer{
		{ID: 1, MeshIP: "10.200.0.1", Method: 1 /* DIRECT */, LastHandshake: time.Now(), LatencyMS: 20},
	}}
	bus := &collector{}
	m := NewMonitor(src, bus, silentLog())

	m.Tick(context.Background())

	if bus.count() != 1 {
		t.Fatalf("events = %d; want 1", bus.count())
	}
	ev := bus.byType(events.TypeHealthUpdate)
	if len(ev) != 1 {
		t.Fatalf("health_update count = %d", len(ev))
	}
	var p map[string]any
	_ = json.Unmarshal(ev[0].Payload, &p)
	if p["status"] == "" {
		t.Error("missing status in payload")
	}
	if p["score"] == nil {
		t.Error("missing score in payload")
	}
}

func TestMonitorFailingFallingEdge(t *testing.T) {
	// Peer with zero handshake + failed ping → FAILING score.
	src := &fakeSource{peers: []*peer.Peer{
		{ID: 1, Method: 8 /* WS_TUNNEL */, LatencyMS: 0 /* no ping */},
	}}
	bus := &collector{}
	m := NewMonitor(src, bus, silentLog())
	m.FailingTicksBeforeDisconnect = 3

	for i := 0; i < 3; i++ {
		m.Tick(context.Background())
	}

	disc := bus.byType(events.TypePeerDisconnected)
	if len(disc) != 1 {
		t.Fatalf("peer_disconnected events = %d; want 1 (after 3 ticks)", len(disc))
	}
	var p map[string]any
	_ = json.Unmarshal(disc[0].Payload, &p)
	if p["previous"] != "failing" {
		t.Errorf("previous = %v; want 'failing'", p["previous"])
	}
}

func TestMonitorRisingEdgeReconnect(t *testing.T) {
	src := &fakeSource{}
	bus := &collector{}
	m := NewMonitor(src, bus, silentLog())
	m.FailingTicksBeforeDisconnect = 2

	// Start in FAILING.
	p := &peer.Peer{ID: 1, Method: 8, LatencyMS: 0}
	src.set([]*peer.Peer{p})
	m.Tick(context.Background())
	m.Tick(context.Background())

	// Flip to healthy.
	p.Method = 1 // DIRECT
	p.LastHandshake = time.Now()
	p.LatencyMS = 25
	m.Tick(context.Background())

	conn := bus.byType(events.TypePeerConnected)
	if len(conn) != 1 {
		t.Fatalf("peer_connected events = %d; want 1", len(conn))
	}
}

func TestMonitorDegradedTriggersFastTick(t *testing.T) {
	src := &fakeSource{peers: []*peer.Peer{
		{ID: 1, Method: 6 /* RELAY */, LatencyMS: 0},
	}}
	bus := &collector{}
	m := NewMonitor(src, bus, silentLog())

	any := m.Tick(context.Background())
	if !any {
		t.Error("expected anyDegraded=true for RELAY+no-ping peer")
	}
}

func TestMonitorNoPeersEmitsNothing(t *testing.T) {
	src := &fakeSource{}
	bus := &collector{}
	m := NewMonitor(src, bus, silentLog())
	m.Tick(context.Background())
	if bus.count() != 0 {
		t.Errorf("unexpected events: %d", bus.count())
	}
}

func TestMethodQualityRank(t *testing.T) {
	cases := map[int]int{
		1: 100, // direct
		2: 90,  // upnp
		3: 70,  // stun
		6: 40,  // relay
		8: 25,  // ws
		0: 50,  // unknown
	}
	for method, want := range cases {
		if got := methodQualityRank(method); got != want {
			t.Errorf("methodQualityRank(%d) = %d; want %d", method, got, want)
		}
	}
}
