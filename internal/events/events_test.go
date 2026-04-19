package events

import (
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func silentBus() *Bus { return NewBus(slog.New(slog.NewTextHandler(io.Discard, nil))) }

func TestBusBasicPubSub(t *testing.T) {
	b := silentBus()
	ch, cancel := b.Subscribe(nil, 8)
	defer cancel()

	b.Publish(New(TypePeerConnected, 42, map[string]any{"method": "direct"}))

	select {
	case ev := <-ch:
		if ev.Type != TypePeerConnected {
			t.Errorf("type = %q", ev.Type)
		}
		if ev.PeerID != 42 {
			t.Errorf("peer_id = %d", ev.PeerID)
		}
		var p map[string]any
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("payload: %v", err)
		}
		if p["method"] != "direct" {
			t.Errorf("payload = %v", p)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for event")
	}
}

func TestBusTypeFilter(t *testing.T) {
	b := silentBus()
	ch, cancel := b.Subscribe([]string{TypeHealthUpdate}, 8)
	defer cancel()

	b.Publish(New(TypePeerConnected, 1, nil)) // filtered out
	b.Publish(New(TypeHealthUpdate, 2, nil))  // passes

	select {
	case ev := <-ch:
		if ev.Type != TypeHealthUpdate {
			t.Errorf("got %q; want %q", ev.Type, TypeHealthUpdate)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out")
	}

	// No more events should arrive.
	select {
	case ev := <-ch:
		t.Errorf("unexpected extra event %q", ev.Type)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBusMultipleSubscribers(t *testing.T) {
	b := silentBus()
	ch1, cancel1 := b.Subscribe(nil, 8)
	defer cancel1()
	ch2, cancel2 := b.Subscribe(nil, 8)
	defer cancel2()

	b.Publish(New(TypeFirewallApplied, 0, nil))

	var wg sync.WaitGroup
	wg.Add(2)
	read := func(ch <-chan Event, name string) {
		defer wg.Done()
		select {
		case <-ch:
		case <-time.After(500 * time.Millisecond):
			t.Errorf("%s: timeout", name)
		}
	}
	go read(ch1, "sub1")
	go read(ch2, "sub2")
	wg.Wait()
}

func TestBusSlowSubscriberDrops(t *testing.T) {
	b := silentBus()
	ch, cancel := b.Subscribe(nil, 2) // tiny buffer
	defer cancel()

	// Publish many events; reader is slow (doesn't read).
	for i := 0; i < 100; i++ {
		b.Publish(New(TypeHealthUpdate, int64(i), nil))
	}

	// First two should be queued.
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("first event missing")
	}
}

func TestBusCancelClosesChannel(t *testing.T) {
	b := silentBus()
	ch, cancel := b.Subscribe(nil, 8)
	cancel()
	if b.SubscriberCount() != 0 {
		t.Errorf("SubscriberCount = %d; want 0", b.SubscriberCount())
	}
	// Channel must be closed.
	_, ok := <-ch
	if ok {
		t.Error("channel should be closed")
	}
}

func TestBusCancelIdempotent(t *testing.T) {
	b := silentBus()
	_, cancel := b.Subscribe(nil, 8)
	cancel()
	cancel() // second call must not panic
}

func TestBusNoSubscribersNoOp(t *testing.T) {
	b := silentBus()
	// Should not panic / block.
	b.Publish(New(TypePeerConnected, 1, nil))
	if b.SubscriberCount() != 0 {
		t.Errorf("count = %d", b.SubscriberCount())
	}
}
