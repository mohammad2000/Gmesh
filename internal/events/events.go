// Package events is gmeshd's in-process pub/sub bus. Publishers — the
// engine, health monitor, scope manager, firewall backend — call
// Bus.Publish with an Event value. Subscribers — primarily the
// SubscribeEvents gRPC handler — call Bus.Subscribe with an optional
// type filter and drain a channel.
//
// Design choices:
//
//   - Bounded per-subscriber buffer (default 256). If a subscriber is
//     slow, newer events drop rather than blocking the publisher. Drops
//     increment a per-subscriber counter and we log once per burst.
//   - Subscribe returns a cancel function. Calling it closes the channel
//     and evicts the subscription atomically; safe to call multiple times.
//   - Zero-cost when there are no subscribers: Publish RLocks, ranges an
//     empty map, returns.
package events

import (
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Event types. These mirror the type strings in docs/protocol.md and map
// onto gmesh.v1.Event.type on the wire. Keep in sync.
const (
	TypePeerConnected     = "peer_connected"
	TypePeerDisconnected  = "peer_disconnected"
	TypePeerMethodChange  = "peer_method_change"
	TypePeerAdded         = "peer_added"
	TypePeerRemoved       = "peer_removed"
	TypeHealthUpdate      = "health_update"
	TypeNATChanged        = "nat_changed"
	TypeFirewallApplied   = "firewall_applied"
	TypeFirewallError     = "firewall_error"
	TypeScopeConnected    = "scope_connected"
	TypeScopeDisconnected = "scope_disconnected"
	TypeRelaySetup        = "relay_setup"
	TypeMeshJoined        = "mesh_joined"
	TypeMeshLeft          = "mesh_left"
)

// Event is one structured notification. Payload is JSON-encoded
// (per-type schema) so subscribers can parse when they care.
type Event struct {
	Timestamp time.Time       `json:"timestamp"`
	Type      string          `json:"type"`
	PeerID    int64           `json:"peer_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// New builds an Event, JSON-encoding the payload. If payload is nil,
// Payload is left empty.
func New(evType string, peerID int64, payload any) Event {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err == nil {
			raw = b
		}
	}
	return Event{
		Timestamp: time.Now().UTC(),
		Type:      evType,
		PeerID:    peerID,
		Payload:   raw,
	}
}

// ── Bus ────────────────────────────────────────────────────────────────

// Bus is a thread-safe event distributor.
type Bus struct {
	Log *slog.Logger

	mu     sync.RWMutex
	subs   map[int64]*subscription
	nextID atomic.Int64
}

type subscription struct {
	id       int64
	filter   map[string]struct{}
	ch       chan Event
	dropped  atomic.Uint64
	canceled atomic.Bool
}

// NewBus returns a new Bus.
func NewBus(log *slog.Logger) *Bus {
	if log == nil {
		log = slog.Default()
	}
	return &Bus{Log: log, subs: make(map[int64]*subscription)}
}

// Publish fans ev out to every matching subscriber. Never blocks; slow
// subscribers drop oldest.
func (b *Bus) Publish(ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.subs {
		if s.canceled.Load() {
			continue
		}
		if len(s.filter) > 0 {
			if _, ok := s.filter[ev.Type]; !ok {
				continue
			}
		}
		select {
		case s.ch <- ev:
		default:
			n := s.dropped.Add(1)
			if n == 1 || n%100 == 0 {
				b.Log.Warn("event dropped (slow subscriber)",
					"sub_id", s.id, "type", ev.Type, "total_dropped", n)
			}
		}
	}
}

// Subscribe registers a new subscriber. typeFilter of nil / empty matches
// all events. bufSize is the per-subscriber channel capacity (defaults to
// 256 when 0). The returned cancel closes the channel and removes the sub.
func (b *Bus) Subscribe(typeFilter []string, bufSize int) (<-chan Event, func()) {
	if bufSize <= 0 {
		bufSize = 256
	}
	filter := make(map[string]struct{}, len(typeFilter))
	for _, t := range typeFilter {
		filter[t] = struct{}{}
	}
	s := &subscription{
		id:     b.nextID.Add(1),
		filter: filter,
		ch:     make(chan Event, bufSize),
	}

	b.mu.Lock()
	b.subs[s.id] = s
	b.mu.Unlock()

	cancel := func() {
		if !s.canceled.CompareAndSwap(false, true) {
			return
		}
		b.mu.Lock()
		delete(b.subs, s.id)
		b.mu.Unlock()
		close(s.ch)
	}
	return s.ch, cancel
}

// SubscriberCount returns how many subscribers are registered.
func (b *Bus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
