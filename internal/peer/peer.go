// Package peer holds the in-memory peer model and the registry that tracks
// every known peer on this node.
package peer

import (
	"sync"
	"time"
)

// Type classifies a peer. Matches gmesh.v1.PeerType.
type Type int

const (
	TypeUnspecified Type = iota
	TypeVM
	TypeScope
)

// Status matches gmesh.v1.PeerStatus.
type Status int

const (
	StatusUnspecified Status = iota
	StatusConnecting
	StatusConnected
	StatusDisconnected
	StatusError
	StatusEstablishing
)

// Peer is the authoritative in-memory record for a remote node.
type Peer struct {
	ID                int64
	Type              Type
	MeshIP            string
	PublicKey         string
	Endpoint          string // host:port
	AllowedIPs        []string
	Status            Status
	Method            int // gmesh.v1.ConnectionMethod
	NATType           int // gmesh.v1.NATType
	SupportsHolePunch bool
	IsRelayCapable    bool
	RxBytes           int64
	TxBytes           int64
	LatencyMS         int64
	PacketLoss        float64
	LastHandshake     time.Time
	ScopeID           int64
	// Internal bookkeeping
	mu sync.RWMutex //nolint:unused // reserved for per-peer locking when we expand
}

// Registry is a thread-safe peer store keyed by peer ID.
type Registry struct {
	mu    sync.RWMutex
	peers map[int64]*Peer
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{peers: make(map[int64]*Peer)} }

// Upsert inserts or updates a peer. Returns the stored pointer.
func (r *Registry) Upsert(p *Peer) *Peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers[p.ID] = p
	return p
}

// Get returns (peer, ok).
func (r *Registry) Get(id int64) (*Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.peers[id]
	return p, ok
}

// Remove deletes a peer, returning the old entry if it existed.
func (r *Registry) Remove(id int64) *Peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peers[id]
	delete(r.peers, id)
	return p
}

// Snapshot returns a shallow copy of every peer. Callers must not mutate.
func (r *Registry) Snapshot() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Peer, 0, len(r.peers))
	for _, p := range r.peers {
		out = append(out, p)
	}
	return out
}

// Count returns the number of tracked peers.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}
