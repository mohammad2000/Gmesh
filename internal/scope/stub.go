package scope

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/crypto"
)

// StubManager is the non-Linux / testing backend. No kernel side-effects —
// it just tracks Peer entries in memory so the RPC surface + engine
// integration still work on dev hosts.
type StubManager struct {
	Log *slog.Logger

	mu    sync.Mutex
	peers map[int64]*Peer
}

// NewStub returns an empty stub manager.
func NewStub(log *slog.Logger) *StubManager {
	if log == nil {
		log = slog.Default()
	}
	return &StubManager{Log: log, peers: make(map[int64]*Peer)}
}

// Name returns "stub".
func (m *StubManager) Name() string { return "stub" }

// Connect generates a real WG keypair (via crypto package) but does no
// kernel operations — just stores the Peer.
func (m *StubManager) Connect(_ context.Context, s Spec) (*Peer, error) {
	m.mu.Lock()
	if _, ok := m.peers[s.ScopeID]; ok {
		m.mu.Unlock()
		return nil, ErrAlreadyConnected
	}
	m.mu.Unlock()

	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	netns := s.Netns
	if netns == "" {
		netns = fmt.Sprintf("scope-%d", s.ScopeID)
	}
	p := &Peer{
		ID:            s.ScopeID,
		Netns:         netns,
		MeshIP:        s.MeshIP,
		VethHost:      fmt.Sprintf("vh-s%d", s.ScopeID),
		VethScope:     fmt.Sprintf("vs-s%d", s.ScopeID),
		VethCIDR:      s.VethCIDR,
		VMVethIP:      s.VMVethIP,
		ScopeVethIP:   s.ScopeVethIP,
		GatewayMeshIP: s.GatewayMeshIP,
		PublicKey:     kp.Public,
		PrivateKey:    kp.Private,
		ListenPort:    s.ListenPort,
		CreatedAt:     time.Now(),
	}

	m.mu.Lock()
	m.peers[s.ScopeID] = p
	m.mu.Unlock()
	m.Log.Info("scope connected (stub)", "id", s.ScopeID, "mesh_ip", s.MeshIP)
	return p, nil
}

// Disconnect removes the tracked peer.
func (m *StubManager) Disconnect(_ context.Context, scopeID int64) error {
	m.mu.Lock()
	_, ok := m.peers[scopeID]
	delete(m.peers, scopeID)
	m.mu.Unlock()
	if !ok {
		return ErrNotConnected
	}
	m.Log.Info("scope disconnected (stub)", "id", scopeID)
	return nil
}

// List returns a snapshot of connected scopes.
func (m *StubManager) List() []*Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Peer, 0, len(m.peers))
	for _, p := range m.peers {
		out = append(out, p)
	}
	return out
}
