package ingress

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// StubManager is the testing / macOS backend. Stores profiles in memory;
// issues no kernel commands.
type StubManager struct {
	Log *slog.Logger

	mu       sync.Mutex
	profiles map[int64]*Profile
}

// NewStub returns an empty stub.
func NewStub(log *slog.Logger) *StubManager {
	if log == nil {
		log = slog.Default()
	}
	return &StubManager{Log: log, profiles: make(map[int64]*Profile)}
}

func (m *StubManager) Name() string { return "stub" }

func (m *StubManager) Create(_ context.Context, p *Profile) (*Profile, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[p.ID]; ok {
		return nil, ErrExists
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	m.profiles[p.ID] = p
	m.Log.Info("ingress profile created (stub)",
		"id", p.ID, "name", p.Name,
		"edge_port", p.EdgePort, "backend", p.BackendIP, "backend_port", p.BackendPort)
	return p, nil
}

func (m *StubManager) Update(_ context.Context, p *Profile) (*Profile, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.profiles[p.ID]
	if !ok {
		return nil, ErrNotFound
	}
	p.CreatedAt = old.CreatedAt
	p.UpdatedAt = time.Now()
	m.profiles[p.ID] = p
	return p, nil
}

func (m *StubManager) Delete(_ context.Context, profileID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[profileID]; !ok {
		return nil
	}
	delete(m.profiles, profileID)
	m.Log.Info("ingress profile deleted (stub)", "id", profileID)
	return nil
}

func (m *StubManager) List() []*Profile {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Profile, 0, len(m.profiles))
	for _, p := range m.profiles {
		cp := *p
		out = append(out, &cp)
	}
	return out
}

var _ Manager = (*StubManager)(nil)
