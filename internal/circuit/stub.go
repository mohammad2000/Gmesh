package circuit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// StubManager is the in-memory backend used on non-Linux builds and in
// tests. It performs validation + bookkeeping exactly like the real
// Linux backend but touches no kernel state.
type StubManager struct {
	Log *slog.Logger

	mu       sync.Mutex
	circuits map[int64]*Circuit
}

// NewStub returns an empty StubManager.
func NewStub(log *slog.Logger) *StubManager {
	if log == nil {
		log = slog.Default()
	}
	return &StubManager{Log: log, circuits: map[int64]*Circuit{}}
}

// Name implements Manager.
func (m *StubManager) Name() string { return "stub" }

// Create implements Manager.
func (m *StubManager) Create(_ context.Context, c *Circuit, _ string, _ string, localPeerID int64) (*Circuit, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.circuits[c.ID]; ok {
		return nil, ErrExists
	}
	now := time.Now()
	c.CreatedAt = now
	c.UpdatedAt = now
	m.circuits[c.ID] = c
	m.Log.Info("circuit installed (stub)",
		"id", c.ID, "name", c.Name,
		"role", c.RoleFor(localPeerID),
		"path", FormatHops(c.Source, c.Hops))
	return c, nil
}

// Update implements Manager.
func (m *StubManager) Update(_ context.Context, c *Circuit, _ string, _ string, _ int64) (*Circuit, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.circuits[c.ID]
	if !ok {
		return nil, ErrNotFound
	}
	c.CreatedAt = old.CreatedAt
	c.UpdatedAt = time.Now()
	m.circuits[c.ID] = c
	return c, nil
}

// Delete implements Manager.
func (m *StubManager) Delete(_ context.Context, circuitID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.circuits, circuitID)
	return nil
}

// List implements Manager.
func (m *StubManager) List() []*Circuit {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Circuit, 0, len(m.circuits))
	for _, c := range m.circuits {
		cp := *c
		out = append(out, &cp)
	}
	return out
}

var _ Manager = (*StubManager)(nil)
