package egress

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// StubManager is the non-Linux + testing backend. Remembers profiles in
// memory; issues no kernel commands.
type StubManager struct {
	Log *slog.Logger

	mu       sync.Mutex
	profiles map[int64]*Profile
}

// NewStub returns an empty stub manager.
func NewStub(log *slog.Logger) *StubManager {
	if log == nil {
		log = slog.Default()
	}
	return &StubManager{Log: log, profiles: make(map[int64]*Profile)}
}

// Name returns "stub".
func (m *StubManager) Name() string { return "stub" }

// Create stores p. Returns ErrExists on collision.
func (m *StubManager) Create(_ context.Context, p *Profile, exitIP, iface string) (*Profile, error) {
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
	m.Log.Info("egress profile created (stub)",
		"id", p.ID, "name", p.Name, "source", p.Source(),
		"exit_peer_ip", exitIP, "iface", iface)
	return p, nil
}

// Update replaces an existing profile.
func (m *StubManager) Update(_ context.Context, p *Profile, exitIP, iface string) (*Profile, error) {
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
	m.Log.Info("egress profile updated (stub)",
		"id", p.ID, "iface", iface, "exit_ip", exitIP)
	return p, nil
}

// Delete removes the profile. Idempotent.
func (m *StubManager) Delete(_ context.Context, profileID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[profileID]; !ok {
		return nil
	}
	delete(m.profiles, profileID)
	m.Log.Info("egress profile deleted (stub)", "id", profileID)
	return nil
}

// List returns a snapshot.
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

// ── Exit side ────────────────────────────────────────────────────────

// StubExitManager tracks enable/disable state but does nothing on the kernel.
type StubExitManager struct {
	Log *slog.Logger

	mu       sync.Mutex
	enabled  bool
	allowed  []int64
	iface    string
}

// NewStubExit returns a stub exit manager.
func NewStubExit(log *slog.Logger) *StubExitManager {
	if log == nil {
		log = slog.Default()
	}
	return &StubExitManager{Log: log}
}

func (m *StubExitManager) Name() string { return "stub" }

func (m *StubExitManager) Enable(_ context.Context, iface string, allowed []int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = true
	m.iface = iface
	m.allowed = append([]int64(nil), allowed...)
	m.Log.Info("exit enabled (stub)", "iface", iface, "allowed", allowed)
	return nil
}

func (m *StubExitManager) Disable(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return nil
	}
	m.enabled = false
	m.Log.Info("exit disabled (stub)")
	return nil
}

func (m *StubExitManager) IsEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

// ensure the stub satisfies the interface.
var _ Manager = (*StubManager)(nil)
var _ ExitManager = (*StubExitManager)(nil)

// appease the linter for the fmt import while keeping room for future
// printf-style log messages.
var _ = fmt.Sprintf
