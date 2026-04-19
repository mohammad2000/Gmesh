package firewall

import (
	"context"
	"sync"
	"time"
)

// MemoryBackend is a no-op firewall that just remembers what was applied.
// Useful on non-Linux dev hosts and for unit tests that assert the
// translator was called with the expected live ruleset.
type MemoryBackend struct {
	mu            sync.Mutex
	ensureCalls   int
	applyCalls    int
	resetCalls    int
	lastRules     []Rule
	lastPolicy    string
	lastAppliedAt time.Time
}

// NewMemory returns an empty in-memory backend.
func NewMemory() *MemoryBackend { return &MemoryBackend{} }

// Name returns "memory".
func (m *MemoryBackend) Name() string { return "memory" }

// Ensure is a no-op that increments the ensureCalls counter.
func (m *MemoryBackend) Ensure(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureCalls++
	return nil
}

// Apply remembers the live ruleset + policy.
func (m *MemoryBackend) Apply(_ context.Context, rules []Rule, policy string) (int, int, []error) {
	live := FilterLive(rules, time.Now())
	m.mu.Lock()
	m.applyCalls++
	m.lastRules = append(m.lastRules[:0], live...)
	m.lastPolicy = policy
	m.lastAppliedAt = time.Now()
	m.mu.Unlock()
	return len(live), 0, nil
}

// Reset clears remembered state.
func (m *MemoryBackend) Reset(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetCalls++
	m.lastRules = nil
	m.lastPolicy = ""
	return nil
}

// List returns the last-applied rules.
func (m *MemoryBackend) List(_ context.Context) ([]Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Rule, len(m.lastRules))
	copy(out, m.lastRules)
	return out, nil
}

// HitCounts returns zeros for every rule (no real kernel counters).
func (m *MemoryBackend) HitCounts(_ context.Context) (map[int64]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[int64]int64, len(m.lastRules))
	for _, r := range m.lastRules {
		out[r.ID] = 0
	}
	return out, nil
}

// Stats returns introspection counters for tests.
type Stats struct {
	EnsureCalls int
	ApplyCalls  int
	ResetCalls  int
	RuleCount   int
	Policy      string
}

// Stats returns a snapshot.
func (m *MemoryBackend) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Stats{
		EnsureCalls: m.ensureCalls,
		ApplyCalls:  m.applyCalls,
		ResetCalls:  m.resetCalls,
		RuleCount:   len(m.lastRules),
		Policy:      m.lastPolicy,
	}
}
