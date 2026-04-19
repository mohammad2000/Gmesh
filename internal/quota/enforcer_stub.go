package quota

import (
	"context"
	"log/slog"
	"sync"
)

// StubEnforcer records Block/Unblock calls for tests and non-Linux builds.
type StubEnforcer struct {
	Log *slog.Logger

	mu      sync.Mutex
	blocked map[int64]uint32
}

// NewStubEnforcer returns an in-memory enforcer.
func NewStubEnforcer(log *slog.Logger) *StubEnforcer {
	if log == nil {
		log = slog.Default()
	}
	return &StubEnforcer{Log: log, blocked: map[int64]uint32{}}
}

// Name returns "stub".
func (e *StubEnforcer) Name() string { return "stub" }

// Block records the blocked profile.
func (e *StubEnforcer) Block(_ context.Context, egressProfileID int64, mark uint32) error {
	e.mu.Lock()
	e.blocked[egressProfileID] = mark
	e.mu.Unlock()
	e.Log.Info("stub enforcer block", "profile", egressProfileID, "mark", mark)
	return nil
}

// Unblock removes the profile from the blocked set. Idempotent.
func (e *StubEnforcer) Unblock(_ context.Context, egressProfileID int64) error {
	e.mu.Lock()
	delete(e.blocked, egressProfileID)
	e.mu.Unlock()
	e.Log.Info("stub enforcer unblock", "profile", egressProfileID)
	return nil
}

// IsBlocked reports whether a profile is currently blocked.
func (e *StubEnforcer) IsBlocked(egressProfileID int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.blocked[egressProfileID]
	return ok
}

// Snapshot returns a copy of the blocked map for tests.
func (e *StubEnforcer) Snapshot() map[int64]uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[int64]uint32, len(e.blocked))
	for k, v := range e.blocked {
		out[k] = v
	}
	return out
}

var _ Enforcer = (*StubEnforcer)(nil)
