package quota

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// StubManager embeds coreManager with in-memory CounterReader.
type StubManager struct {
	*coreManager
	reader *InMemoryReader
}

// NewStub returns a stub manager. Use reader.Set(profileID, bytes) in tests
// to inject byte counts before calling Tick.
func NewStub(log *slog.Logger, pub Publisher, sw Switcher) *StubManager {
	r := NewInMemoryReader()
	c := newCore("stub", log, r, sw, pub)
	return &StubManager{coreManager: c, reader: r}
}

// Reader returns the in-memory counter so tests can push updates.
func (m *StubManager) Reader() *InMemoryReader { return m.reader }

// InMemoryReader is a CounterReader used in tests and on non-Linux.
type InMemoryReader struct {
	mu     sync.Mutex
	bytes  map[int64]int64
	sample time.Time
}

// NewInMemoryReader returns an empty reader.
func NewInMemoryReader() *InMemoryReader {
	return &InMemoryReader{bytes: map[int64]int64{}}
}

// Set overrides a profile's byte count (tests).
func (r *InMemoryReader) Set(profileID, bytes int64) {
	r.mu.Lock()
	r.bytes[profileID] = bytes
	r.sample = time.Now()
	r.mu.Unlock()
}

// Add increments a profile's byte count (simulated traffic).
func (r *InMemoryReader) Add(profileID, delta int64) {
	r.mu.Lock()
	r.bytes[profileID] += delta
	r.sample = time.Now()
	r.mu.Unlock()
}

// ReadProfileBytes implements CounterReader.
func (r *InMemoryReader) ReadProfileBytes(_ context.Context, profileID int64) (int64, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytes[profileID], r.sample, nil
}

// Reset implements CounterReader.
func (r *InMemoryReader) Reset(_ context.Context, profileID int64) error {
	r.mu.Lock()
	r.bytes[profileID] = 0
	r.mu.Unlock()
	return nil
}

var _ Manager = (*StubManager)(nil)
var _ CounterReader = (*InMemoryReader)(nil)
