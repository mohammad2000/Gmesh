package l7

import "sync"

// StubReader returns scripted flow batches for tests and non-Linux
// builds. Push(...) stages a snapshot; the next Read call consumes it.
// Returns an empty slice when no snapshots are queued.
type StubReader struct {
	mu    sync.Mutex
	queue [][]Flow
}

// NewStubReader returns an empty reader.
func NewStubReader() *StubReader { return &StubReader{} }

// Name implements Reader.
func (r *StubReader) Name() string { return "stub" }

// Push queues one snapshot. Tests call this to drive the classifier.
func (r *StubReader) Push(flows []Flow) {
	r.mu.Lock()
	copy := append([]Flow(nil), flows...)
	r.queue = append(r.queue, copy)
	r.mu.Unlock()
}

// Read implements Reader — returns the next queued batch, or an empty
// slice if none.
func (r *StubReader) Read() ([]Flow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) == 0 {
		return nil, nil
	}
	head := r.queue[0]
	r.queue = r.queue[1:]
	return head, nil
}

var _ Reader = (*StubReader)(nil)
