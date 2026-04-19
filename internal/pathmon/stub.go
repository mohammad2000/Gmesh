package pathmon

import (
	"context"
	"sync"
	"time"
)

// StubPublisher records events for tests.
type StubPublisher struct {
	mu sync.Mutex
	ev []Event
}

// NewStubPublisher returns an empty publisher.
func NewStubPublisher() *StubPublisher { return &StubPublisher{} }

// Publish records ev.
func (p *StubPublisher) Publish(ev Event) {
	p.mu.Lock()
	p.ev = append(p.ev, ev)
	p.mu.Unlock()
}

// Events returns a copy of recorded events.
func (p *StubPublisher) Events() []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Event, len(p.ev))
	copy(out, p.ev)
	return out
}

// ByType filters Events by Type.
func (p *StubPublisher) ByType(t string) []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Event
	for _, e := range p.ev {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// StubProber returns a scripted Result per call, cycling through Results.
// Tests push expected results via Push; calling Probe consumes them in order.
// If no Result is queued for a target, it returns a default Up=false.
type StubProber struct {
	mu   sync.Mutex
	byID map[int64][]Result
}

// NewStubProber returns an empty prober.
func NewStubProber() *StubProber {
	return &StubProber{byID: map[int64][]Result{}}
}

// Name returns "stub".
func (p *StubProber) Name() string { return "stub" }

// Push queues a Result for the given peer — next Probe call returns it.
func (p *StubProber) Push(peerID int64, r Result) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r.When = time.Now()
	p.byID[peerID] = append(p.byID[peerID], r)
}

// PushUp queues a successful probe with a fixed RTT.
func (p *StubProber) PushUp(peerID int64, rtt time.Duration) {
	p.Push(peerID, Result{RTT: rtt, Up: true})
}

// PushDown queues a failed probe.
func (p *StubProber) PushDown(peerID int64, reason string) {
	p.Push(peerID, Result{Up: false, Error: reason})
}

// Probe implements Prober.
func (p *StubProber) Probe(_ context.Context, t Target) Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	queued := p.byID[t.PeerID]
	if len(queued) == 0 {
		return Result{Up: false, When: time.Now(), Error: "no scripted result"}
	}
	r := queued[0]
	p.byID[t.PeerID] = queued[1:]
	if r.When.IsZero() {
		r.When = time.Now()
	}
	return r
}

var _ Prober = (*StubProber)(nil)
var _ Publisher = (*StubPublisher)(nil)
