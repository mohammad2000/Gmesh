// Package traversal holds NAT-traversal strategies: direct dial, UPnP
// port mapping, STUN-assisted hole-punching, simultaneous-open, birthday
// paradox port guessing, UDP relay, TCP relay, and WebSocket tunneling.
//
// Each strategy implements the Strategy interface. The Engine type iterates
// a ladder of strategies (ordered by latency / reliability) until one
// verifies bidirectional connectivity via a WireGuard handshake.
package traversal

import (
	"context"
	"errors"
	"time"
)

// Method matches gmesh.v1.ConnectionMethod.
type Method int

const (
	MethodUnspecified Method = iota
	MethodDirect
	MethodUPnPPortMap
	MethodSTUNHolePunch
	MethodSimultaneousOpen
	MethodBirthdayPunch
	MethodRelay
	MethodRelayTCP
	MethodWSTunnel
)

// Outcome is the result of attempting a single strategy.
type Outcome struct {
	Method    Method
	Success   bool
	LatencyMS int64
	Error     string
}

// PeerContext is what a strategy needs to know about the remote end.
type PeerContext struct {
	PeerID          int64
	RemotePublicKey string
	RemoteEndpoint  string
	RemoteNATType   int
	FireAtUnixMS    int64 // for SimultaneousOpen
}

// Strategy is one NAT-traversal approach.
type Strategy interface {
	Method() Method
	Attempt(ctx context.Context, pc *PeerContext) (*Outcome, error)
}

// Engine runs a ladder of strategies until one succeeds.
type Engine struct {
	strategies map[Method]Strategy
}

// NewEngine returns an empty Engine. Call Register for each available strategy.
func NewEngine() *Engine { return &Engine{strategies: make(map[Method]Strategy)} }

// Register adds a strategy.
func (e *Engine) Register(s Strategy) { e.strategies[s.Method()] = s }

// Run tries each method in order, returning the first successful Outcome.
// Returns ErrExhausted if every method failed.
func (e *Engine) Run(ctx context.Context, ladder []Method, pc *PeerContext) (*Outcome, []*Outcome, error) {
	history := make([]*Outcome, 0, len(ladder))
	for _, m := range ladder {
		s, ok := e.strategies[m]
		if !ok {
			history = append(history, &Outcome{Method: m, Error: "strategy not registered"})
			continue
		}
		start := time.Now()
		out, err := s.Attempt(ctx, pc)
		if err != nil && out == nil {
			out = &Outcome{Method: m, Error: err.Error()}
		}
		if out.LatencyMS == 0 && out.Success {
			out.LatencyMS = time.Since(start).Milliseconds()
		}
		history = append(history, out)
		if out.Success {
			return out, history, nil
		}
	}
	return nil, history, ErrExhausted
}

// ErrExhausted is returned when every strategy in the ladder fails.
var ErrExhausted = errors.New("traversal: all strategies exhausted")
