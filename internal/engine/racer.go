// Endpoint racer.
//
// When a peer advertises multiple candidate endpoints (LAN / WAN / STUN
// / relay), we want to pick the best one that actually works. WireGuard
// can only hold one endpoint per peer at a time, so "racing" here means:
//
//   1. Start with the highest-priority candidate (lowest priority #).
//   2. Wait N seconds for a WG handshake on that endpoint.
//   3. If none, call `wg set ... endpoint=<next>` and reset the timer.
//   4. Stop as soon as a handshake succeeds; mark that endpoint as
//      LastOK and remember the chosen candidate.
//
// The racer runs as a goroutine keyed by peer ID; starting a new race
// for the same peer cancels the previous one.

package engine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/peer"
	"github.com/mohammad2000/Gmesh/internal/relay"
	"github.com/mohammad2000/Gmesh/internal/wireguard"
)

// How long to wait on each candidate before rotating.
const raceCandidateTimeout = 15 * time.Second

// How often to poll WG for handshake progress. Cheap — uses wgctrl dump.
const racePollInterval = 2 * time.Second

// EndpointRacer tries candidate endpoints for a peer in priority order,
// switching to the next one whenever the current candidate fails to
// produce a handshake within raceCandidateTimeout.
type EndpointRacer struct {
	mu     sync.Mutex
	active map[int64]context.CancelFunc
}

// NewEndpointRacer returns an empty racer. Engine owns one instance.
func NewEndpointRacer() *EndpointRacer {
	return &EndpointRacer{active: make(map[int64]context.CancelFunc)}
}

// Start kicks off (or restarts) a race for the given peer. Safe to call
// multiple times — later calls cancel prior races for the same peer.
func (r *EndpointRacer) Start(parentCtx context.Context, e *Engine, p *peer.Peer) {
	if len(p.Endpoints) <= 1 {
		// Nothing to race; default endpoint was already applied.
		return
	}

	r.mu.Lock()
	if cancel, ok := r.active[p.ID]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(parentCtx)
	r.active[p.ID] = cancel
	r.mu.Unlock()

	go r.run(ctx, e, p.ID)
}

// Stop cancels the in-flight race for peer (if any). Called from
// RemovePeer and on engine shutdown.
func (r *EndpointRacer) Stop(peerID int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cancel, ok := r.active[peerID]; ok {
		cancel()
		delete(r.active, peerID)
	}
}

// StopAll cancels every active race.
func (r *EndpointRacer) StopAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, cancel := range r.active {
		cancel()
		delete(r.active, id)
	}
}

func (r *EndpointRacer) run(ctx context.Context, e *Engine, peerID int64) {
	defer func() {
		r.mu.Lock()
		delete(r.active, peerID)
		r.mu.Unlock()
	}()

	p, ok := e.Peers.Get(peerID)
	if !ok || len(p.Endpoints) == 0 {
		return
	}

	candidates := sortedCandidates(p.Endpoints)

	for _, cand := range candidates {
		if ctx.Err() != nil {
			return
		}
		// Switch WG to this candidate.
		if err := e.WG.AddPeer(ctx, e.Interface(), wireguard.PeerConfig{
			PublicKey:                   p.PublicKey,
			Endpoint:                    cand.Address,
			AllowedIPs:                  p.AllowedIPs,
			PersistentKeepaliveInterval: e.keepalive,
		}); err != nil {
			e.Log.Warn("racer: wg add_peer failed",
				"peer", peerID, "endpoint", cand.Address, "error", err)
			continue
		}
		p.Endpoint = cand.Address
		e.Log.Info("racer: probing candidate",
			"peer", peerID, "endpoint", cand.Address, "kind", cand.Kind.String())

		baseRxTx := currentTraffic(e, p.PublicKey)
		deadline := time.Now().Add(raceCandidateTimeout)

		for time.Now().Before(deadline) && ctx.Err() == nil {
			time.Sleep(racePollInterval)
			if handshakeSince(e, p.PublicKey, cand, baseRxTx) {
				cand.LastOK = time.Now()
				// Commit the win back into the peer's candidate list so
				// future RefreshPeerStats reflects which endpoint worked.
				updateCandidateLastOK(p, cand)
				e.Log.Info("racer: candidate won",
					"peer", peerID, "endpoint", cand.Address, "kind", cand.Kind.String())
				return
			}
		}

		e.Log.Info("racer: candidate timed out",
			"peer", peerID, "endpoint", cand.Address, "kind", cand.Kind.String())
	}

	e.Log.Warn("racer: all candidates exhausted", "peer", peerID)

	// Last-resort: if a relay is configured, fall back through it. The
	// relay server forwards encrypted WG packets between peers that
	// can't open a direct UDP path (symmetric NATs, ISP hairpin bugs,
	// carrier-grade NAT). We don't gate this on is_relay_capable
	// because the whole point of a relay is that peers behind unfriendly
	// NATs don't have a choice.
	relayURL := e.Config.Relay.DefaultRelayURL
	if relayURL == "" || e.Config.Relay.Secret == "" {
		e.Log.Debug("racer: no relay configured; giving up on peer", "peer", peerID)
		return
	}
	sid := sessionIDFromString(fmt.Sprintf("peer-%d", peerID))
	tok := relay.SignToken([]byte(e.Config.Relay.Secret), sid, uint64(peerID))
	if _, err := e.SetupRelay(ctx, peerID, relayURL, sid, tok); err != nil {
		e.Log.Warn("racer: relay fallback failed", "peer", peerID, "error", err)
		return
	}
	e.Log.Info("racer: relay fallback active", "peer", peerID, "relay", relayURL)
}

// sessionIDFromString is a local duplicate of rpc.sessionIDFromString —
// we can't import the rpc package from engine without a cycle, and the
// hash is trivial.
func sessionIDFromString(s string) [16]byte {
	h := sha256.Sum256([]byte(s))
	var out [16]byte
	copy(out[:], h[:16])
	return out
}

// sortedCandidates returns a fresh slice ordered by priority (asc),
// with previously-successful endpoints promoted within their tier.
func sortedCandidates(in []peer.Endpoint) []peer.Endpoint {
	out := make([]peer.Endpoint, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].LastOK.After(out[j].LastOK)
	})
	return out
}

// currentTraffic reads rx+tx for the peer as a baseline. We detect a
// "handshake" as either rx_bytes growing from the starting value or
// LatencyMS/LastHandshake moving forward after the stats refresh.
type peerTraffic struct {
	Rx, Tx        int64
	LastHandshake time.Time
}

func currentTraffic(e *Engine, publicKey string) peerTraffic {
	for _, p := range e.Peers.Snapshot() {
		if p.PublicKey == publicKey {
			return peerTraffic{
				Rx: p.RxBytes, Tx: p.TxBytes,
				LastHandshake: p.LastHandshake,
			}
		}
	}
	return peerTraffic{}
}

// handshakeSince does a stats refresh and returns true if WG has made
// progress on this peer since the base snapshot — meaning the current
// endpoint is actually working.
func handshakeSince(e *Engine, publicKey string, _ peer.Endpoint, base peerTraffic) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := e.RefreshPeerStats(ctx); err != nil {
		return false
	}
	for _, p := range e.Peers.Snapshot() {
		if p.PublicKey != publicKey {
			continue
		}
		if p.LastHandshake.After(base.LastHandshake) {
			return true
		}
		if p.RxBytes > base.Rx {
			return true
		}
	}
	return false
}

// updateCandidateLastOK marks the winning candidate's LastOK in the
// peer's Endpoints slice so future races/refreshes know it worked.
func updateCandidateLastOK(p *peer.Peer, cand peer.Endpoint) {
	for i := range p.Endpoints {
		if p.Endpoints[i].Address == cand.Address {
			p.Endpoints[i].LastOK = cand.LastOK
			return
		}
	}
}
