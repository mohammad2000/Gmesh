// Relay fallback.
//
// When a relay and a credential are configured, every peer gets a standby
// relay session: a socket to gmesh-relay registered for this pair of keys,
// plus a loopback forwarder WireGuard can use as the peer's endpoint. The
// standby costs one tiny packet every 20 s.
//
// A watcher looks at each peer every 10 s:
//   - on a direct path with no handshake for staleAfter (or none at all
//     since it was added), it points WireGuard at the relay forwarder;
//   - on the relay, it tries the best direct candidate now and then (with
//     backoff). If the direct path works, the peer's WireGuard roams to it
//     and so do we; if it doesn't, the peer's next packet through the relay
//     roams us straight back. Nothing is lost but a few keepalives.
//
// Only one side has to decide: WireGuard sends to wherever the peer's last
// authenticated packet came from, so when one side starts sending through
// the relay, the other side's WireGuard answers through its own standby
// session.
package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/events"
	"github.com/mohammad2000/Gmesh/internal/peer"
	"github.com/mohammad2000/Gmesh/internal/relay"
	"github.com/mohammad2000/Gmesh/internal/wireguard"
)

const (
	relayTick        = 10 * time.Second
	relayStaleAfter  = 190 * time.Second // WG re-handshakes every ≤2 min while keepalive runs
	relayNewPeerWait = 35 * time.Second  // a brand-new peer gets this long to handshake directly
	relayMinSwitch   = 30 * time.Second
	relayRetryFirst  = 5 * time.Minute
	relayRetryMax    = 30 * time.Minute
	relayDialBackoff = time.Minute
	relayPreferFor   = 30 * time.Minute
	relayTryWindow   = 40 * time.Second // > keepalive: a failed try roams back before this
	relayTryMute     = 3 * time.Second  // relayed packets dropped while a try starts
	relayRxSilence   = 75 * time.Second // ~3 keepalives without a byte in: the path is dead

	methodDirect = 1 // gmesh.v1.ConnectionMethod
	methodRelay  = 6
)

// RelayConf is what the control plane hands a node.
type RelayConf struct {
	Relays    []string `json:"relays"`     // host:port of gmesh-relay servers, best first
	PublicKey string   `json:"public_key"` // the node's WG key the credential is for
	Expiry    int64    `json:"expiry"`
	MAC       string   `json:"mac"` // base64
}

func (c RelayConf) credential() (relay.Credential, error) {
	var cr relay.Credential
	k, err := relay.ParseKey(c.PublicKey)
	if err != nil {
		return cr, err
	}
	m, err := base64.StdEncoding.DecodeString(c.MAC)
	if err != nil || len(m) != 32 {
		return cr, errors.New("relay: bad credential mac")
	}
	cr.PublicKey, cr.Expiry = k, c.Expiry
	copy(cr.MAC[:], m)
	return cr, nil
}

type relayPeer struct {
	key       relay.Key
	sess      *relay.Session
	relayAddr string
	seen      time.Time // first time the manager saw this peer
	nextDial  time.Time
	dialedAt  time.Time
	lastErr   string

	onRelaySince time.Time
	lastSwitch   time.Time
	nextTry      time.Time
	tryEvery     time.Duration
	tryingSince  time.Time // a direct try in progress
	tryRx        int64
	lastRx       int64
	rxAt         time.Time // when rx last moved
	lastDirect   string    // the last direct endpoint WG used
}

type relayManager struct {
	kick chan struct{}
	// prefer is the index in conf.Relays that worked when the first one
	// didn't (e.g. the WebSocket on a network that blocks UDP).
	prefer      int
	preferUntil time.Time
	mu          sync.Mutex
	conf        *RelayConf
	cred        relay.Credential
	peers       map[int64]*relayPeer
}

// RelayPeerStatus is one peer's relay state, for status/ctl.
type RelayPeerStatus struct {
	PeerID       int64
	Standby      bool // a session to the relay is registered
	Healthy      bool // the relay answered within the last minute
	OnRelay      bool // WG currently sends through it
	OnRelaySince time.Time
	Relay        string
	Error        string
	TxBytes      uint64
	RxBytes      uint64
}

// RelayStatus is the node's relay state.
type RelayStatus struct {
	Configured bool
	Relays     []string
	Expiry     time.Time
	Error      string
	Peers      []RelayPeerStatus
}

func (e *Engine) relayFile() string { return filepath.Join(e.Config.State.Dir, "relay.json") }

// loadRelayConf restores the relay settings after a restart.
func (e *Engine) loadRelayConf() {
	b, err := os.ReadFile(e.relayFile())
	if err != nil {
		return
	}
	var c RelayConf
	if json.Unmarshal(b, &c) != nil {
		return
	}
	if cr, err := c.credential(); err == nil {
		e.relay.mu.Lock()
		e.relay.conf, e.relay.cred = &c, cr
		e.relay.mu.Unlock()
	}
}

// SetRelayConfig installs (or, with no relays, removes) the relay settings.
func (e *Engine) SetRelayConfig(ctx context.Context, c RelayConf) error {
	if len(c.Relays) == 0 {
		e.closeRelays()
		e.relay.mu.Lock()
		e.relay.conf = nil
		e.relay.mu.Unlock()
		_ = os.Remove(e.relayFile())
		return nil
	}
	for _, r := range c.Relays {
		if relay.IsWS(r) {
			if u, err := url.Parse(r); err != nil || u.Host == "" {
				return fmt.Errorf("relay address %q: not a URL", r)
			}
		} else if _, _, err := net.SplitHostPort(strings.TrimPrefix(r, "udp://")); err != nil {
			return fmt.Errorf("relay address %q: %w", r, err)
		}
	}
	cr, err := c.credential()
	if err != nil {
		return err
	}
	if pk := e.PubKey(); pk != "" && pk != c.PublicKey {
		return errors.New("relay credential is for another WireGuard key (re-issue after re-join)")
	}
	if time.Unix(c.Expiry, 0).Before(time.Now()) {
		return relay.ErrExpired
	}
	b, _ := json.Marshal(c)
	if err := os.MkdirAll(filepath.Dir(e.relayFile()), 0o700); err == nil {
		_ = os.WriteFile(e.relayFile(), b, 0o600)
	}
	e.relay.mu.Lock()
	prev := e.relay.conf
	e.relay.conf, e.relay.cred = &c, cr
	var renew []*relayPeer
	for _, rp := range e.relay.peers {
		if rp.sess == nil {
			continue
		}
		if prev == nil || !slices.Contains(c.Relays, rp.relayAddr) {
			rp.sess.Close()
			rp.sess, rp.nextDial = nil, time.Time{}
			continue
		}
		renew = append(renew, rp)
	}
	e.relay.mu.Unlock()
	for _, rp := range renew {
		rp.sess.SetAuth(relay.Auth{Cred: cr, Peer: rp.key})
	}
	e.Log.Info("relay configured", "relays", c.Relays, "expires", time.Unix(c.Expiry, 0).UTC())
	select { // the watcher looks right away instead of at its next tick
	case e.relay.kick <- struct{}{}:
	default:
	}
	return nil
}

func (e *Engine) closeRelays() {
	e.relay.mu.Lock()
	defer e.relay.mu.Unlock()
	for id, rp := range e.relay.peers {
		if rp.sess != nil {
			rp.sess.Close()
		}
		delete(e.relay.peers, id)
	}
}

// relayLoop runs the watcher until ctx ends.
func (e *Engine) relayLoop(ctx context.Context) {
	t := time.NewTicker(relayTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			e.closeRelays()
			return
		case <-t.C:
			e.relayCheck(ctx)
		case <-e.relay.kick:
			e.relayCheck(ctx)
		}
	}
}

var relayCheckMu sync.Mutex

// relayCheck is one pass of the watcher.
func (e *Engine) relayCheck(ctx context.Context) {
	relayCheckMu.Lock()
	defer relayCheckMu.Unlock()
	if !e.IsJoined() {
		e.closeRelays()
		return
	}
	e.relay.mu.Lock()
	conf, cred := e.relay.conf, e.relay.cred
	e.relay.mu.Unlock()
	if conf == nil || len(conf.Relays) == 0 || time.Now().Unix() > cred.Expiry || e.PubKey() != conf.PublicKey {
		e.closeRelays()
		return
	}
	dumps, err := e.WG.ListPeers(ctx, e.Interface())
	if err != nil {
		return
	}
	byKey := make(map[string]wireguard.PeerDump, len(dumps))
	for _, d := range dumps {
		byKey[d.PublicKey] = d
	}
	now := time.Now()
	live := map[int64]bool{}
	dials := 0
	for _, p := range e.Peers.Snapshot() {
		// Scopes hang off a host (or this node); dial-in peers such as VPN
		// clients have no endpoint of their own — nothing to fall back from.
		if p.PublicKey == "" || p.Type == peer.TypeScope || (p.Endpoint == "" && len(p.Endpoints) == 0) {
			continue
		}
		key, err := relay.ParseKey(p.PublicKey)
		if err != nil {
			continue
		}
		live[p.ID] = true
		e.relay.mu.Lock()
		rp := e.relay.peers[p.ID]
		if rp == nil || rp.key != key {
			if rp != nil && rp.sess != nil {
				rp.sess.Close()
			}
			rp = &relayPeer{key: key, seen: now, tryEvery: relayRetryFirst}
			e.relay.peers[p.ID] = rp
		}
		e.relay.mu.Unlock()

		// A session the relay stopped answering (relay restart it missed,
		// a dropped WebSocket) is replaced.
		var oldFwd string
		e.relay.mu.Lock()
		preferUntil := e.relay.preferUntil
		e.relay.mu.Unlock()
		if rp.sess != nil && relay.IsWS(rp.relayAddr) && rp.onRelaySince.IsZero() && rp.tryingSince.IsZero() &&
			now.After(preferUntil) && now.Sub(rp.dialedAt) > relayPreferFor {
			// On the TCP fallback, idle, and the preference ran out: see
			// whether UDP gets out again.
			rp.sess.Close()
			rp.sess = nil
		}
		if rp.sess != nil && !rp.sess.Healthy() && now.Sub(rp.dialedAt) > time.Minute {
			oldFwd = rp.sess.LocalEndpoint().String()
			e.Log.Info("relay: standby went silent, redialing", "peer", p.ID, "relay", rp.relayAddr, "error", rp.sess.AuthError())
			rp.sess.Close()
			rp.sess = nil
		}
		if rp.sess == nil && now.After(rp.nextDial) && dials < 16 {
			dials++
			e.relayDial(ctx, rp, conf.Relays, cred)
			if rp.sess != nil && oldFwd != "" {
				if d, ok := byKey[p.PublicKey]; ok && d.Endpoint == oldFwd {
					_ = e.setEndpoint(ctx, p, rp.sess.LocalEndpoint().String()) // stay on the relay, new socket
				}
			}
		}
		if rp.sess == nil || (e.Racer != nil && e.Racer.Active(p.ID)) {
			continue
		}
		d, ok := byKey[p.PublicKey]
		if !ok {
			continue
		}
		fwd := rp.sess.LocalEndpoint().String()
		onRelay := d.Endpoint == fwd
		fresh := !d.LastHandshake.IsZero() && now.Sub(d.LastHandshake) < relayStaleAfter
		if d.RxBytes != rp.lastRx || rp.rxAt.IsZero() {
			rp.lastRx, rp.rxAt = d.RxBytes, now
		}
		// Persistent keepalive makes the peer send at least every 25 s; a
		// receive counter standing still that long means nothing gets in.
		silent := now.Sub(rp.rxAt) > relayRxSilence

		if !onRelay {
			if !rp.tryingSince.IsZero() {
				// We are testing the direct path. Had it failed, the peer's
				// next packet through the relay would have roamed us back.
				if now.Sub(rp.tryingSince) < relayTryWindow {
					continue
				}
				rp.tryingSince = time.Time{}
				if fresh && d.RxBytes > rp.tryRx {
					e.relayBackDirect(p, rp, d.Endpoint, now)
				} else {
					e.relaySwitch(ctx, p, fwd, rp, "direct path still silent")
				}
				continue
			}
			if !rp.onRelaySince.IsZero() && fresh {
				// The peer's packets now come straight to us: it tried the
				// direct path and WG followed.
				e.relayBackDirect(p, rp, d.Endpoint, now)
			}
			if rp.onRelaySince.IsZero() && fresh && !loopbackEP(d.Endpoint) {
				rp.lastDirect = d.Endpoint
			}
			stuck := (!fresh || silent) && now.Sub(rp.seen) > relayNewPeerWait
			if stuck && rp.sess.Healthy() && now.Sub(rp.lastSwitch) > relayMinSwitch {
				why := "no handshake on " + orNone(d.Endpoint)
				if fresh {
					why = "nothing received for " + now.Sub(rp.rxAt).Round(time.Second).String() + " on " + orNone(d.Endpoint)
				}
				e.relaySwitch(ctx, p, fwd, rp, why)
				continue
			}
			if fresh && rp.onRelaySince.IsZero() {
				p.Method = methodDirect
			}
			continue
		}

		// On the relay.
		if !rp.tryingSince.IsZero() {
			rp.tryingSince = time.Time{} // roamed back mid-try: direct is still dead
		}
		if rp.onRelaySince.IsZero() {
			rp.onRelaySince = now // the peer started it; we followed
			rp.nextTry = now.Add(rp.tryEvery)
			e.Log.Info("relay: peer reached us through the relay", "peer", p.ID)
			e.emit(events.TypePeerMethodChange, p.ID, map[string]any{"method": "relay", "relay": rp.relayAddr, "why": "the peer moved to the relay", "mesh_ip": p.MeshIP})
		}
		p.Method = methodRelay
		if now.After(rp.nextTry) {
			cand := e.directCandidate(p, rp)
			if cand != "" {
				rp.sess.Mute(relayTryMute)
			}
			if cand != "" && e.setEndpoint(ctx, p, cand) == nil {
				e.Log.Info("relay: trying the direct path again", "peer", p.ID, "endpoint", cand)
				rp.tryingSince, rp.tryRx, rp.lastSwitch = now, d.RxBytes, now
			}
			rp.tryEvery = min(rp.tryEvery*2, relayRetryMax)
			rp.nextTry = now.Add(rp.tryEvery)
		}
	}
	e.relay.mu.Lock()
	for id, rp := range e.relay.peers {
		if !live[id] {
			if rp.sess != nil {
				rp.sess.Close()
			}
			delete(e.relay.peers, id)
		}
	}
	e.relay.mu.Unlock()
}

func orNone(s string) string {
	if s == "" {
		return "no endpoint"
	}
	return s
}

// relayDial opens the standby session, trying the relays in order — UDP
// first, the WebSocket (TCP/443) where UDP can't get out. Once a later
// entry was the one that worked, it goes first for relayPreferFor so the
// other peers don't each wait out the dead transport.
func (e *Engine) relayDial(ctx context.Context, rp *relayPeer, relays []string, cred relay.Credential) {
	order := make([]int, 0, len(relays))
	e.relay.mu.Lock()
	if p := e.relay.prefer; p > 0 && p < len(relays) && time.Now().Before(e.relay.preferUntil) {
		order = append(order, p)
	}
	e.relay.mu.Unlock()
	for i := range relays {
		if len(order) == 0 || order[0] != i {
			order = append(order, i)
		}
	}
	var errs []string
	for _, i := range order {
		addr := relays[i]
		timeout := 3 * time.Second
		if relay.IsWS(addr) {
			timeout = 8 * time.Second
		}
		dctx, cancel := context.WithTimeout(ctx, timeout+time.Second)
		s, err := relay.DialSession(dctx, relay.Config{
			Auth:        relay.Auth{Cred: cred, Peer: rp.key},
			RelayAddr:   addr,
			WGEndpoint:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(e.ListenPort())},
			DialTimeout: timeout,
			Log:         e.Log,
		})
		cancel()
		if err != nil {
			errs = append(errs, addr+": "+err.Error())
			continue
		}
		e.relay.mu.Lock()
		if i > 0 {
			if e.relay.prefer != i {
				e.Log.Info("relay: using a fallback transport", "relay", addr)
			}
			e.relay.prefer, e.relay.preferUntil = i, time.Now().Add(relayPreferFor)
		} else {
			e.relay.prefer = 0
		}
		e.relay.mu.Unlock()
		rp.sess, rp.relayAddr, rp.lastErr, rp.dialedAt = s, addr, "", time.Now()
		return
	}
	rp.lastErr, rp.nextDial = strings.Join(errs, "; "), time.Now().Add(relayDialBackoff)
	e.Log.Debug("relay: standby dial failed", "error", rp.lastErr)
}

func (e *Engine) relayBackDirect(p *peer.Peer, rp *relayPeer, ep string, now time.Time) {
	e.Log.Info("relay: peer back on a direct path", "peer", p.ID, "endpoint", ep,
		"relayed_for", now.Sub(rp.onRelaySince).Round(time.Second).String())
	e.emit(events.TypePeerMethodChange, p.ID, map[string]any{"method": "direct", "endpoint": ep, "mesh_ip": p.MeshIP})
	rp.onRelaySince, rp.tryEvery, rp.lastDirect = time.Time{}, relayRetryFirst, ep
	p.Method, p.Endpoint = methodDirect, ep
}

// relaySwitch points WG at the relay forwarder for p.
func (e *Engine) relaySwitch(ctx context.Context, p *peer.Peer, fwd string, rp *relayPeer, why string) {
	if rp.lastDirect == "" && !loopbackEP(p.Endpoint) {
		rp.lastDirect = p.Endpoint // something to try again later
	}
	if err := e.setEndpoint(ctx, p, fwd); err != nil {
		e.Log.Warn("relay: switch failed", "peer", p.ID, "error", err)
		return
	}
	now := time.Now()
	rp.onRelaySince, rp.lastSwitch, rp.tryEvery = now, now, relayRetryFirst
	rp.nextTry = now.Add(rp.tryEvery)
	p.Method = methodRelay
	e.Log.Info("relay: peer moved to the relay", "peer", p.ID, "relay", rp.relayAddr, "why", why)
	e.emit(events.TypePeerMethodChange, p.ID, map[string]any{"method": "relay", "relay": rp.relayAddr, "why": why, "mesh_ip": p.MeshIP})
}

func (e *Engine) setEndpoint(ctx context.Context, p *peer.Peer, ep string) error {
	err := e.WG.AddPeer(ctx, e.Interface(), wireguard.PeerConfig{
		PublicKey: p.PublicKey, Endpoint: ep, AllowedIPs: p.AllowedIPs, PersistentKeepaliveInterval: e.keepalive,
	})
	if err == nil {
		p.Endpoint = ep
	}
	return err
}

// directCandidate picks the direct endpoint to try: the one that last
// worked, else the best-ranked non-relay candidate.
func (e *Engine) directCandidate(p *peer.Peer, rp *relayPeer) string {
	if !loopbackEP(rp.lastDirect) {
		return rp.lastDirect
	}
	c := make([]peer.Endpoint, 0, len(p.Endpoints))
	for _, x := range p.Endpoints {
		if x.Kind != peer.EndpointKindRelay && !loopbackEP(x.Address) {
			c = append(c, x)
		}
	}
	if len(c) == 0 {
		return ""
	}
	sort.SliceStable(c, func(i, j int) bool {
		if !c[i].LastOK.Equal(c[j].LastOK) {
			return c[i].LastOK.After(c[j].LastOK)
		}
		return c[i].Priority < c[j].Priority
	})
	return c[0].Address
}

// relayFallbackNow is the racer's last resort: move p to the relay now.
func (e *Engine) relayFallbackNow(ctx context.Context, peerID int64) bool {
	p, ok := e.Peers.Get(peerID)
	if !ok {
		return false
	}
	e.relay.mu.Lock()
	rp := e.relay.peers[peerID]
	e.relay.mu.Unlock()
	if rp == nil || rp.sess == nil || !rp.sess.Healthy() {
		return false
	}
	e.relaySwitch(ctx, p, rp.sess.LocalEndpoint().String(), rp, "every direct candidate failed")
	return true
}

// GetRelayStatus reports the relay settings and each peer's state.
func (e *Engine) GetRelayStatus(ctx context.Context) RelayStatus {
	e.relay.mu.Lock()
	defer e.relay.mu.Unlock()
	var out RelayStatus
	if e.relay.conf != nil {
		out.Configured = true
		out.Relays = append([]string(nil), e.relay.conf.Relays...)
		out.Expiry = time.Unix(e.relay.conf.Expiry, 0)
		if time.Now().After(out.Expiry) {
			out.Error = "credential expired"
		} else if pk := e.PubKey(); pk != "" && pk != e.relay.conf.PublicKey {
			out.Error = "credential is for another WireGuard key"
		}
	}
	for id, rp := range e.relay.peers {
		s := RelayPeerStatus{PeerID: id, Relay: rp.relayAddr, Error: rp.lastErr, OnRelay: !rp.onRelaySince.IsZero(), OnRelaySince: rp.onRelaySince}
		if rp.sess != nil {
			st := rp.sess.Stats()
			s.Standby, s.Healthy, s.TxBytes, s.RxBytes = true, rp.sess.Healthy(), st.BytesTx, st.BytesRx
			if ae := rp.sess.AuthError(); ae != "" {
				s.Error = ae
			}
		}
		out.Peers = append(out.Peers, s)
	}
	sort.Slice(out.Peers, func(i, j int) bool { return out.Peers[i].PeerID < out.Peers[j].PeerID })
	return out
}

// savedEndpoint is what state keeps for p: never the relay forwarder's
// loopback port, which dies with this process.
func (e *Engine) savedEndpoint(p *peer.Peer) string {
	if !loopbackEP(p.Endpoint) {
		return p.Endpoint
	}
	e.relay.mu.Lock()
	rp := e.relay.peers[p.ID]
	e.relay.mu.Unlock()
	if rp != nil && !loopbackEP(rp.lastDirect) {
		return rp.lastDirect
	}
	return firstDirect(p.Endpoints)
}

func firstDirect(eps []peer.Endpoint) string {
	for _, c := range sortedCandidates(eps) {
		if c.Kind != peer.EndpointKindRelay && !loopbackEP(c.Address) {
			return c.Address
		}
	}
	return ""
}

// loopbackEP: empty, or a 127.x/::1 address — the relay forwarder, never a
// path to a peer.
func loopbackEP(ep string) bool {
	if ep == "" {
		return true
	}
	host, _, err := net.SplitHostPort(ep)
	return err == nil && net.ParseIP(host).IsLoopback()
}
