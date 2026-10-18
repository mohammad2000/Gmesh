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
	"net/netip"
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
	relayTryMute     = 4 * time.Second  // relayed packets dropped while a try starts
	relayMappedEvery = 5 * time.Minute
	relayMappedFresh = 10 * time.Minute
	relayInfoEvery   = 2 * time.Minute
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
	id        int64
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
	// what the peer told us through the relay (PEERINFO)
	peerMapped   netip.AddrPort // its WireGuard port as seen from outside
	peerMappedAt time.Time
	punchReq     time.Time // it asked us to punch with it
	mappedNew    bool      // peerMapped changed since the watcher last looked
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
	// our own WireGuard port as seen from outside (STUN from that port)
	mapped    netip.AddrPort
	mappedAt  time.Time
	mappedErr string
	infoAt    time.Time // last PEERINFO round to every peer
	mu        sync.Mutex
	conf      *RelayConf
	cred      relay.Credential
	peers     map[int64]*relayPeer
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
	PeerMapped   string
}

// RelayStatus is the node's relay state.
type RelayStatus struct {
	Configured bool
	Relays     []string
	Expiry     time.Time
	Error      string
	Mapped     string
	MappedErr  string
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
	e.refreshMapped(ctx, conf)
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
			rp = &relayPeer{id: p.ID, key: key, seen: now, tryEvery: relayRetryFirst}
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
		e.relay.mu.Lock()
		punchReq, peerMapped, peerMappedAt, mappedNew := rp.punchReq, rp.peerMapped, rp.peerMappedAt, rp.mappedNew
		rp.punchReq, rp.mappedNew = time.Time{}, false
		e.relay.mu.Unlock()
		if mappedNew && rp.tryingSince.IsZero() {
			// A new public address on a relayed link (the peer moved
			// networks): worth a try soon, not at the backoff's pace.
			if soon := now.Add(10 * time.Second); soon.Before(rp.nextTry) {
				rp.nextTry = soon
			}
		}
		mappedFresh := peerMapped.IsValid() && now.Sub(peerMappedAt) < relayMappedFresh
		switch {
		case !punchReq.IsZero() && now.Sub(punchReq) < 15*time.Second && mappedFresh:
			// The peer is punching toward us right now: fire back at its
			// public WireGuard address so both NATs open at once.
			e.punch(ctx, p, rp, peerMapped.String(), d.RxBytes, false, "answering the peer's punch")
		case now.After(rp.nextTry):
			cand := e.directCandidate(p, rp)
			if mappedFresh {
				cand = peerMapped.String()
			}
			if cand != "" {
				e.punch(ctx, p, rp, cand, d.RxBytes, mappedFresh, "trying the direct path again")
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
		id := rp.id
		s.OnPeerInfo(func(b []byte) { e.relayPeerInfo(id, b) })
		e.sendInfo(rp, false)
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
	if e.relay.mapped.IsValid() {
		out.Mapped = e.relay.mapped.String()
	}
	out.MappedErr = e.relay.mappedErr
	for id, rp := range e.relay.peers {
		s := RelayPeerStatus{PeerID: id, Relay: rp.relayAddr, Error: rp.lastErr, OnRelay: !rp.onRelaySince.IsZero(), OnRelaySince: rp.onRelaySince}
		if rp.peerMapped.IsValid() {
			s.PeerMapped = rp.peerMapped.String()
		}
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

// peerInfo is the PEERINFO payload: our WireGuard port as the world sees
// it, and — when punch is set — "I am sending to you directly right now".
type peerInfo struct {
	V      int    `json:"v"`
	Mapped string `json:"mapped,omitempty"`
	Punch  bool   `json:"punch,omitempty"`
}

// refreshMapped learns our WireGuard port's public address (STUN from that
// port to the UDP relay) every relayMappedEvery, and tells every peer
// when it changed or every relayInfoEvery.
func (e *Engine) refreshMapped(ctx context.Context, conf *RelayConf) {
	r, ok := e.WG.(wireguard.Reflector)
	e.relay.mu.Lock()
	due := time.Since(e.relay.mappedAt) > relayMappedEvery
	infoDue := time.Since(e.relay.infoAt) > relayInfoEvery
	e.relay.mu.Unlock()
	changed := false
	if ok && due {
		var server netip.AddrPort
		for _, a := range conf.Relays {
			if relay.IsWS(a) {
				continue
			}
			if ua, err := net.ResolveUDPAddr("udp4", strings.TrimPrefix(a, "udp://")); err == nil {
				server = ua.AddrPort()
				break
			}
		}
		if server.IsValid() {
			sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			m, err := r.Reflexive(sctx, e.Interface(), e.ListenPort(), netip.AddrPortFrom(server.Addr().Unmap(), server.Port()))
			cancel()
			e.relay.mu.Lock()
			e.relay.mappedAt = time.Now()
			if err != nil {
				e.relay.mappedErr = err.Error()
			} else {
				changed = m != e.relay.mapped
				e.relay.mapped, e.relay.mappedErr = m, ""
			}
			e.relay.mu.Unlock()
			if changed {
				e.Log.Info("relay: our WireGuard port as seen from outside", "mapped", m.String())
			}
		}
	}
	if changed || infoDue {
		e.relay.mu.Lock()
		e.relay.infoAt = time.Now()
		peers := make([]*relayPeer, 0, len(e.relay.peers))
		for _, rp := range e.relay.peers {
			peers = append(peers, rp)
		}
		e.relay.mu.Unlock()
		for _, rp := range peers {
			e.sendInfo(rp, false)
		}
	}
}

func (e *Engine) sendInfo(rp *relayPeer, punch bool) {
	e.relay.mu.Lock()
	m := e.relay.mapped
	e.relay.mu.Unlock()
	if rp.sess == nil || (!m.IsValid() && !punch) {
		return
	}
	pi := peerInfo{V: 1, Punch: punch}
	if m.IsValid() {
		pi.Mapped = m.String()
	}
	b, _ := json.Marshal(pi)
	_ = rp.sess.SendPeerInfo(b)
}

// relayPeerInfo handles a PEERINFO from peer id (relay session goroutine).
func (e *Engine) relayPeerInfo(id int64, b []byte) {
	var pi peerInfo
	if json.Unmarshal(b, &pi) != nil || pi.V != 1 {
		return
	}
	m, err := netip.ParseAddrPort(pi.Mapped)
	if err != nil || m.Addr().IsLoopback() || m.Addr().IsUnspecified() || m.Port() == 0 {
		m = netip.AddrPort{}
	}
	e.relay.mu.Lock()
	rp := e.relay.peers[id]
	if rp == nil {
		e.relay.mu.Unlock()
		return
	}
	if m.IsValid() {
		if m != rp.peerMapped {
			rp.mappedNew = true
		}
		rp.peerMapped, rp.peerMappedAt = m, time.Now()
	}
	if pi.Punch {
		rp.punchReq = time.Now()
	}
	e.relay.mu.Unlock()
	if pi.Punch {
		select {
		case e.relay.kick <- struct{}{}:
		default:
		}
	}
}

// punch points WG at ep while the relay is muted, and makes WG send at
// once. With ask set, the peer is told through the relay to do the same
// toward us, so both NATs see outgoing packets at the same moment.
func (e *Engine) punch(ctx context.Context, p *peer.Peer, rp *relayPeer, ep string, rx int64, ask bool, why string) {
	if ask {
		e.sendInfo(rp, true)
	}
	rp.sess.Mute(relayTryMute)
	if err := e.setEndpoint(ctx, p, ep); err != nil {
		return
	}
	e.Log.Info("relay: "+why, "peer", p.ID, "endpoint", ep, "coordinated", ask)
	now := time.Now()
	rp.tryingSince, rp.tryRx, rp.lastSwitch = now, rx, now
	go nudge(p.MeshIP)
}

// nudge makes WireGuard transmit now: a few datagrams to the peer's mesh
// address (discard port) go out through the tunnel to the new endpoint.
func nudge(meshIP string) {
	ip := net.ParseIP(meshIP)
	if ip == nil {
		return
	}
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: 9})
	if err != nil {
		return
	}
	defer c.Close()
	for _, d := range []time.Duration{0, 300 * time.Millisecond, 700 * time.Millisecond, 1500 * time.Millisecond} {
		time.Sleep(d)
		_, _ = c.Write([]byte("gmesh-punch"))
	}
}
