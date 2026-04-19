// Package engine orchestrates the mesh lifecycle. It owns references to every
// other subsystem (wireguard, peer registry, nat discoverer, traversal, relay,
// firewall, routing, health) and exposes high-level verbs that the gRPC
// server calls in response to incoming requests.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/config"
	"github.com/mohammad2000/Gmesh/internal/crypto"
	"github.com/mohammad2000/Gmesh/internal/firewall"
	"github.com/mohammad2000/Gmesh/internal/nat"
	"github.com/mohammad2000/Gmesh/internal/peer"
	"github.com/mohammad2000/Gmesh/internal/relay"
	"github.com/mohammad2000/Gmesh/internal/routing"
	"github.com/mohammad2000/Gmesh/internal/state"
	"github.com/mohammad2000/Gmesh/internal/traversal"
	"github.com/mohammad2000/Gmesh/internal/wireguard"
)

// Engine is the central orchestrator.
type Engine struct {
	Config   *config.Config
	Log      *slog.Logger
	Peers    *peer.Registry
	NAT      *nat.Discoverer
	Trav     *traversal.Engine
	WG       wireguard.Manager
	Relay    relay.Client
	Firewall firewall.Backend
	Routing  routing.Manager
	Store    *state.Store

	mu      sync.RWMutex
	joined  bool
	meshIP  string
	iface   string
	nodeID  string
	pubKey  string
	privKey string
	keepalive time.Duration
}

// Options bundles the optional dependencies that vary between tests and
// production.
type Options struct {
	Log   *slog.Logger
	WG    wireguard.Manager // nil → auto-detect via wireguard.New
	Store *state.Store      // nil → auto-create from cfg.State
}

// New wires an Engine together.
func New(cfg *config.Config, opts Options) (*Engine, error) {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	wg := opts.WG
	if wg == nil {
		m, err := wireguard.New(wireguard.BackendUnknown, log)
		if err != nil {
			return nil, fmt.Errorf("wireguard init: %w", err)
		}
		wg = m
	}

	store := opts.Store
	if store == nil {
		s, err := state.NewStore(cfg.State.Dir, cfg.State.File)
		if err != nil {
			return nil, fmt.Errorf("state store: %w", err)
		}
		store = s
	}

	e := &Engine{
		Config:    cfg,
		Log:       log,
		Peers:     peer.NewRegistry(),
		NAT:       nat.NewDiscoverer(cfg.NAT.STUNServers, time.Duration(cfg.NAT.DiscoveryTimeoutS)*time.Second, time.Duration(cfg.NAT.CacheTTLSeconds)*time.Second),
		Trav:      traversal.NewEngine(),
		WG:        wg,
		Routing:   routing.NewInMemory(),
		Store:     store,
		keepalive: time.Duration(cfg.WireGuard.KeepaliveSeconds) * time.Second,
	}

	if err := e.rehydrate(); err != nil {
		return nil, fmt.Errorf("rehydrate state: %w", err)
	}
	return e, nil
}

// rehydrate restores in-memory state from the on-disk file. Missing file = no-op.
func (e *Engine) rehydrate() error {
	st, err := e.Store.Load()
	if err != nil {
		return err
	}
	if !st.Node.Joined {
		return nil
	}
	e.mu.Lock()
	e.joined = true
	e.meshIP = st.Node.MeshIP
	e.iface = st.Node.Interface
	e.nodeID = st.Node.NodeID
	e.privKey = st.Node.PrivateKey
	e.pubKey = st.Node.PublicKey
	e.mu.Unlock()

	for _, p := range st.Peers {
		t := peer.TypeVM
		if p.Type == "scope" {
			t = peer.TypeScope
		}
		e.Peers.Upsert(&peer.Peer{
			ID:         p.ID,
			Type:       t,
			MeshIP:     p.MeshIP,
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIPs: p.AllowedIPs,
			Status:     peer.StatusConnecting, // will be refreshed by health loop
			ScopeID:    p.ScopeID,
		})
	}
	e.Log.Info("rehydrated", "peers", len(st.Peers), "mesh_ip", e.meshIP)
	return nil
}

// Start begins background loops. Canceling ctx stops them.
func (e *Engine) Start(ctx context.Context) error {
	_ = ctx
	// TODO: health monitor, NAT refresher, event dispatcher.
	return nil
}

// Stop tears the engine down. Safe to call multiple times.
func (e *Engine) Stop(_ context.Context) error {
	if e.WG != nil {
		_ = e.WG.Close()
	}
	return nil
}

// IsJoined reports whether Join() has been called.
func (e *Engine) IsJoined() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.joined
}

// MeshIP returns this node's assigned mesh IP.
func (e *Engine) MeshIP() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.meshIP
}

// Interface returns the WG interface name.
func (e *Engine) Interface() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.iface
}

// PublicKey returns this node's WG public key (empty before Join).
func (e *Engine) PublicKey() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.pubKey
}

// ── Lifecycle ──────────────────────────────────────────────────────────

// JoinResult is the outcome of a successful Join.
type JoinResult struct {
	PublicKey  string
	PrivateKey string // raw base64; caller is responsible for encrypting before sending over the wire
}

// Join generates keys, brings up the WG interface, and marks this node as joined.
func (e *Engine) Join(ctx context.Context, meshIP, iface string, listenPort uint16, networkCIDR, nodeID string) (*JoinResult, error) {
	e.mu.Lock()
	if e.joined {
		e.mu.Unlock()
		return nil, ErrAlreadyJoined
	}
	e.mu.Unlock()

	// Generate keypair.
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	// Build "meshIP/prefix" from network CIDR (e.g. 10.200.0.7/16).
	addrCIDR := meshIP
	if prefix := maskFromCIDR(networkCIDR); prefix != "" {
		addrCIDR = meshIP + "/" + prefix
	}

	// Bring up interface.
	if err := e.WG.CreateInterface(ctx, iface, addrCIDR, int(e.Config.WireGuard.MTU), listenPort); err != nil {
		return nil, fmt.Errorf("create interface: %w", err)
	}
	if err := e.WG.SetPrivateKey(ctx, iface, kp.Private); err != nil {
		// Best-effort cleanup.
		_ = e.WG.DeleteInterface(ctx, iface)
		return nil, fmt.Errorf("set private key: %w", err)
	}

	e.mu.Lock()
	e.joined = true
	e.meshIP = meshIP
	e.iface = iface
	e.nodeID = nodeID
	e.privKey = kp.Private
	e.pubKey = kp.Public
	e.mu.Unlock()

	if err := e.persist(); err != nil {
		e.Log.Warn("persist after Join failed", "error", err)
	}

	e.Log.Info("joined mesh",
		"mesh_ip", meshIP,
		"interface", iface,
		"listen_port", listenPort,
		"public_key", kp.Public,
	)

	return &JoinResult{PublicKey: kp.Public, PrivateKey: kp.Private}, nil
}

// Leave tears down WireGuard and clears registry.
func (e *Engine) Leave(ctx context.Context, reason string) error {
	e.mu.Lock()
	joined := e.joined
	iface := e.iface
	e.mu.Unlock()

	if !joined {
		return nil
	}

	if err := e.WG.DeleteInterface(ctx, iface); err != nil {
		e.Log.Warn("delete interface failed", "error", err, "iface", iface)
	}

	e.mu.Lock()
	e.joined = false
	e.meshIP = ""
	e.iface = ""
	e.nodeID = ""
	e.privKey = ""
	e.pubKey = ""
	e.mu.Unlock()

	// Clear peer registry and persist.
	for _, p := range e.Peers.Snapshot() {
		e.Peers.Remove(p.ID)
	}
	if err := e.persist(); err != nil {
		e.Log.Warn("persist after Leave failed", "error", err)
	}

	e.Log.Info("left mesh", "reason", reason)
	return nil
}

// ── Peers ──────────────────────────────────────────────────────────────

// AddPeer installs a peer on the WG interface and registers it.
func (e *Engine) AddPeer(ctx context.Context, p *peer.Peer, keepaliveOverride time.Duration) error {
	if !e.IsJoined() {
		return ErrNotJoined
	}
	ka := e.keepalive
	if keepaliveOverride > 0 {
		ka = keepaliveOverride
	}
	if err := e.WG.AddPeer(ctx, e.Interface(), wireguard.PeerConfig{
		PublicKey:                   p.PublicKey,
		Endpoint:                    p.Endpoint,
		AllowedIPs:                  p.AllowedIPs,
		PersistentKeepaliveInterval: ka,
	}); err != nil {
		return fmt.Errorf("wg add peer: %w", err)
	}
	e.Peers.Upsert(p)
	if err := e.persist(); err != nil {
		e.Log.Warn("persist after AddPeer failed", "error", err)
	}
	return nil
}

// RemovePeer removes a peer from WG and from the registry.
func (e *Engine) RemovePeer(ctx context.Context, peerID int64) error {
	p, ok := e.Peers.Get(peerID)
	if !ok {
		return ErrPeerNotFound
	}
	if err := e.WG.RemovePeer(ctx, e.Interface(), p.PublicKey); err != nil {
		return fmt.Errorf("wg remove peer: %w", err)
	}
	e.Peers.Remove(peerID)
	if err := e.persist(); err != nil {
		e.Log.Warn("persist after RemovePeer failed", "error", err)
	}
	return nil
}

// UpdatePeer changes endpoint / allowed_ips / keepalive for an existing peer.
func (e *Engine) UpdatePeer(ctx context.Context, peerID int64, endpoint string, allowedIPs []string, keepalive time.Duration) error {
	p, ok := e.Peers.Get(peerID)
	if !ok {
		return ErrPeerNotFound
	}
	if endpoint != "" {
		p.Endpoint = endpoint
	}
	if allowedIPs != nil {
		p.AllowedIPs = allowedIPs
	}
	ka := e.keepalive
	if keepalive > 0 {
		ka = keepalive
	}
	if err := e.WG.AddPeer(ctx, e.Interface(), wireguard.PeerConfig{
		PublicKey:                   p.PublicKey,
		Endpoint:                    p.Endpoint,
		AllowedIPs:                  p.AllowedIPs,
		PersistentKeepaliveInterval: ka,
	}); err != nil {
		return fmt.Errorf("wg update peer: %w", err)
	}
	e.Peers.Upsert(p)
	if err := e.persist(); err != nil {
		e.Log.Warn("persist after UpdatePeer failed", "error", err)
	}
	return nil
}

// RefreshPeerStats pulls live stats from the WG interface and updates each
// peer in the registry. Returns the merged list.
func (e *Engine) RefreshPeerStats(ctx context.Context) ([]*peer.Peer, error) {
	if !e.IsJoined() {
		return e.Peers.Snapshot(), nil
	}
	dumps, err := e.WG.ListPeers(ctx, e.Interface())
	if err != nil {
		return nil, err
	}
	// Map dumps by public key for fast lookup.
	byKey := make(map[string]wireguard.PeerDump, len(dumps))
	for _, d := range dumps {
		byKey[d.PublicKey] = d
	}
	for _, p := range e.Peers.Snapshot() {
		d, ok := byKey[p.PublicKey]
		if !ok {
			continue
		}
		p.LastHandshake = d.LastHandshake
		p.RxBytes = d.RxBytes
		p.TxBytes = d.TxBytes
		if !d.LastHandshake.IsZero() && time.Since(d.LastHandshake) < 3*time.Minute {
			p.Status = peer.StatusConnected
		}
	}
	return e.Peers.Snapshot(), nil
}

// ── State persistence ──────────────────────────────────────────────────

func (e *Engine) persist() error {
	e.mu.RLock()
	st := state.State{
		Node: state.NodeState{
			MeshIP:     e.meshIP,
			Interface:  e.iface,
			ListenPort: e.Config.WireGuard.ListenPort,
			PrivateKey: e.privKey,
			PublicKey:  e.pubKey,
			NodeID:     e.nodeID,
			Joined:     e.joined,
		},
	}
	e.mu.RUnlock()

	for _, p := range e.Peers.Snapshot() {
		t := "vm"
		if p.Type == peer.TypeScope {
			t = "scope"
		}
		st.Peers = append(st.Peers, state.PeerEntry{
			ID:         p.ID,
			Type:       t,
			MeshIP:     p.MeshIP,
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIPs: p.AllowedIPs,
			ScopeID:    p.ScopeID,
		})
	}
	return e.Store.Save(&st)
}

// ── Errors ─────────────────────────────────────────────────────────────

var (
	ErrAlreadyJoined = errors.New("engine: already joined")
	ErrNotJoined     = errors.New("engine: not joined")
	ErrPeerNotFound  = errors.New("engine: peer not found")
)

// maskFromCIDR extracts "16" from "10.200.0.0/16". Returns "" if parse fails.
func maskFromCIDR(cidr string) string {
	for i := len(cidr) - 1; i >= 0; i-- {
		if cidr[i] == '/' {
			return cidr[i+1:]
		}
	}
	return ""
}
