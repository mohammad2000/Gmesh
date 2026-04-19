// Package engine orchestrates the mesh lifecycle. It owns references to every
// other subsystem (wireguard, peer registry, nat discoverer, traversal, relay,
// firewall, routing, health) and exposes high-level verbs that the gRPC
// server calls in response to incoming requests.
package engine

import (
	"context"
	"errors"
	"sync"

	"github.com/mohammad2000/Gmesh/internal/config"
	"github.com/mohammad2000/Gmesh/internal/firewall"
	"github.com/mohammad2000/Gmesh/internal/nat"
	"github.com/mohammad2000/Gmesh/internal/peer"
	"github.com/mohammad2000/Gmesh/internal/relay"
	"github.com/mohammad2000/Gmesh/internal/routing"
	"github.com/mohammad2000/Gmesh/internal/traversal"
	"github.com/mohammad2000/Gmesh/internal/wireguard"
)

// Engine is the central orchestrator.
type Engine struct {
	Config   *config.Config
	Peers    *peer.Registry
	NAT      *nat.Discoverer
	Trav     *traversal.Engine
	WG       wireguard.Manager
	Relay    relay.Client
	Firewall firewall.Backend
	Routing  routing.Manager

	mu      sync.RWMutex
	joined  bool
	meshIP  string
	iface   string
	nodeID  string
	pubKey  string
	privKey string
}

// New wires an Engine together.
func New(cfg *config.Config) *Engine {
	return &Engine{
		Config:  cfg,
		Peers:   peer.NewRegistry(),
		NAT:     nat.NewDiscoverer(cfg.NAT.STUNServers, 0, 0),
		Trav:    traversal.NewEngine(),
		Routing: routing.NewInMemory(),
	}
}

// Start begins background loops (health checks, NAT re-discovery, etc).
// Returns once loops are running; canceling ctx stops them.
func (e *Engine) Start(ctx context.Context) error {
	_ = ctx
	// TODO: start health monitor, NAT refresher, event dispatcher, etc.
	return nil
}

// Stop tears the engine down. Safe to call multiple times.
func (e *Engine) Stop(ctx context.Context) error {
	_ = ctx
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

// Join brings up WireGuard and registers this node on the mesh.
func (e *Engine) Join(ctx context.Context, meshIP, iface string, listenPort uint16, networkCIDR, nodeID string) (pubKey, privKeyEnc string, err error) {
	_ = ctx
	_ = networkCIDR
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.joined {
		return "", "", ErrAlreadyJoined
	}
	// TODO: generate keys, create WG interface, bind listen port, run NAT discovery.
	e.joined = true
	e.meshIP = meshIP
	e.iface = iface
	e.nodeID = nodeID
	_ = listenPort
	return e.pubKey, e.privKey, nil
}

// Leave tears down WireGuard and clears registry.
func (e *Engine) Leave(ctx context.Context, reason string) error {
	_ = ctx
	_ = reason
	e.mu.Lock()
	defer e.mu.Unlock()
	e.joined = false
	return nil
}

// ErrAlreadyJoined is returned from Join when called twice.
var ErrAlreadyJoined = errors.New("engine: already joined")
