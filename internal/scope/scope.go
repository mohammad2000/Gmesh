// Package scope manages per-scope WireGuard peers that live in their own
// Linux network namespaces.
//
// # Clean model
//
// Gritiva's legacy "scope peer" model treated scopes as logical entries in
// the backend DB with no independent WireGuard identity — traffic for a
// scope's mesh IP just routed through the parent VM's wg-gritiva interface
// via veth. Gmesh switches to the clean model:
//
//   - Each scope owns a dedicated WG keypair, generated at connect time.
//   - The scope's WG interface lives inside a dedicated Linux netns
//     (default name "scope-{id}").
//   - Remote peers add the scope as a first-class WG peer. Handshakes
//     arrive at the host, are DNAT'd into the netns, and terminate at the
//     scope's WG interface — which alone holds the private key.
//   - Traffic out of the scope goes: app → scope's wg-scope (netns) →
//     encapsulated → veth host side → host's default gateway → remote.
//
// # Topology per scope
//
//	Host                                      Scope netns (scope-{id})
//	─────                                     ─────────────────────────
//	eth0 (public)                             wg-scope (10.200.x.y/16)
//	  │                                         │  (own keypair; listen
//	  │  DNAT :listen_port ─────┐              │   on .veth_scope_ip:port)
//	  ▼                          ▼              ▼
//	veth_host (veth_cidr[0]) ◄──── veth ────► veth_scope (veth_cidr[1])
//	                                           default route via veth_host
//
// # Lifecycle
//
//   - Connect: create netns, veth pair, assign IPs, bring up, generate
//     scope keypair, create wg-scope inside netns, add DNAT, optionally
//     install host-side route for scope_mesh_ip/32 via veth.
//   - Disconnect: reverse — delete DNAT, wg-scope, veth pair, netns.
//
// # Platform support
//
// Linux only (real impl). On macOS and other non-Linux hosts the stub
// manager tracks state in memory so unit tests and dev builds still work.
package scope

import (
	"context"
	"errors"
	"time"
)

// Peer is the scope-side view of a netns-isolated peer.
type Peer struct {
	ID            int64
	Netns         string // "scope-{id}"
	MeshIP        string // 10.200.x.x
	VethHost      string // "vh-s{id}"
	VethScope     string // "vs-s{id}"
	VethCIDR      string // "10.50.{id}.0/30"
	VMVethIP      string // "10.50.{id}.1"
	ScopeVethIP   string // "10.50.{id}.2"
	GatewayMeshIP string
	PublicKey     string // scope's own WG public key
	PrivateKey    string // base64; returned from Connect, stored in gmeshd state
	ListenPort    uint16 // host-visible port forwarded to the scope's WG
	CreatedAt     time.Time
}

// Manager owns scope lifecycle.
type Manager interface {
	// Connect creates the netns, veth, WG-in-netns, and DNAT rule.
	// Returns the scope Peer with generated keypair filled in.
	Connect(ctx context.Context, spec Spec) (*Peer, error)

	// Disconnect tears everything down. Idempotent.
	Disconnect(ctx context.Context, scopeID int64) error

	// List returns currently connected scopes.
	List() []*Peer

	// Name identifies the backend ("linux" | "stub").
	Name() string
}

// Spec is the input for Connect. The caller (engine / backend) chooses
// the IPs + listen port; gmeshd doesn't allocate them.
type Spec struct {
	ScopeID       int64
	Netns         string // default: "scope-{id}"
	MeshIP        string // 10.200.x.x/16 scope identity
	VethCIDR      string // /30 for the point-to-point veth link
	VMVethIP      string // host end of veth
	ScopeVethIP   string // scope end of veth
	GatewayMeshIP string // parent VM's mesh_ip, for logging / audit
	ListenPort    uint16 // host-visible UDP port (DNAT'd into netns)
	MTU           int    // WG MTU in netns; default 1420
}

// ErrNotConnected is returned by Disconnect when the scope isn't tracked.
var ErrNotConnected = errors.New("scope: not connected")

// ErrAlreadyConnected is returned by Connect when a scope is already up.
var ErrAlreadyConnected = errors.New("scope: already connected")
