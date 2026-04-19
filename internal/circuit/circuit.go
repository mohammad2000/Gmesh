// Package circuit implements multi-hop source-routed paths through the
// mesh. A Circuit is an ordered list of peer IDs that traffic matching
// the circuit's filter must traverse before reaching the destination:
//
//     source_node  ──wg──▶  hop[0]  ──wg──▶  hop[1]  ──wg──▶ … ──▶ exit
//
// # Why not Tor-style onion routing
//
// Full Tor-style onion routing requires layered encryption where each
// hop only learns the next hop, not the full path. WireGuard is a
// point-to-point transport, not a layered cipher stack, so we do NOT
// provide that property here. What we DO provide is the operational
// benefit that motivates most "onion" requests in practice:
//
//   - Traffic egresses to the internet from the LAST hop's public IP.
//   - Intermediate hops act as traffic transit (they see ciphertext of
//     the inner WireGuard tunnel but can't decrypt it — WG is E2E
//     between source and exit).
//   - If a hop is compromised, it can de-anonymise the path only to
//     the extent its view allows: a transit hop sees
//     source_mesh_ip ↔ exit_mesh_ip; the exit sees source_mesh_ip ↔
//     internet_dest.
//
// For true Tor-style anonymity (each hop knows only +1 / −1), wrap
// this with an application-layer onion stack in a future phase.
//
// # Role per node
//
// Each node independently runs gmeshd, so the same Circuit object is
// pushed to every node in the hop list (plus the source). Each node
// figures out its ROLE by comparing its own peer ID with the hops:
//
//     Role            When                       Kernel state installed
//     ─────────────── ────────────────────────── ─────────────────────────
//     source          local peer = circuit src    mark + route dest → h[0]
//     transit         local peer in hops[1..N-2]  ip_forward + mark +
//                                                 route dest → h[i+1]
//     exit            local peer = hops[N-1]      ip_forward + masquerade
//
// The source role is applied on the node that owns the circuit's
// Source field; nodes not listed in Hops or Source become no-ops
// (they simply don't install anything).
//
// # Data model
package circuit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

// Circuit describes one multi-hop path.
type Circuit struct {
	ID       int64
	Name     string
	Enabled  bool
	Priority int32

	// Source is the originating peer. Traffic from this peer matching
	// the filter below is source-routed through Hops.
	Source int64

	// Hops is the ordered list of peer IDs the traffic must traverse,
	// ending with the exit peer. Must have length >= 1.
	Hops []int64

	// Filter (same surface as egress.Profile's match).
	Protocol  string // "any" | "tcp" | "udp"
	DestCIDR  string
	DestPorts string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Role identifies what a node should install.
type Role int

const (
	RoleNone    Role = iota
	RoleSource        // mark + route to hops[0]
	RoleTransit       // forward from prev hop to next hop
	RoleExit          // terminate + masquerade out
)

// String renders the role for logs.
func (r Role) String() string {
	switch r {
	case RoleSource:
		return "source"
	case RoleTransit:
		return "transit"
	case RoleExit:
		return "exit"
	default:
		return "none"
	}
}

// Validate checks structural invariants.
func (c *Circuit) Validate() error {
	if c.Name == "" {
		return errors.New("circuit: name required")
	}
	if c.Priority < 0 || c.Priority > 1000 {
		return errors.New("circuit: priority out of range [0..1000]")
	}
	if c.Source == 0 {
		return errors.New("circuit: source peer required")
	}
	if len(c.Hops) == 0 {
		return errors.New("circuit: at least one hop required")
	}
	for i, h := range c.Hops {
		if h == 0 {
			return fmt.Errorf("circuit: hops[%d] is zero", i)
		}
		if h == c.Source {
			return fmt.Errorf("circuit: source %d appears in hops (disallowed)", h)
		}
	}
	// Forbid duplicate hops — not a hard protocol invariant but usually
	// a user bug.
	seen := map[int64]bool{}
	for _, h := range c.Hops {
		if seen[h] {
			return fmt.Errorf("circuit: duplicate hop %d", h)
		}
		seen[h] = true
	}
	// Validate optional dest CIDR.
	if c.DestCIDR != "" && c.DestCIDR != "0.0.0.0/0" {
		if _, _, err := net.ParseCIDR(c.DestCIDR); err != nil {
			return fmt.Errorf("circuit: bad dest_cidr %q: %w", c.DestCIDR, err)
		}
	}
	if c.Protocol != "" && c.Protocol != "any" && c.Protocol != "tcp" && c.Protocol != "udp" {
		return errors.New(`circuit: protocol must be "", "any", "tcp", or "udp"`)
	}
	return nil
}

// RoleFor classifies a node's role given its local peer ID.
func (c *Circuit) RoleFor(localPeerID int64) Role {
	if localPeerID == c.Source {
		return RoleSource
	}
	for i, h := range c.Hops {
		if h != localPeerID {
			continue
		}
		if i == len(c.Hops)-1 {
			return RoleExit
		}
		return RoleTransit
	}
	return RoleNone
}

// NextHop returns the peer ID this node should forward to. Only
// meaningful when RoleFor(localPeerID) is RoleSource or RoleTransit.
// Returns 0 for RoleExit / RoleNone.
func (c *Circuit) NextHop(localPeerID int64) int64 {
	if localPeerID == c.Source {
		return c.Hops[0]
	}
	for i, h := range c.Hops {
		if h != localPeerID {
			continue
		}
		if i+1 >= len(c.Hops) {
			return 0
		}
		return c.Hops[i+1]
	}
	return 0
}

// PrevHop returns the peer ID this node should accept from. Used by
// transit + exit nodes to build ingress filter rules. For transit,
// prev is either the source (if this is hop[0]) or hop[i-1]. For
// source / none, returns 0.
func (c *Circuit) PrevHop(localPeerID int64) int64 {
	for i, h := range c.Hops {
		if h != localPeerID {
			continue
		}
		if i == 0 {
			return c.Source
		}
		return c.Hops[i-1]
	}
	return 0
}

// TableID derives a stable routing table number for the circuit. Uses
// a disjoint slice (1000..1999) from egress single/pool space.
func TableID(circuitID int64) int {
	return 1000 + int(circuitID%1000)
}

// FwMark derives a fwmark for the circuit. Uses 0x20______ (reserved
// circuit mark range) so circuit marks never collide with egress's
// 0x10______ space.
func FwMark(circuitID int64) uint32 {
	return 0x20000000 | uint32(circuitID&0x0FFFFFFF)
}

// RulePriority staggers the `ip rule` priority so circuits live above
// ordinary egress profiles.
func RulePriority(priority int32) int {
	return 21000 + int(priority)
}

// Manager installs kernel state for a circuit, respecting the node's
// role.
type Manager interface {
	Create(ctx context.Context, c *Circuit, nextHopMeshIP, wgIface string, localPeerID int64) (*Circuit, error)
	Update(ctx context.Context, c *Circuit, nextHopMeshIP, wgIface string, localPeerID int64) (*Circuit, error)
	Delete(ctx context.Context, circuitID int64) error
	List() []*Circuit
	Name() string
}

// Errors.
var (
	ErrExists   = errors.New("circuit: already exists")
	ErrNotFound = errors.New("circuit: not found")
)

// FormatHops renders the hop list for logs ("1→2→3").
func FormatHops(source int64, hops []int64) string {
	parts := make([]string, 0, len(hops)+1)
	parts = append(parts, fmt.Sprintf("%d", source))
	for _, h := range hops {
		parts = append(parts, fmt.Sprintf("%d", h))
	}
	return strings.Join(parts, "→")
}

// New picks the best backend. Stub on non-Linux; LinuxManager otherwise.
func New(log *slog.Logger) Manager {
	return newPlatformManager(log)
}
