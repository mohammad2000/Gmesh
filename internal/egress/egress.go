// Package egress implements per-profile outbound routing via a designated
// mesh peer acting as an "exit node".
//
// # Model
//
// An EgressProfile says: "traffic matching filter F on THIS node should
// leave through peer P instead of the local default gateway." The backend
// on the source node installs:
//
//   1. A dedicated routing table (number = 100 + profile.id).
//   2. A default route in that table: via <exit_peer.mesh_ip> dev wg-gmesh.
//   3. nftables mark rule in table `inet gmesh-egress` that stamps matching
//      packets with fwmark = profile.id.
//   4. An ip rule: `from fwmark X lookup T`, with priority 1000 + prio.
//
// The exit peer additionally installs one-time MASQUERADE + FORWARD rules
// (EnableExit RPC) in its own table `inet gmesh-exit`.
//
// # Why a mark table instead of direct `ip rule from <cidr>`?
//
// The fwmark indirection lets us match on full nftables power (L4 ports,
// L4 proto, destination CIDR, connection state) AND still hand the packet
// to the right routing table. Pure `ip rule from <cidr>` can only match
// source address.
//
// # Two-sided coordination
//
// gmeshd on the source side owns everything listed above. gmeshd on the
// exit side is a separate process with no direct knowledge of the source's
// profile — it just installs generic MASQUERADE for any traffic forwarded
// from the mesh interface. Authorisation (who can use this as exit) lives
// in the backend DB and is enforced at profile-creation time, not by
// hop-by-hop checks here.
package egress

import (
	"context"
	"errors"
	"time"
)

// Profile is the in-memory representation of an egress profile.
//
// Field names match the proto 1:1 for easy translation; see api/proto/
// gmesh/v1/gmesh.proto for the wire schema.
type Profile struct {
	ID             int64
	Name           string
	Enabled        bool
	Priority       int32

	SourceScopeID  int64
	SourceCIDR     string
	Protocol       string // "any" | "tcp" | "udp"
	DestCIDR       string
	DestPorts      string

	GeoIPCountries []string // Phase 15 hook

	ExitPeerID     int64
	ExitPool       []int64 // Phase 16 hook
	ExitWeights    []int32 // Phase 16 hook

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate ensures the profile is well-formed before hitting the kernel.
func (p *Profile) Validate() error {
	if p.Name == "" {
		return errors.New("egress: name required")
	}
	if p.Priority < 0 || p.Priority > 1000 {
		return errors.New("egress: priority out of range [0..1000]")
	}
	if p.ExitPeerID == 0 && len(p.ExitPool) == 0 {
		return errors.New("egress: exit_peer_id or exit_pool required")
	}
	if p.Protocol != "" && p.Protocol != "any" && p.Protocol != "tcp" && p.Protocol != "udp" {
		return errors.New(`egress: protocol must be "", "any", "tcp", or "udp"`)
	}
	return nil
}

// Source describes the match for logging + diff.
func (p *Profile) Source() string {
	if p.SourceScopeID != 0 {
		return "scope:" + itoaS(p.SourceScopeID)
	}
	if p.SourceCIDR != "" {
		return "cidr:" + p.SourceCIDR
	}
	return "any"
}

// Manager owns profile lifecycle + kernel state.
type Manager interface {
	// Create installs a profile. Returns ErrExists if a profile with the
	// same ID is already active.
	Create(ctx context.Context, p *Profile, exitPeerMeshIP, wgIface string) (*Profile, error)

	// Update changes fields on an existing profile in place. Uses the
	// compare-and-swap model: caller supplies the full new state.
	Update(ctx context.Context, p *Profile, exitPeerMeshIP, wgIface string) (*Profile, error)

	// Delete removes kernel state for the given profile. Idempotent.
	Delete(ctx context.Context, profileID int64) error

	// List returns a snapshot of current profiles.
	List() []*Profile

	// Name returns "linux" | "stub".
	Name() string
}

// ExitManager is the other side: controls MASQUERADE / FORWARD on a node
// that is used as an exit by others.
type ExitManager interface {
	Enable(ctx context.Context, wgIface string, allowedPeerIDs []int64) error
	Disable(ctx context.Context) error
	IsEnabled() bool
	Name() string
}

// ErrExists is returned by Create when profile.id collides.
var ErrExists = errors.New("egress: profile already exists")

// ErrNotFound is returned by Update/Delete when the profile is unknown.
var ErrNotFound = errors.New("egress: profile not found")

// TableID returns the per-profile routing table number used on the source
// node. 100..1099 matches the kernel's supported range without colliding
// with common defaults (main=254, default=253, local=255).
func TableID(profileID int64) int {
	return 100 + int(profileID%1000)
}

// FwMark returns the packet mark used for the profile. We use the profile
// ID directly, clamped to the unsigned 32-bit range. The full mark space
// is 0..0xFFFFFFFF; gmesh reserves 0x10000000..0x1FFFFFFF for egress
// profiles so other subsystems can use the rest without collisions.
func FwMark(profileID int64) uint32 {
	return 0x10000000 | uint32(profileID&0x0FFFFFFF)
}

// RulePriority derives the `ip rule` priority from profile priority.
// Lower numeric = higher match priority. We stagger gmesh rules above the
// common default rule (priority 32766) to make intent obvious.
func RulePriority(profilePriority int32) int {
	return 20000 + int(profilePriority)
}

func itoaS(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
