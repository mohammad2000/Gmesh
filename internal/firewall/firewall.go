// Package firewall owns the node's mesh firewall. Default backend is
// nftables (atomic replace, modern, JSON introspection). iptables is kept
// as a fallback for old kernels or systems without nft. An in-memory
// backend is used on non-Linux dev hosts and for unit tests.
//
// All rules live in a dedicated table (default "gmesh") and chain prefix
// ("mesh_") so we never touch the user's existing rules. Every Apply
// replaces the full ruleset atomically.
package firewall

import (
	"context"
	"errors"
	"time"
)

// Action matches gmesh.v1.FirewallAction.
type Action int

const (
	ActionUnspecified Action = iota
	ActionAllow
	ActionDeny
	ActionLimit
	ActionLog
)

// String returns the wire-format label.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	case ActionLimit:
		return "limit"
	case ActionLog:
		return "log"
	default:
		return "unspecified"
	}
}

// ParseAction converts a string to Action (case-insensitive).
func ParseAction(s string) Action {
	switch s {
	case "allow", "Allow", "ALLOW":
		return ActionAllow
	case "deny", "drop", "Deny", "DENY":
		return ActionDeny
	case "limit", "Limit", "LIMIT":
		return ActionLimit
	case "log", "Log", "LOG":
		return ActionLog
	default:
		return ActionUnspecified
	}
}

// Protocol matches gmesh.v1.FirewallProtocol.
type Protocol int

const (
	ProtoUnspecified Protocol = iota
	ProtoAny
	ProtoTCP
	ProtoUDP
	ProtoICMP
	ProtoICMPv6
)

// String returns the wire name.
func (p Protocol) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	case ProtoICMPv6:
		return "icmpv6"
	case ProtoAny:
		return "any"
	default:
		return "unspecified"
	}
}

// Direction is where the rule hooks in.
type Direction int

const (
	DirectionInbound  Direction = 0
	DirectionOutbound Direction = 1
	DirectionBoth     Direction = 2
)

// ParseDirection parses "inbound" | "outbound" | "both" (case-insensitive).
func ParseDirection(s string) Direction {
	switch s {
	case "inbound", "in", "INBOUND":
		return DirectionInbound
	case "outbound", "out", "OUTBOUND":
		return DirectionOutbound
	default:
		return DirectionBoth
	}
}

// Rule is the normalized representation handed to a Backend.
type Rule struct {
	ID          int64
	Name        string
	Enabled     bool
	Priority    int32
	Action      Action
	Protocol    Protocol
	Source      string // CIDR | "peer:NN" | "any" | ""
	Destination string
	PortRange   string // "80" | "80-443" | "22,80,443"
	Direction   Direction
	TCPFlags    string // e.g. "syn"
	ConnState   string // e.g. "NEW,ESTABLISHED,RELATED"
	RateLimit   string // e.g. "100/s" | "1000/m"
	RateBurst   uint32
	ScheduleRaw string // JSON — see schedule.go
	ExpiresAt   int64  // unix seconds, 0 = never
	Tags        []string
}

// IsLive returns true if the rule is enabled, not expired, and (if scheduled)
// the schedule window is currently active.
func (r *Rule) IsLive(now time.Time) bool {
	if !r.Enabled {
		return false
	}
	if r.ExpiresAt > 0 && now.Unix() >= r.ExpiresAt {
		return false
	}
	if r.ScheduleRaw != "" {
		s, err := ParseSchedule(r.ScheduleRaw)
		if err != nil || !s.Active(now) {
			return false
		}
	}
	return true
}

// FilterLive returns a new slice containing only currently live rules.
func FilterLive(rules []Rule, now time.Time) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.IsLive(now) {
			out = append(out, r)
		}
	}
	return out
}

// Backend is an abstraction over the kernel firewall engine.
type Backend interface {
	// Ensure creates the gmesh table/chain if missing. Idempotent.
	Ensure(ctx context.Context) error

	// Apply installs the given ruleset atomically (replace-all semantics).
	Apply(ctx context.Context, rules []Rule, defaultPolicy string) (applied int, failed int, errs []error)

	// Reset flushes the gmesh table.
	Reset(ctx context.Context) error

	// List returns the rules currently live in the gmesh chain, best-effort.
	List(ctx context.Context) ([]Rule, error)

	// HitCounts returns per-rule counter snapshots keyed by Rule.ID.
	HitCounts(ctx context.Context) (map[int64]int64, error)

	// Name returns "nftables" | "iptables" | "memory".
	Name() string
}

// ErrNotImplemented indicates a placeholder backend method.
var ErrNotImplemented = errors.New("firewall: not implemented")
