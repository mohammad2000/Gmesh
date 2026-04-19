// Package firewall owns the node's mesh firewall. Default backend is
// nftables (atomic transactions, modern). iptables is kept as a fallback
// for old kernels.
//
// All rules live in a dedicated table (default "gmesh") and chain
// (default "mesh") so we never touch the user's existing rules.
package firewall

import (
	"context"
	"errors"
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

// Rule is the normalized representation handed to a Backend.
type Rule struct {
	ID          int64
	Name        string
	Enabled     bool
	Priority    int32
	Action      Action
	Protocol    Protocol
	Source      string // CIDR | "peer:NN" | "any"
	Destination string
	PortRange   string // "80" | "80-443" | "22,80,443"
	Direction   string // "inbound" | "outbound" | "both"
	TCPFlags    string
	ConnState   string // "NEW,ESTABLISHED,RELATED"
	RateLimit   string // "100/s" | "1000/m"
	RateBurst   uint32
	ScheduleRaw string // JSON cron-ish window
	ExpiresAt   int64  // unix seconds, 0 = never
	Tags        []string
}

// Backend is an abstraction over the kernel firewall engine.
type Backend interface {
	// Ensure creates the gmesh table/chain if missing. Idempotent.
	Ensure(ctx context.Context) error

	// Apply installs the given ruleset atomically (replace-all semantics).
	Apply(ctx context.Context, rules []Rule, defaultPolicy string) (applied int, failed int, errs []error)

	// Reset flushes the gmesh table.
	Reset(ctx context.Context) error

	// List returns the rules currently live in the gmesh chain.
	List(ctx context.Context) ([]Rule, error)

	// HitCounts returns per-rule counter snapshots keyed by Rule.ID.
	HitCounts(ctx context.Context) (map[int64]int64, error)

	// Name returns "nftables" or "iptables".
	Name() string
}

// ErrNotImplemented indicates a placeholder backend method.
var ErrNotImplemented = errors.New("firewall: not implemented")
