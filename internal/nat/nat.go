// Package nat owns STUN discovery and NAT-type classification.
//
// The public entry point is Discover, which returns the node's external
// (host, port, NAT type) tuple. Results are cached in memory for the TTL
// defined in config.NATConfig.
package nat

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Type enumerates the possible NAT classifications. Matches gmesh.v1.NATType.
type Type int

const (
	Unknown Type = iota
	Open
	FullCone
	RestrictedCone
	PortRestrictedCone
	Symmetric
)

// String returns the lowercase canonical name.
func (t Type) String() string {
	switch t {
	case Open:
		return "open"
	case FullCone:
		return "full_cone"
	case RestrictedCone:
		return "restricted_cone"
	case PortRestrictedCone:
		return "port_restricted_cone"
	case Symmetric:
		return "symmetric"
	default:
		return "unknown"
	}
}

// IsSymmetric reports whether hole-punching is effectively impossible.
func (t Type) IsSymmetric() bool { return t == Symmetric }

// SupportsHolePunch reports whether STUN-assisted hole-punching is viable.
func (t Type) SupportsHolePunch() bool {
	return t == Open || t == FullCone || t == RestrictedCone || t == PortRestrictedCone
}

// Info is the full NAT discovery result.
type Info struct {
	Type              Type
	ExternalIP        string
	ExternalPort      uint16
	SupportsHolePunch bool
	IsRelayCapable    bool
	DiscoveredAt      time.Time
}

// Discoverer runs STUN queries and caches the result.
type Discoverer struct {
	Servers []string
	Timeout time.Duration
	TTL     time.Duration

	mu    sync.RWMutex
	cache *Info
}

// NewDiscoverer returns a Discoverer bound to the given STUN server list.
func NewDiscoverer(servers []string, timeout, ttl time.Duration) *Discoverer {
	return &Discoverer{Servers: servers, Timeout: timeout, TTL: ttl}
}

// Discover returns the cached Info if still fresh, otherwise runs a full
// STUN probe across all configured servers.
//
// TODO: real implementation. Current version is a placeholder.
func (d *Discoverer) Discover(ctx context.Context, forceRefresh bool) (*Info, error) {
	if !forceRefresh {
		d.mu.RLock()
		c := d.cache
		d.mu.RUnlock()
		if c != nil && time.Since(c.DiscoveredAt) < d.TTL {
			return c, nil
		}
	}

	_ = ctx
	return nil, errors.New("not implemented")
}
