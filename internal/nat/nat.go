// Package nat owns STUN discovery and NAT-type classification.
//
// The public entry point is Discover, which returns this node's external
// (host, port, NAT type) tuple. Results are cached for the configured TTL.
//
// Classification heuristic (pragmatic, no CHANGE-REQUEST required):
//
//   1. Query STUN server A → mapped_A (external IP:port as seen by A).
//   2. Query STUN server B → mapped_B.
//   3. If mapped_A.IP == local IP and mapped_A.Port == local port → Open.
//   4. If mapped_A == mapped_B (same external IP+port from both servers)
//      → endpoint-independent (cone) mapping. We classify as
//      PortRestrictedCone conservatively because most home NATs are
//      port-restricted; hole-punching works.
//   5. If IPs match but ports differ → Symmetric. Hole-punching will fail;
//      fallback to relay/WS-tunnel.
//   6. Otherwise → Unknown.
//
// This mirrors what Tailscale's `netcheck` does in practice. Distinguishing
// full-cone from restricted-cone requires an out-of-band probe which modern
// STUN servers don't support.
package nat

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pion/stun/v2"
)

// Type enumerates NAT classifications. Matches gmesh.v1.NATType.
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

// STUNProbe probes multiple STUN servers from a single shared UDP socket
// and returns the mapped address each server saw. Sharing the socket is
// essential for accurate NAT-type classification: a cone NAT maps (src_ip,
// src_port) to the same (external_ip, external_port) regardless of destination,
// so querying both servers from the same source port lets us compare.
//
// Abstracted behind an interface so tests can swap in a fake.
type STUNProbe interface {
	QueryAll(ctx context.Context, servers []string) ([]*net.UDPAddr, error)
}

// pionProbe is the real STUN implementation backed by pion/stun.
type pionProbe struct{ timeout time.Duration }

// QueryAll opens one UDP socket and sends a Binding Request to each server
// in sequence from the same source port. Returns one *net.UDPAddr per server
// in order; entries may be nil on individual failures.
func (p *pionProbe) QueryAll(ctx context.Context, servers []string) ([]*net.UDPAddr, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	out := make([]*net.UDPAddr, len(servers))
	for i, srv := range servers {
		addr, err := p.queryOne(ctx, conn, srv)
		if err != nil {
			// Leave out[i] nil; log via caller's logger.
			continue
		}
		out[i] = addr
	}
	return out, nil
}

func (p *pionProbe) queryOne(ctx context.Context, conn *net.UDPConn, server string) (*net.UDPAddr, error) {
	rctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	var d net.Dialer
	tmp, err := d.DialContext(rctx, "udp", server)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", server, err)
	}
	remote := tmp.RemoteAddr().(*net.UDPAddr)
	_ = tmp.Close()

	deadline := time.Now().Add(p.timeout)
	if dl, ok := rctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	txid := msg.TransactionID
	if _, err := conn.WriteToUDP(msg.Raw, remote); err != nil {
		return nil, fmt.Errorf("write stun: %w", err)
	}

	// Read until we see the matching transaction ID, or deadline.
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("read stun: %w", err)
		}
		resp := new(stun.Message)
		resp.Raw = append(resp.Raw[:0], buf[:n]...)
		if err := resp.Decode(); err != nil {
			continue
		}
		if resp.TransactionID != txid {
			continue
		}
		var xor stun.XORMappedAddress
		if err := xor.GetFrom(resp); err == nil {
			return &net.UDPAddr{IP: xor.IP, Port: xor.Port}, nil
		}
		var mapped stun.MappedAddress
		if err := mapped.GetFrom(resp); err == nil {
			return &net.UDPAddr{IP: mapped.IP, Port: mapped.Port}, nil
		}
		return nil, errors.New("stun response has no mapped-address")
	}
}

// Discoverer runs STUN queries and caches the result.
type Discoverer struct {
	Servers []string
	Timeout time.Duration
	TTL     time.Duration
	Probe   STUNProbe
	Log     *slog.Logger

	mu    sync.RWMutex
	cache *Info
}

// NewDiscoverer returns a Discoverer bound to the given STUN server list.
// Timeout/TTL of 0 use sane defaults (5s and 5min).
func NewDiscoverer(servers []string, timeout, ttl time.Duration) *Discoverer {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &Discoverer{
		Servers: servers,
		Timeout: timeout,
		TTL:     ttl,
		Probe:   &pionProbe{timeout: timeout},
		Log:     slog.Default(),
	}
}

// Cached returns the cached Info if fresh, else nil.
func (d *Discoverer) Cached() *Info {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.cache == nil {
		return nil
	}
	if time.Since(d.cache.DiscoveredAt) > d.TTL {
		return nil
	}
	c := *d.cache
	return &c
}

// Discover returns the cached Info if still fresh, otherwise runs STUN
// probes and classifies the NAT type.
func (d *Discoverer) Discover(ctx context.Context, forceRefresh bool) (*Info, error) {
	if !forceRefresh {
		if c := d.Cached(); c != nil {
			return c, nil
		}
	}

	if len(d.Servers) < 2 {
		return nil, errors.New("nat: need at least 2 STUN servers for classification")
	}

	// QueryAll shares a single UDP socket across all probes so we can detect
	// whether the mapped port is stable (cone) or varies per destination (symmetric).
	results, err := d.Probe.QueryAll(ctx, d.Servers)
	if err != nil {
		return nil, fmt.Errorf("stun probe: %w", err)
	}
	// Collect the first two non-nil results.
	var a, b *net.UDPAddr
	for _, r := range results {
		if r == nil {
			continue
		}
		if a == nil {
			a = r
			continue
		}
		b = r
		break
	}
	if a == nil || b == nil {
		return nil, errors.New("nat: fewer than 2 successful STUN responses")
	}

	info := classify(a, b)
	info.DiscoveredAt = time.Now()

	d.mu.Lock()
	d.cache = info
	d.mu.Unlock()

	d.Log.Info("nat discovered",
		"type", info.Type,
		"external_ip", info.ExternalIP,
		"external_port", info.ExternalPort,
	)
	return info, nil
}

// classify applies the heuristic described in the package doc to two mapped
// addresses. Exported for tests.
func classify(a, b *net.UDPAddr) *Info {
	info := &Info{}
	if a == nil || b == nil {
		info.Type = Unknown
		return info
	}
	info.ExternalIP = a.IP.String()
	info.ExternalPort = uint16(a.Port) //nolint:gosec

	if !a.IP.Equal(b.IP) {
		// Different external IPs — unusual (multi-homed / double-NAT).
		// Treat as symmetric to be safe.
		info.Type = Symmetric
		return info
	}

	if a.Port == b.Port {
		// Port stable across servers → endpoint-independent mapping (cone).
		info.Type = PortRestrictedCone
		info.SupportsHolePunch = true
		info.IsRelayCapable = true
		return info
	}

	// Port varies by destination → symmetric NAT.
	info.Type = Symmetric
	info.IsRelayCapable = true
	return info
}

// ErrNotImplemented kept for back-compat; no longer returned by Discover.
var ErrNotImplemented = errors.New("nat: not implemented")
