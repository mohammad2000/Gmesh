// Package ingress implements reverse port-forward profiles: traffic
// arriving on a mesh peer's public interface is DNAT'd to a backend
// service reachable through the mesh.
//
// # Example
//
// A home VM runs a web admin panel on 10.250.0.10:8000. Operators want
// it reachable from the public internet at germany-vps.example.com:80.
//
// Solution: on the Germany VPS, install:
//
//	Profile{
//	  BackendPeerID: <home vm peer id>, BackendIP: "10.250.0.10",
//	  BackendPort:   8000,
//	  EdgePeerID:   <self>, EdgePort: 80, Protocol: "tcp",
//	}
//
// gmeshd translates this into the nftables rules below (Linux backend).
//
// # Mechanism
//
// Table `inet gmesh-ingress` has two chains:
//
//   - `prerouting` (type nat, hook prerouting, priority dstnat): the
//     DNAT entry. `tcp dport <edge_port> dnat to <backend_ip>:<backend_port>`.
//   - `forward` (type filter, hook forward, priority filter): allow the
//     mesh-bound leg of the flow so the kernel's default-drop FORWARD
//     doesn't gobble it.
//   - `postrouting` (type nat, hook postrouting, priority srcnat):
//     MASQUERADE to the mesh egress interface so return packets come
//     back to the edge (conntrack keeps the state).
//
// The backend peer needs no special setup beyond having the edge peer in
// its AllowedIPs (already true for any mesh member).
//
// # Platform support
//
// Linux with `nft` on PATH gets the real backend; everything else uses
// the stub that stores profiles in memory for tests and dev.
package ingress

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Profile is the in-memory form of an IngressProfile.
type Profile struct {
	ID              int64
	Name            string
	Enabled         bool
	BackendPeerID   int64
	BackendScopeID  int64
	BackendIP       string
	BackendPort     uint16
	EdgePeerID      int64
	EdgePort        uint16
	Protocol        string // "tcp" | "udp"
	AllowedSources  []string
	RequireMTLS     bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Validate enforces invariants before hitting the kernel.
func (p *Profile) Validate() error {
	if p.Name == "" {
		return errors.New("ingress: name required")
	}
	if p.BackendIP == "" {
		return errors.New("ingress: backend_ip required")
	}
	if p.BackendPort == 0 {
		return errors.New("ingress: backend_port required")
	}
	if p.EdgePort == 0 {
		return errors.New("ingress: edge_port required")
	}
	switch strings.ToLower(p.Protocol) {
	case "", "tcp":
		p.Protocol = "tcp"
	case "udp":
		p.Protocol = "udp"
	default:
		return fmt.Errorf("ingress: protocol %q not supported", p.Protocol)
	}
	if p.RequireMTLS {
		return errors.New("ingress: require_mtls not supported until Phase 20")
	}
	return nil
}

// Manager owns the lifecycle.
type Manager interface {
	Create(ctx context.Context, p *Profile) (*Profile, error)
	Update(ctx context.Context, p *Profile) (*Profile, error)
	Delete(ctx context.Context, profileID int64) error
	List() []*Profile
	Name() string // "linux" | "stub"
}

// Errors.
var (
	ErrExists   = errors.New("ingress: profile already exists")
	ErrNotFound = errors.New("ingress: profile not found")
)
