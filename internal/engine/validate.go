package engine

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Peer address validation.
//
// AddPeer/UpdatePeer used to install whatever the control plane sent:
// normalizeMeshIP passes anything containing "/" through, so a mesh_ip of
// "0.0.0.0/0" or "192.168.2.0/24" became `ip route replace … dev wg-gmesh`
// and took the host's default or LAN route; and because WireGuard
// AllowedIPs are exclusive per peer, one peer given 10.200.0.0/16 stole the
// whole mesh from every other peer. A bug or a forged message upstream was
// enough. These checks keep a peer to addresses it can legitimately own.

// minAllowedPrefix is the widest non-mesh range a peer may carry (a site
// LAN behind a router client); anything wider is a routing takeover.
const minAllowedPrefix = 16

// localAddrs lists this host's own addresses; a test can replace it.
var localAddrs = func() []netip.Addr {
	var out []netip.Addr
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

// validatePeerAddrs checks a peer's mesh IP and AllowedIPs against the
// mesh this node joined.
func (e *Engine) validatePeerAddrs(meshIP string, allowed []string) error {
	e.mu.RLock()
	cidr, self := e.networkCIDR, e.meshIP
	e.mu.RUnlock()

	var mesh netip.Prefix
	if cidr != "" {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("node mesh cidr %q is invalid: %w", cidr, err)
		}
		mesh = p.Masked()
	}
	selfIP, _ := netip.ParseAddr(strings.Split(self, "/")[0])

	if meshIP != "" {
		ip, err := parseHost(meshIP)
		if err != nil {
			return fmt.Errorf("mesh_ip %q: %w", meshIP, err)
		}
		if mesh.IsValid() && !mesh.Contains(ip) {
			return fmt.Errorf("mesh_ip %s is outside the mesh %s", ip, mesh)
		}
		if selfIP.IsValid() && ip == selfIP {
			return fmt.Errorf("mesh_ip %s is this node's own address", ip)
		}
	}

	local := localAddrs()
	for _, raw := range allowed {
		pfx, err := parseAllowed(raw)
		if err != nil {
			return fmt.Errorf("allowed_ip %q: %w", raw, err)
		}
		if mesh.IsValid() && pfx.Overlaps(mesh) {
			// Inside the mesh a peer owns single addresses, never a slice
			// of it (that would pull other peers' traffic onto this one).
			if !(pfx.IsSingleIP() && mesh.Contains(pfx.Addr())) {
				return fmt.Errorf("allowed_ip %s claims part of the mesh %s; only single addresses are allowed", pfx, mesh)
			}
			if selfIP.IsValid() && pfx.Addr() == selfIP {
				return fmt.Errorf("allowed_ip %s is this node's own address", pfx)
			}
			continue
		}
		if pfx.Bits() < minAllowedPrefix {
			return fmt.Errorf("allowed_ip %s is wider than /%d", pfx, minAllowedPrefix)
		}
		if !pfx.Addr().IsPrivate() {
			return fmt.Errorf("allowed_ip %s is not a private range", pfx)
		}
		// Never route this host's own networks into the tunnel.
		for _, a := range local {
			if a.IsLoopback() || (mesh.IsValid() && mesh.Contains(a)) {
				continue
			}
			if pfx.Contains(a) {
				return fmt.Errorf("allowed_ip %s contains this host's address %s", pfx, a)
			}
		}
	}
	return nil
}

func parseHost(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, err
		}
		if !pfx.IsSingleIP() {
			return netip.Addr{}, fmt.Errorf("must be a single address, got %s", pfx)
		}
		s = s[:i]
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if !ip.Is4() {
		return netip.Addr{}, fmt.Errorf("must be IPv4")
	}
	return ip, nil
}

func parseAllowed(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		ip, err := parseHost(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(ip, 32), nil
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !pfx.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("must be IPv4")
	}
	if pfx != pfx.Masked() {
		return netip.Prefix{}, fmt.Errorf("host bits set (did you mean %s?)", pfx.Masked())
	}
	return pfx, nil
}
