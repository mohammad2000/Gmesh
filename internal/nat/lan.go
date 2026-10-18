// LAN candidate discovery.
//
// Enumerates non-loopback, non-wireguard local interfaces and returns
// the usable private IPv4 addresses on them. These are advertised to the
// coordinator so other peers on the same LAN can connect directly
// (much lower latency, no dependence on residential ISP routing or NAT
// hairpinning).
//
// Filters applied:
//   - Skip loopback, down, or point-to-point interfaces.
//   - Skip utun* and wg* interfaces (those are WireGuard's own tun devices).
//   - Require an RFC1918 / link-local-ish IPv4 address
//     (10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10 for CGNAT).
//   - IPv6: GlobalIPv6Endpoints lists the global unicast addresses
//     separately (no NAT on them, so they are WAN candidates).
package nat

import (
	"net"
	"strconv"
	"strings"
)

// LocalEndpoints returns "ip:port" strings for every private IPv4 on
// an interface that's up and not a tunnel. The caller supplies the
// WireGuard listen port — all candidates share that port.
func LocalEndpoints(listenPort uint32) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isTunnelInterface(ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := ipFromAddr(a)
			if ip == nil || ip.To4() == nil {
				continue
			}
			if !isPrivateV4(ip) {
				continue
			}
			out = append(out, net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(listenPort), 10)))
		}
	}
	return out
}

func ipFromAddr(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

// isTunnelInterface matches tunnel and virtual container-network
// interfaces that carry no traffic reachable from other hosts. We skip
// them because advertising e.g. `docker0`'s 172.17.0.1 as a LAN
// candidate poisons the remote peer's endpoint list — nothing outside
// this host can route to that address.
func isTunnelInterface(name string) bool {
	n := strings.ToLower(name)
	switch {
	// WireGuard, userspace tunnels, platform-specific VPN devices.
	case strings.HasPrefix(n, "utun"),
		strings.HasPrefix(n, "wg"),
		strings.HasPrefix(n, "tun"),
		strings.HasPrefix(n, "tap"),
		strings.HasPrefix(n, "gpd"), // gmesh's own
		strings.HasPrefix(n, "zt"),  // ZeroTier
		strings.HasPrefix(n, "tailscale"):
		return true
	// Container / CNI virtual interfaces. Their IPs live entirely
	// inside this host and never route across the internet.
	case strings.HasPrefix(n, "docker"),
		strings.HasPrefix(n, "br-"), // docker/compose user-defined bridges
		strings.HasPrefix(n, "veth"),
		// gmeshd's own scope veths (vh-s<id>/vs-s<id>) and GritivaCore
		// VNet switch ports (vsp-/vsh-): host-local /30s and VNet
		// subnets that peers on other hosts cannot reach.
		strings.HasPrefix(n, "vh-"),
		strings.HasPrefix(n, "vs-"),
		strings.HasPrefix(n, "vsp-"),
		strings.HasPrefix(n, "vsh-"),
		strings.HasPrefix(n, "cni"),
		strings.HasPrefix(n, "cali"), // Calico
		strings.HasPrefix(n, "flannel"),
		strings.HasPrefix(n, "weave"),
		strings.HasPrefix(n, "cilium"),
		strings.HasPrefix(n, "podman"),
		strings.HasPrefix(n, "virbr"), // libvirt
		strings.HasPrefix(n, "vnet"),  // KVM/QEMU
		strings.HasPrefix(n, "kube"):
		return true
	}
	return false
}

// isPrivateV4 returns true for RFC1918, link-local, and CGNAT ranges.
// These are the only addresses worth advertising as a "LAN" candidate —
// everything else we leave to STUN discovery.
func isPrivateV4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	// 10.0.0.0/8
	if v4[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if v4[0] == 192 && v4[1] == 168 {
		return true
	}
	// 169.254.0.0/16 link-local
	if v4[0] == 169 && v4[1] == 254 {
		return true
	}
	// 100.64.0.0/10 CGNAT (some mobile carriers & enterprises)
	if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}

// GlobalIPv6Endpoints returns "[ip]:port" for every global unicast IPv6
// address (2000::/3; not link-local, not ULA) on an interface that's up and
// not a tunnel. Peers that are stuck behind IPv4 NAT/CGNAT on both sides
// can often still reach each other over these.
func GlobalIPv6Endpoints(listenPort uint32) []string {
	var out []string
	for _, ip := range globalIPv6() {
		out = append(out, net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(listenPort), 10)))
	}
	return out
}

// HasGlobalIPv6 reports whether this host has a global IPv6 address at all
// (without one, IPv6 candidates of peers can't be reached from here).
func HasGlobalIPv6() bool { return len(globalIPv6()) > 0 }

func globalIPv6() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || isTunnelInterface(ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := ipFromAddr(a)
			if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip[0]&0xe0 != 0x20 {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}
