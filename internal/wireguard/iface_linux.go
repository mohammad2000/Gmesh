//go:build linux

package wireguard

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// ifaceEnsure creates the WG interface if it doesn't exist, assigns addrCIDR,
// sets MTU, and brings it up. Idempotent.
func ifaceEnsure(ctx context.Context, name, addrCIDR string, mtu int) error {
	exists, err := ifaceExists(name)
	if err != nil {
		return err
	}
	if !exists {
		if err := run(ctx, "ip", "link", "add", "dev", name, "type", "wireguard"); err != nil {
			return fmt.Errorf("ip link add %s type wireguard: %w", name, err)
		}
	}
	if addrCIDR != "" {
		// Best-effort; may already exist.
		_ = run(ctx, "ip", "address", "add", addrCIDR, "dev", name)
	}
	if mtu > 0 {
		if err := run(ctx, "ip", "link", "set", "dev", name, "mtu", itoa(mtu)); err != nil {
			return fmt.Errorf("set mtu: %w", err)
		}
	}
	if err := run(ctx, "ip", "link", "set", "up", "dev", name); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	// Make the host actually forward decrypted mesh traffic. Without this
	// the kernel correctly decrypts incoming packets but the FORWARD chain
	// drops them when the destination is another peer (cross-VM scope→
	// scope hits this — the packet has to cross wg-gmesh in and out, or
	// wg-gmesh in and another interface out for egress profiles). Most
	// hosts ship FORWARD policy=DROP, so without an explicit allow
	// nothing crosses. Hub-and-spoke scope-to-scope tests hung at the
	// parent VM until `iptables -I FORWARD -i wg-gmesh -j ACCEPT` was
	// added by hand; this folds that into the interface lifecycle so a
	// reboot or `ip link del` + Join cycle can't strand the mesh.
	ensureForwardAllow(ctx, name)
	// Net-level prerequisite: ip_forward must be on for the rules above
	// to do anything. Idempotent — set every time so a stale sysctl from
	// a previous boot can't leave the mesh silently broken.
	_ = run(ctx, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
	return nil
}

// ensureForwardAllow installs `-i name -j ACCEPT` and `-o name -j ACCEPT`
// in the iptables FORWARD chain if missing. Errors are non-fatal — gmeshd
// must come up even when iptables is absent (containerized or alt-firewall
// hosts), the operator just won't get cross-VM mesh forwarding without
// equivalent rules elsewhere.
func ensureForwardAllow(ctx context.Context, name string) {
	if name == "" {
		return
	}
	for _, direction := range []string{"-i", "-o"} {
		// `-C` returns 0 if the rule already exists, non-zero otherwise.
		// We don't want a flag day where every gmeshd restart prepends
		// another duplicate.
		check := exec.CommandContext(ctx, "iptables", "-C", "FORWARD", direction, name, "-j", "ACCEPT")
		if err := check.Run(); err == nil {
			continue
		}
		// `-I` prepends — important: jumps to e.g. DOCKER-USER or
		// kube-proxy chains that come earlier could reject our packets
		// before our rule fires. Putting our allow at the head wins
		// against any policy=drop further down. Best-effort: a missing
		// iptables binary or lacking CAP_NET_ADMIN just leaves the
		// host without the auto-rule and we keep going.
		_ = run(ctx, "iptables", "-I", "FORWARD", direction, name, "-j", "ACCEPT")
	}
}

// ifaceDelete removes the WG interface if present and tears down the
// FORWARD allow rules ifaceEnsure installed. The rules are matched by
// interface name so a deleted interface leaves dangling rules behind
// otherwise; iptables tolerates it (the rule never matches once the
// iface is gone) but `iptables -L` then accumulates noise across
// gmeshd restarts.
func ifaceDelete(name string) error {
	for _, direction := range []string{"-i", "-o"} {
		// `-D` until the rule is gone — `-I` only ever adds one but a
		// pre-existing manual duplicate could leave more than one
		// hanging around. Cap at 5 to avoid a pathological loop.
		for i := 0; i < 5; i++ {
			cmd := exec.Command("iptables", "-D", "FORWARD", direction, name, "-j", "ACCEPT")
			if err := cmd.Run(); err != nil {
				break
			}
		}
	}
	exists, err := ifaceExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return exec.Command("ip", "link", "del", "dev", name).Run()
}

// ifaceExists checks `ip link show <name>`.
func ifaceExists(name string) (bool, error) {
	out, err := exec.Command("ip", "link", "show", name).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "does not exist") ||
			strings.Contains(string(out), "Cannot find device") {
			return false, nil
		}
		return false, fmt.Errorf("ip link show %s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return true, nil
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}
