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
	return nil
}

// ifaceDelete removes the WG interface if present.
func ifaceDelete(name string) error {
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
