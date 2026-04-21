//go:build linux

package routing

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
)

// LinuxManager issues `ip route` commands via the `iproute2` suite.
// Tracked routes are kept in memory so Remove is idempotent even if the
// kernel state is already gone (e.g. after a reboot of the gmeshd daemon
// while kernel state persisted, or vice versa).
type LinuxManager struct {
	Log *slog.Logger

	mu     sync.Mutex
	routes map[string]Route // key: "meshIP/iface"
}

// NewLinux returns a real Linux routing manager.
func NewLinux(log *slog.Logger) *LinuxManager {
	if log == nil {
		log = slog.Default()
	}
	return &LinuxManager{Log: log, routes: make(map[string]Route)}
}

// Ensure installs a /32 (or /128) route to meshIP via iface, replacing
// any conflicting route on a different interface.
//
// sourceIP is optional. When non-empty the route is installed with
// `src <sourceIP>`, pinning the kernel's source-IP choice for packets
// heading to this peer. This matters when iface has multiple addresses
// (e.g. a host bridging the 10.200.* and 10.250.* meshes) — without
// src the kernel picks the interface's primary IP, the remote peer's
// WireGuard allowed_ips rejects it, and handshakes silently go one-
// way (you can ping out but not in). Callers that don't need it pass "".
func (m *LinuxManager) Ensure(ctx context.Context, meshIP, iface, sourceIP string) error {
	if meshIP == "" || iface == "" {
		return fmt.Errorf("routing: meshIP and iface required")
	}
	target := normalizeMeshIP(meshIP)

	args := []string{"route", "replace", target, "dev", iface}
	if sourceIP != "" {
		args = append(args, "src", sourceIP)
	}
	// `ip route replace` will insert if missing, overwrite if present.
	if err := run(ctx, "ip", args...); err != nil {
		return fmt.Errorf("ip route replace %s dev %s: %w", target, iface, err)
	}

	m.mu.Lock()
	m.routes[target+"/"+iface] = Route{MeshIP: meshIP, Interface: iface}
	m.mu.Unlock()

	m.Log.Debug("route installed", "mesh_ip", meshIP, "iface", iface, "src", sourceIP)
	return nil
}

// Remove deletes the tracked route. Missing-in-kernel is not an error.
func (m *LinuxManager) Remove(ctx context.Context, meshIP, iface string) error {
	if meshIP == "" || iface == "" {
		return nil
	}
	target := normalizeMeshIP(meshIP)

	// Ignore "No such process" and "cannot find" errors — route may already be gone.
	if err := run(ctx, "ip", "route", "del", target, "dev", iface); err != nil {
		if !strings.Contains(err.Error(), "No such process") &&
			!strings.Contains(err.Error(), "Cannot find") &&
			!strings.Contains(err.Error(), "No route to host") {
			return fmt.Errorf("ip route del %s dev %s: %w", target, iface, err)
		}
	}

	m.mu.Lock()
	delete(m.routes, target+"/"+iface)
	m.mu.Unlock()

	m.Log.Debug("route removed", "mesh_ip", meshIP, "iface", iface)
	return nil
}

// List returns tracked routes (not the full kernel table).
func (m *LinuxManager) List() []Route {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Route, 0, len(m.routes))
	for _, r := range m.routes {
		out = append(out, r)
	}
	return out
}

// run executes a command and returns trimmed output on error.
func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
