//go:build darwin

package routing

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
)

// DarwinManager installs routes on macOS via the `route` command.
// Kernel routing on macOS doesn't support `ip route` — we shell out to
// `/sbin/route` instead.
//
// Tracked routes are kept in memory so Remove is idempotent even if the
// kernel state is already gone.
type DarwinManager struct {
	Log *slog.Logger

	mu     sync.Mutex
	routes map[string]Route // key: "meshIP/iface"
}

// NewDarwin returns a real macOS routing manager.
func NewDarwin(log *slog.Logger) *DarwinManager {
	if log == nil {
		log = slog.Default()
	}
	return &DarwinManager{Log: log, routes: make(map[string]Route)}
}

// Ensure installs a host route to meshIP via iface. sourceIP is ignored
// on Darwin — `route -ifp` does not accept a per-route source address.
// Packets already pick the interface's primary address.
//
// Semantics match LinuxManager.Ensure: idempotent, replaces existing.
func (m *DarwinManager) Ensure(ctx context.Context, meshIP, iface, _ string) error {
	if meshIP == "" || iface == "" {
		return fmt.Errorf("routing: meshIP and iface required")
	}
	target := normalizeMeshIP(meshIP)

	// `route add -host X -interface Y` fails if the route exists; we
	// silently delete first so the call is idempotent. Ignore the
	// delete failure — missing is fine.
	_ = runCmd(ctx, "/sbin/route", "-n", "delete", target)

	if err := runCmd(ctx, "/sbin/route", "-n", "add", target, "-interface", iface); err != nil {
		return fmt.Errorf("route add %s -interface %s: %w", target, iface, err)
	}

	m.mu.Lock()
	m.routes[target+"/"+iface] = Route{MeshIP: meshIP, Interface: iface}
	m.mu.Unlock()

	m.Log.Debug("route installed", "mesh_ip", meshIP, "iface", iface)
	return nil
}

// Remove deletes the tracked route. Missing-in-kernel is not an error.
func (m *DarwinManager) Remove(ctx context.Context, meshIP, iface string) error {
	if meshIP == "" || iface == "" {
		return nil
	}
	target := normalizeMeshIP(meshIP)

	if err := runCmd(ctx, "/sbin/route", "-n", "delete", target); err != nil {
		lower := strings.ToLower(err.Error())
		if !strings.Contains(lower, "not in table") &&
			!strings.Contains(lower, "no such process") {
			return fmt.Errorf("route delete %s: %w", target, err)
		}
	}

	m.mu.Lock()
	delete(m.routes, target+"/"+iface)
	m.mu.Unlock()

	m.Log.Debug("route removed", "mesh_ip", meshIP, "iface", iface)
	return nil
}

// List returns tracked routes (not the full kernel table).
func (m *DarwinManager) List() []Route {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Route, 0, len(m.routes))
	for _, r := range m.routes {
		out = append(out, r)
	}
	return out
}

// runCmd executes a command and returns trimmed output on error.
func runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
