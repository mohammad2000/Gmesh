// Package routing manages `ip route` state for mesh peers: one /32 host
// route per peer mesh_ip pointing at the WG interface, plus conflict
// resolution when another interface claims the same prefix.
//
// Two implementations live here:
//
//   - InMemory: tracks state only, no kernel side-effects. Used on macOS
//     dev and in tests.
//   - LinuxManager (linux.go): issues real `ip route replace / del`
//     commands via iproute2.
//
// Picked at runtime via New(), which returns LinuxManager on Linux and
// falls back to InMemory elsewhere.
package routing

import (
	"context"
	"errors"
	"log/slog"
	"sync"
)

// Manager is the routing abstraction.
type Manager interface {
	// Ensure installs a /32 route to mesh_ip via interface. Idempotent.
	Ensure(ctx context.Context, meshIP, iface string) error

	// Remove deletes the route.
	Remove(ctx context.Context, meshIP, iface string) error

	// List returns all routes currently tracked by this manager (not the
	// full kernel routing table).
	List() []Route
}

// Route is a single tracked route.
type Route struct {
	MeshIP    string
	Interface string
}

// InMemory is a placeholder implementation that tracks state but does not
// issue `ip route` commands yet.
type InMemory struct {
	mu     sync.Mutex
	routes map[string]Route // key: "meshIP/iface"
}

// NewInMemory returns an empty InMemory manager.
func NewInMemory() *InMemory { return &InMemory{routes: make(map[string]Route)} }

// Ensure adds a tracked route. TODO: issue `ip route replace`.
func (m *InMemory) Ensure(_ context.Context, meshIP, iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[meshIP+"/"+iface] = Route{MeshIP: meshIP, Interface: iface}
	return nil
}

// Remove deletes a tracked route. TODO: issue `ip route del`.
func (m *InMemory) Remove(_ context.Context, meshIP, iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.routes, meshIP+"/"+iface)
	return nil
}

// List returns a snapshot.
func (m *InMemory) List() []Route {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Route, 0, len(m.routes))
	for _, r := range m.routes {
		out = append(out, r)
	}
	return out
}

// ErrNotImplemented is returned by real backends still under construction.
var ErrNotImplemented = errors.New("routing: not implemented")

// New returns the best available routing backend for the current host.
// Linux → LinuxManager; everything else → InMemory.
func New(log *slog.Logger) Manager { return newPlatformManager(log) }
