// Package wireguard wraps two WireGuard backends:
//
//   - the in-kernel module, configured via netlink using wgctrl;
//   - the userspace wireguard-go implementation, as a fallback.
//
// A single Manager instance owns the interface lifecycle (create, up,
// configure, tear down). The picked backend is opaque to callers.
package wireguard

import (
	"context"
	"errors"
	"time"
)

// Manager is the high-level WireGuard API.
//
// All methods are safe for concurrent use.
type Manager interface {
	// Backend reports which backend this manager uses.
	Backend() Backend

	// CreateInterface brings up the WG device with the given IPv4 address
	// and MTU, and starts listening on listenPort. Idempotent.
	CreateInterface(ctx context.Context, name, addrCIDR string, mtu int, listenPort uint16) error

	// DeleteInterface tears the device down. Idempotent.
	DeleteInterface(ctx context.Context, name string) error

	// SetPrivateKey installs the private key (base64) on the interface.
	SetPrivateKey(ctx context.Context, iface, privKeyB64 string) error

	// AddPeer upserts a peer by public key.
	AddPeer(ctx context.Context, iface string, p PeerConfig) error

	// RemovePeer removes a peer by public key.
	RemovePeer(ctx context.Context, iface, publicKey string) error

	// ListPeers returns a snapshot of every peer configured on the interface.
	ListPeers(ctx context.Context, iface string) ([]PeerDump, error)

	// Close releases any resources held by the manager.
	Close() error
}

// PeerConfig is the input for AddPeer.
type PeerConfig struct {
	PublicKey                   string
	Endpoint                    string // "host:port"
	AllowedIPs                  []string
	PersistentKeepaliveInterval time.Duration
	PresharedKey                string // optional
}

// PeerDump is a snapshot of a peer's current state.
type PeerDump struct {
	PublicKey     string
	Endpoint      string
	AllowedIPs    []string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Backend identifies a WireGuard implementation.
type Backend int

const (
	BackendUnknown Backend = iota
	BackendKernel
	BackendUserspace
)

// String returns the lowercase backend name.
func (b Backend) String() string {
	switch b {
	case BackendKernel:
		return "kernel"
	case BackendUserspace:
		return "userspace"
	default:
		return "unknown"
	}
}

// ErrInterfaceNotFound is returned when the expected WG device is missing.
var ErrInterfaceNotFound = errors.New("wireguard: interface not found")

// ErrBackendUnavailable is returned when no backend is available on this host.
var ErrBackendUnavailable = errors.New("wireguard: no backend available")
