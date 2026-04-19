// Package wireguard wraps the kernel WireGuard device (via wgctrl) and falls
// back to the userspace wireguard-go implementation when the kernel module
// is unavailable. A single Manager instance owns the interface lifecycle.
package wireguard

import (
	"context"
	"errors"
	"time"
)

// Manager is the high-level interface for WireGuard management.
type Manager interface {
	// CreateInterface brings up the WG device with the given address.
	CreateInterface(ctx context.Context, name, addrCIDR string, mtu int, listenPort uint16) error

	// DeleteInterface tears down the WG device.
	DeleteInterface(ctx context.Context, name string) error

	// GenerateKey returns a fresh (privateKey, publicKey) pair (base64).
	GenerateKey() (privateKey, publicKey string, err error)

	// SetPrivateKey installs the private key on the interface.
	SetPrivateKey(ctx context.Context, iface, privKeyB64 string) error

	// AddPeer upserts a peer.
	AddPeer(ctx context.Context, iface string, p PeerConfig) error

	// RemovePeer removes a peer by public key.
	RemovePeer(ctx context.Context, iface, publicKey string) error

	// ListPeers returns all configured peers on the interface.
	ListPeers(ctx context.Context, iface string) ([]PeerDump, error)
}

// PeerConfig is the input for AddPeer.
type PeerConfig struct {
	PublicKey                   string
	Endpoint                    string // host:port
	AllowedIPs                  []string
	PersistentKeepaliveInterval time.Duration
	PresharedKey                string
}

// PeerDump is a snapshot of a peer's current state on the interface.
type PeerDump struct {
	PublicKey     string
	Endpoint      string
	AllowedIPs    []string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Backend identifies which WireGuard backend is in use.
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

// Detect returns the preferred available backend. If prefer is BackendKernel and
// the kernel module is present, returns BackendKernel; otherwise userspace.
//
// TODO: real detection. Placeholder returns BackendUnknown with ErrNotImplemented.
func Detect(prefer Backend) (Backend, error) {
	_ = prefer
	return BackendUnknown, ErrNotImplemented
}

// ErrNotImplemented is returned from placeholder methods.
var ErrNotImplemented = errors.New("wireguard: not implemented")
