package wireguard

import (
	"context"
	"errors"
	"log/slog"
)

// userspaceManager is a placeholder for the wireguard-go fallback.
//
// A full implementation creates a TUN device via wireguard-go/tun, wires it
// to a wireguard-go device, and exposes the uapi socket so wgctrl can
// configure it. That lands in Phase 1.5 if any target platform lacks the
// in-kernel WG module.
type userspaceManager struct {
	log *slog.Logger //nolint:unused // kept for future impl
}

// errUserspaceNotImplemented is the sentinel returned by every method.
var errUserspaceNotImplemented = errors.New("userspace wireguard-go: not yet implemented (Phase 1.5)")

func newUserspaceManager(_ *slog.Logger) (*userspaceManager, error) {
	return nil, errUserspaceNotImplemented
}

func (u *userspaceManager) Backend() Backend                                                      { return BackendUserspace }
func (u *userspaceManager) Close() error                                                          { return nil }
func (u *userspaceManager) CreateInterface(_ context.Context, _, _ string, _ int, _ uint16) error { return errUserspaceNotImplemented }
func (u *userspaceManager) DeleteInterface(_ context.Context, _ string) error                    { return errUserspaceNotImplemented }
func (u *userspaceManager) SetPrivateKey(_ context.Context, _, _ string) error                   { return errUserspaceNotImplemented }
func (u *userspaceManager) AddPeer(_ context.Context, _ string, _ PeerConfig) error              { return errUserspaceNotImplemented }
func (u *userspaceManager) RemovePeer(_ context.Context, _, _ string) error                      { return errUserspaceNotImplemented }
func (u *userspaceManager) ListPeers(_ context.Context, _ string) ([]PeerDump, error)            { return nil, errUserspaceNotImplemented }
