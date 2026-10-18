//go:build !linux

package wireguard

import (
	"context"
	"net/netip"
)

// Reflexive is not available for kernel WireGuard off Linux.
func (k *kernelManager) Reflexive(context.Context, string, uint16, netip.AddrPort) (netip.AddrPort, error) {
	return netip.AddrPort{}, ErrNoReflexive
}
