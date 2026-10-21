//go:build windows

package wireguard

import (
	"crypto/sha256"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

// createTUN gives the adapter the same GUID on every start (derived from its
// name). Wintun otherwise picks a new one each time, and whatever Windows
// keeps per adapter — its network profile, firewall rules scoped to the
// interface — stops applying after every gmeshd restart.
func createTUN(name string, mtu int) (tun.Device, error) {
	g := adapterGUID(name)
	return tun.CreateTUNWithRequestedGUID(name, &g, mtu)
}

func adapterGUID(name string) windows.GUID {
	h := sha256.Sum256([]byte("gmesh-adapter:" + name))
	var g windows.GUID
	g.Data1 = uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
	g.Data2 = uint16(h[4])<<8 | uint16(h[5])
	g.Data3 = (uint16(h[6])<<8|uint16(h[7]))&0x0fff | 0x5000 // name-based (v5-style)
	copy(g.Data4[:], h[8:16])
	g.Data4[0] = g.Data4[0]&0x3f | 0x80 // RFC 4122 variant
	return g
}
