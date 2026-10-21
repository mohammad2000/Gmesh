//go:build !windows

package wireguard

import "golang.zx2c4.com/wireguard/tun"

func createTUN(name string, mtu int) (tun.Device, error) { return tun.CreateTUN(name, mtu) }
