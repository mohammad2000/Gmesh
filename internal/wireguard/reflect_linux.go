//go:build linux

package wireguard

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/mohammad2000/Gmesh/internal/stunlite"
)

// Reflexive for kernel WireGuard: the port belongs to the kernel, so the
// request goes out through a raw socket with the WireGuard port as its
// source port; Linux hands raw sockets a copy of every incoming UDP
// datagram, so the answer (which WireGuard itself discards) is seen too.
func (k *kernelManager) Reflexive(ctx context.Context, _ string, port uint16, server netip.AddrPort) (netip.AddrPort, error) {
	if !server.Addr().Is4() {
		return netip.AddrPort{}, errors.New("reflexive address: IPv4 STUN server only")
	}
	c, err := net.ListenIP("ip4:udp", nil)
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer c.Close()
	tx := stunlite.NewTxID()
	payload := stunlite.Request(tx)
	pkt := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], port)
	binary.BigEndian.PutUint16(pkt[2:4], server.Port())
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)))
	copy(pkt[8:], payload) // checksum 0: "none" is valid for UDP over IPv4
	dst := &net.IPAddr{IP: server.Addr().AsSlice()}

	deadline := time.Now().Add(2500 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	buf := make([]byte, 2048)
	nextSend := time.Time{}
	for sent := 0; time.Now().Before(deadline); {
		if sent < 4 && !time.Now().Before(nextSend) {
			if _, err := c.WriteToIP(pkt, dst); err != nil {
				return netip.AddrPort{}, err
			}
			sent++
			nextSend = time.Now().Add(500 * time.Millisecond)
		}
		_ = c.SetReadDeadline(minTime(nextSend, deadline))
		n, from, err := c.ReadFromIP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return netip.AddrPort{}, err
		}
		if n < 8 || !from.IP.Equal(dst.IP) {
			continue
		}
		b := buf[:n]
		if binary.BigEndian.Uint16(b[0:2]) != server.Port() || binary.BigEndian.Uint16(b[2:4]) != port {
			continue
		}
		if a, ok := stunlite.ParseResponse(b[8:], tx); ok {
			return a, nil
		}
	}
	return netip.AddrPort{}, errors.New("reflexive address: no STUN answer")
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
