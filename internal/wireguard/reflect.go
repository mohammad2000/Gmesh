package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/mohammad2000/Gmesh/internal/stunlite"
)

// Reflector learns how the WireGuard listen port looks from outside the
// NAT: it sends a STUN binding request from that very port. That address
// (not the one of some other socket) is what a peer must aim at to punch
// through.
type Reflector interface {
	Reflexive(ctx context.Context, iface string, port uint16, server netip.AddrPort) (netip.AddrPort, error)
}

// ErrNoReflexive: this backend can't send from the WireGuard port.
var ErrNoReflexive = errors.New("reflexive address: not supported by this WireGuard backend")

// stunBind wraps wireguard-go's socket: STUN answers for our own
// transactions are taken out of the receive path (size set to 0, which
// the device skips), everything else passes through.
type stunBind struct {
	conn.Bind
	mu      sync.Mutex
	waiters map[stunlite.TxID]chan netip.AddrPort
}

func newSTUNBind(b conn.Bind) *stunBind {
	return &stunBind{Bind: b, waiters: map[stunlite.TxID]chan netip.AddrPort{}}
}

func (s *stunBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := s.Bind.Open(port)
	if err != nil {
		return fns, actual, err
	}
	out := make([]conn.ReceiveFunc, len(fns))
	for i, f := range fns {
		out[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := f(packets, sizes, eps)
			s.mu.Lock()
			if len(s.waiters) > 0 {
				for j := 0; j < n; j++ {
					b := packets[j][:sizes[j]]
					for tx, ch := range s.waiters {
						if a, ok := stunlite.ParseResponse(b, tx); ok {
							select {
							case ch <- a:
							default:
							}
							sizes[j] = 0
							break
						}
					}
				}
			}
			s.mu.Unlock()
			return n, err
		}
	}
	return out, actual, nil
}

func (s *stunBind) reflexive(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
	ep, err := s.Bind.ParseEndpoint(server.String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	tx := stunlite.NewTxID()
	ch := make(chan netip.AddrPort, 1)
	s.mu.Lock()
	s.waiters[tx] = ch
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.waiters, tx); s.mu.Unlock() }()
	req := stunlite.Request(tx)
	t := time.NewTicker(400 * time.Millisecond)
	defer t.Stop()
	for i := 0; ; i++ {
		if i < 4 {
			if err := s.Bind.Send([][]byte{req}, ep); err != nil {
				return netip.AddrPort{}, err
			}
		}
		select {
		case a := <-ch:
			return a, nil
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		case <-t.C:
		}
	}
}
