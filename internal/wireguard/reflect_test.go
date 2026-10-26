package wireguard

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/mohammad2000/Gmesh/internal/stunlite"
)

func TestSTUNBindReflexive(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		b := make([]byte, 1500)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			if tx, ok := stunlite.ParseRequest(b[:n]); ok {
				_, _ = srv.WriteToUDPAddrPort(stunlite.Response(tx, from), from)
				_, _ = srv.WriteToUDPAddrPort([]byte("not stun, for wireguard"), from)
			}
		}
	}()

	sb := newSTUNBind(conn.NewDefaultBind())
	fns, port, err := sb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	passed := make(chan string, 4)
	// The device hands each receive loop a full batch of buffers; on Linux,
	// with UDP GRO, wireguard-go needs all of them (a single buffer reads
	// nothing there).
	batch := sb.BatchSize()
	for _, f := range fns { // the device's receive loops
		go func(f conn.ReceiveFunc) {
			bufs := make([][]byte, batch)
			for i := range bufs {
				bufs[i] = make([]byte, 65535)
			}
			sizes := make([]int, batch)
			eps := make([]conn.Endpoint, batch)
			for {
				n, err := f(bufs, sizes, eps)
				if err != nil {
					return
				}
				for i := 0; i < n; i++ {
					if sizes[i] > 0 {
						passed <- string(bufs[i][:sizes[i]])
					}
				}
			}
		}(f)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, err := sb.reflexive(ctx, netip.MustParseAddrPort(srv.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if a.Port() != port {
		t.Fatalf("reflexive %v, want port %d", a, port)
	}
	select {
	case p := <-passed:
		if p != "not stun, for wireguard" {
			t.Fatalf("the STUN answer leaked to the device: %q", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary packet did not reach the device")
	}
}
