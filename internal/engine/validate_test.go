package engine

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/mohammad2000/Gmesh/internal/peer"
)

func withLocalAddrs(t *testing.T, addrs ...string) {
	t.Helper()
	old := localAddrs
	t.Cleanup(func() { localAddrs = old })
	localAddrs = func() []netip.Addr {
		var out []netip.Addr
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
}

func TestValidatePeerAddrs(t *testing.T) {
	eng, _ := setup(t)
	ctx := context.Background()
	if _, err := eng.Join(ctx, "10.200.0.1", "wg-test", 51820, "10.200.0.0/16", "n"); err != nil {
		t.Fatalf("Join: %v", err)
	}
	withLocalAddrs(t, "127.0.0.1", "192.168.2.20", "10.200.0.1", "10.50.0.1")

	good := []struct {
		mesh    string
		allowed []string
	}{
		{"10.200.0.8", []string{"10.200.0.8/32"}},
		{"10.200.0.8/32", []string{"10.200.0.8/32", "10.200.0.2/32", "10.60.0.4/32"}},
		{"10.200.0.8", []string{"10.200.0.8/32", "192.168.0.0/24"}}, // site LAN behind a router
		{"10.200.0.9", nil},
	}
	for _, c := range good {
		if err := eng.validatePeerAddrs(c.mesh, c.allowed); err != nil {
			t.Errorf("validatePeerAddrs(%q, %v) = %v; want ok", c.mesh, c.allowed, err)
		}
	}

	bad := []struct {
		name    string
		mesh    string
		allowed []string
	}{
		{"default route as mesh ip", "0.0.0.0/0", nil},
		{"LAN as mesh ip", "192.168.2.0/24", nil},
		{"mesh ip outside the mesh", "10.201.0.5", nil},
		{"own address", "10.200.0.1", nil},
		{"ipv6", "fd00::1", nil},
		{"whole mesh", "10.200.0.8", []string{"10.200.0.0/16"}},
		{"slice of the mesh", "10.200.0.8", []string{"10.200.1.0/24"}},
		{"default route", "10.200.0.8", []string{"0.0.0.0/0"}},
		{"too wide", "10.200.0.8", []string{"10.0.0.0/8"}},
		{"public range", "10.200.0.8", []string{"8.8.8.0/24"}},
		{"host LAN", "10.200.0.8", []string{"192.168.2.0/24"}},
		{"scope bridge", "10.200.0.8", []string{"10.50.0.0/24"}},
		{"host bits", "10.200.0.8", []string{"192.168.0.5/24"}},
		{"own mesh ip", "10.200.0.8", []string{"10.200.0.1/32"}},
		{"garbage", "10.200.0.8", []string{"-rf"}},
	}
	for _, c := range bad {
		if err := eng.validatePeerAddrs(c.mesh, c.allowed); err == nil {
			t.Errorf("%s: validatePeerAddrs(%q, %v) = nil; want an error", c.name, c.mesh, c.allowed)
		}
	}
}

func TestAddPeerRejectsRouteTakeover(t *testing.T) {
	eng, fw := setup(t)
	ctx := context.Background()
	if _, err := eng.Join(ctx, "10.200.0.1", "wg-test", 51820, "10.200.0.0/16", "n"); err != nil {
		t.Fatalf("Join: %v", err)
	}
	withLocalAddrs(t, "192.168.2.20")
	p := &peer.Peer{ID: 7, MeshIP: "10.200.0.8", PublicKey: "PUBKEY7000000000000000000000000000000000000=",
		AllowedIPs: []string{"10.200.0.0/16"}}
	err := eng.AddPeer(ctx, p, 0)
	if !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("AddPeer = %v; want ErrInvalidPeer", err)
	}
	if _, ok := fw.peers[p.PublicKey]; ok {
		t.Fatal("rejected peer reached WireGuard")
	}
	// UpdatePeer on a valid peer can't widen it either.
	p.AllowedIPs = []string{"10.200.0.8/32"}
	if err := eng.AddPeer(ctx, p, 0); err != nil {
		t.Fatalf("AddPeer valid: %v", err)
	}
	if err := eng.UpdatePeer(ctx, 7, "", []string{"0.0.0.0/0"}, 0); !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("UpdatePeer = %v; want ErrInvalidPeer", err)
	}
}

func TestReAddKeepsStatus(t *testing.T) {
	eng, _ := setup(t)
	ctx := context.Background()
	if _, err := eng.Join(ctx, "10.200.0.1", "wg-test", 51820, "10.200.0.0/16", "n"); err != nil {
		t.Fatalf("Join: %v", err)
	}
	withLocalAddrs(t)
	key := "PUBKEY8000000000000000000000000000000000000="
	if err := eng.AddPeer(ctx, &peer.Peer{ID: 8, MeshIP: "10.200.0.9", PublicKey: key}, 0); err != nil {
		t.Fatal(err)
	}
	got, _ := eng.Peers.Get(8)
	got.Status = peer.StatusConnected
	eng.Peers.Upsert(got)
	if err := eng.AddPeer(ctx, &peer.Peer{ID: 8, MeshIP: "10.200.0.9", PublicKey: key, Status: peer.StatusConnecting}, 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := eng.Peers.Get(8); got.Status != peer.StatusConnected {
		t.Fatalf("status after same-key re-add = %v; want Connected", got.Status)
	}
}
