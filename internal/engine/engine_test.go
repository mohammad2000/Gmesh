package engine

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/mohammad2000/Gmesh/internal/config"
	"github.com/mohammad2000/Gmesh/internal/peer"
	"github.com/mohammad2000/Gmesh/internal/state"
	"github.com/mohammad2000/Gmesh/internal/wireguard"
)

// fakeWG is an in-memory stand-in for wireguard.Manager.
type fakeWG struct {
	mu       sync.Mutex
	iface    string
	privKey  string
	peers    map[string]wireguard.PeerConfig
	dumps    map[string]wireguard.PeerDump
	addr     string
	port     uint16
	mtu      int
	deleted  bool
	interfErr error
}

func newFakeWG() *fakeWG { return &fakeWG{peers: map[string]wireguard.PeerConfig{}, dumps: map[string]wireguard.PeerDump{}} }

func (f *fakeWG) Backend() wireguard.Backend { return wireguard.BackendKernel }
func (f *fakeWG) Close() error               { return nil }

func (f *fakeWG) CreateInterface(_ context.Context, name, addr string, mtu int, port uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.interfErr != nil {
		return f.interfErr
	}
	f.iface = name
	f.addr = addr
	f.mtu = mtu
	f.port = port
	f.deleted = false
	return nil
}
func (f *fakeWG) DeleteInterface(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.iface == name {
		f.deleted = true
	}
	return nil
}
func (f *fakeWG) SetPrivateKey(_ context.Context, _, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.privKey = key
	return nil
}
func (f *fakeWG) AddPeer(_ context.Context, _ string, p wireguard.PeerConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers[p.PublicKey] = p
	return nil
}
func (f *fakeWG) RemovePeer(_ context.Context, _, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.peers, key)
	return nil
}
func (f *fakeWG) ListPeers(_ context.Context, _ string) ([]wireguard.PeerDump, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]wireguard.PeerDump, 0, len(f.peers))
	for k := range f.peers {
		if d, ok := f.dumps[k]; ok {
			out = append(out, d)
		} else {
			out = append(out, wireguard.PeerDump{PublicKey: k})
		}
	}
	return out, nil
}

// setup builds an Engine wired to a fakeWG and a temp Store.
func setup(t *testing.T) (*Engine, *fakeWG) {
	t.Helper()
	cfg := config.Default()
	cfg.State.Dir = t.TempDir()
	cfg.State.File = "state.json"

	s, err := state.NewStore(cfg.State.Dir, cfg.State.File)
	if err != nil {
		t.Fatalf("state.NewStore: %v", err)
	}
	fw := newFakeWG()
	eng, err := New(cfg, Options{
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		WG:    fw,
		Store: s,
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng, fw
}

func TestJoinLeaveRoundtrip(t *testing.T) {
	eng, fw := setup(t)
	ctx := context.Background()

	if eng.IsJoined() {
		t.Fatal("engine is joined before Join")
	}

	res, err := eng.Join(ctx, "10.200.0.7", "wg-test", 51820, "10.200.0.0/16", "node-abc")
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if res.PublicKey == "" || res.PrivateKey == "" {
		t.Fatal("empty keys from Join")
	}
	if !eng.IsJoined() {
		t.Fatal("not joined after Join")
	}
	if fw.addr != "10.200.0.7/16" {
		t.Errorf("CreateInterface addr = %q; want 10.200.0.7/16", fw.addr)
	}
	if fw.privKey != res.PrivateKey {
		t.Errorf("SetPrivateKey mismatch")
	}

	// Second Join should fail.
	if _, err := eng.Join(ctx, "10.200.0.7", "wg-test", 51820, "10.200.0.0/16", ""); err != ErrAlreadyJoined {
		t.Errorf("second Join err = %v; want ErrAlreadyJoined", err)
	}

	if err := eng.Leave(ctx, "test"); err != nil {
		t.Fatalf("Leave: %v", err)
	}
	if eng.IsJoined() {
		t.Error("still joined after Leave")
	}
	if !fw.deleted {
		t.Error("interface not deleted on Leave")
	}
}

func TestAddRemoveUpdatePeer(t *testing.T) {
	eng, fw := setup(t)
	ctx := context.Background()

	if _, err := eng.Join(ctx, "10.200.0.1", "wg-test", 51820, "10.200.0.0/16", "n"); err != nil {
		t.Fatalf("Join: %v", err)
	}

	p := &peer.Peer{
		ID:         42,
		Type:       peer.TypeVM,
		MeshIP:     "10.200.0.8",
		PublicKey:  "PUBKEY0000000000000000000000000000000000000=",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.200.0.8/32"},
	}
	if err := eng.AddPeer(ctx, p, 0); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if _, ok := fw.peers[p.PublicKey]; !ok {
		t.Error("fake WG missing peer after AddPeer")
	}
	if _, ok := eng.Peers.Get(42); !ok {
		t.Error("registry missing peer after AddPeer")
	}

	// Update endpoint.
	if err := eng.UpdatePeer(ctx, 42, "5.6.7.8:9999", []string{"10.200.0.8/32", "10.50.1.0/24"}, 30*time.Second); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	got, _ := eng.Peers.Get(42)
	if got.Endpoint != "5.6.7.8:9999" {
		t.Errorf("peer endpoint = %q; want 5.6.7.8:9999", got.Endpoint)
	}
	if len(got.AllowedIPs) != 2 {
		t.Errorf("peer allowed_ips len = %d; want 2", len(got.AllowedIPs))
	}

	// Remove.
	if err := eng.RemovePeer(ctx, 42); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if _, ok := fw.peers[p.PublicKey]; ok {
		t.Error("fake WG still has peer after RemovePeer")
	}
	if _, ok := eng.Peers.Get(42); ok {
		t.Error("registry still has peer after RemovePeer")
	}

	if err := eng.RemovePeer(ctx, 999); err != ErrPeerNotFound {
		t.Errorf("RemovePeer(missing) err = %v; want ErrPeerNotFound", err)
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	cfg := config.Default()
	cfg.State.Dir = t.TempDir()
	cfg.State.File = "state.json"
	s, err := state.NewStore(cfg.State.Dir, cfg.State.File)
	if err != nil {
		t.Fatalf("state.NewStore: %v", err)
	}
	fw := newFakeWG()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	eng1, err := New(cfg, Options{Log: log, WG: fw, Store: s})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	ctx := context.Background()
	if _, err := eng1.Join(ctx, "10.200.0.1", "wg-test", 51820, "10.200.0.0/16", "nodeX"); err != nil {
		t.Fatalf("Join: %v", err)
	}
	if err := eng1.AddPeer(ctx, &peer.Peer{ID: 7, Type: peer.TypeVM, MeshIP: "10.200.0.7", PublicKey: "K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K7K=", Endpoint: "1.1.1.1:51820", AllowedIPs: []string{"10.200.0.7/32"}}, 0); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	// Restart: new engine with same store + new fake WG (state should rehydrate the peer).
	fw2 := newFakeWG()
	eng2, err := New(cfg, Options{Log: log, WG: fw2, Store: s})
	if err != nil {
		t.Fatalf("engine.New restart: %v", err)
	}
	if !eng2.IsJoined() {
		t.Fatal("restart: engine not joined from state")
	}
	if eng2.MeshIP() != "10.200.0.1" {
		t.Errorf("restart MeshIP = %q; want 10.200.0.1", eng2.MeshIP())
	}
	if eng2.Peers.Count() != 1 {
		t.Errorf("restart Peers.Count() = %d; want 1", eng2.Peers.Count())
	}
	if _, ok := eng2.Peers.Get(7); !ok {
		t.Error("restart: peer 7 missing")
	}
}
