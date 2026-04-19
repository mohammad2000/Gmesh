package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreLoadMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, "state.json")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.Version == 0 {
		t.Errorf("Version = 0; want non-zero")
	}
	if len(st.Peers) != 0 {
		t.Errorf("Peers len = %d; want 0", len(st.Peers))
	}
}

func TestStoreSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, "state.json")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	in := &State{
		Node: NodeState{
			MeshIP:     "10.200.0.7",
			Interface:  "wg-gritiva",
			ListenPort: 51820,
			PrivateKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
			PublicKey:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=",
			NodeID:     "node-abc12345",
			Joined:     true,
		},
		Peers: []PeerEntry{
			{ID: 1, Type: "vm", MeshIP: "10.200.0.8", PublicKey: "peerkey=", Endpoint: "1.2.3.4:51820", AllowedIPs: []string{"10.200.0.8/32"}},
			{ID: 2, Type: "scope", MeshIP: "10.200.0.9", PublicKey: "scopekey=", Endpoint: "5.6.7.8:51820", ScopeID: 42, AllowedIPs: []string{"10.200.0.9/32"}},
		},
	}
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// File should exist with mode 0600.
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("file mode = %o; want 0600", mode)
	}

	out, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.Node.MeshIP != in.Node.MeshIP {
		t.Errorf("Node.MeshIP = %q; want %q", out.Node.MeshIP, in.Node.MeshIP)
	}
	if len(out.Peers) != 2 {
		t.Fatalf("Peers len = %d; want 2", len(out.Peers))
	}
	if out.Peers[1].ScopeID != 42 {
		t.Errorf("Peers[1].ScopeID = %d; want 42", out.Peers[1].ScopeID)
	}
	if out.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero")
	}
}

func TestStoreSaveAtomicity(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, "state.json")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Save twice; make sure no .tmp files linger.
	for i := 0; i < 3; i++ {
		if err := s.Save(&State{Node: NodeState{NodeID: "x"}}); err != nil {
			t.Fatalf("Save[%d]: %v", i, err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("stray temp file: %s", e.Name())
		}
	}
}
