package peer

import "testing"

func TestRegistryUpsertGetRemove(t *testing.T) {
	r := NewRegistry()
	if r.Count() != 0 {
		t.Fatalf("new registry count = %d; want 0", r.Count())
	}

	p := &Peer{ID: 1, MeshIP: "10.200.0.5", PublicKey: "xx=", Type: TypeVM}
	r.Upsert(p)
	if r.Count() != 1 {
		t.Errorf("Count after upsert = %d; want 1", r.Count())
	}
	got, ok := r.Get(1)
	if !ok {
		t.Fatal("Get(1) missing")
	}
	if got.MeshIP != p.MeshIP {
		t.Errorf("MeshIP = %q; want %q", got.MeshIP, p.MeshIP)
	}

	// Upsert updates in place.
	p2 := &Peer{ID: 1, MeshIP: "10.200.0.6", PublicKey: "yy=", Type: TypeScope}
	r.Upsert(p2)
	if r.Count() != 1 {
		t.Errorf("Count after re-upsert = %d; want 1", r.Count())
	}
	got, _ = r.Get(1)
	if got.MeshIP != "10.200.0.6" {
		t.Errorf("MeshIP after update = %q; want 10.200.0.6", got.MeshIP)
	}

	old := r.Remove(1)
	if old == nil {
		t.Fatal("Remove returned nil for existing peer")
	}
	if _, ok := r.Get(1); ok {
		t.Errorf("peer still present after remove")
	}
	if r.Count() != 0 {
		t.Errorf("Count after remove = %d; want 0", r.Count())
	}
}

func TestRegistrySnapshotIsIndependent(t *testing.T) {
	r := NewRegistry()
	r.Upsert(&Peer{ID: 1})
	r.Upsert(&Peer{ID: 2})
	r.Upsert(&Peer{ID: 3})

	s1 := r.Snapshot()
	if len(s1) != 3 {
		t.Fatalf("snapshot len = %d; want 3", len(s1))
	}

	// Mutating registry after snapshot should not alter snapshot length.
	r.Remove(2)
	if len(s1) != 3 {
		t.Errorf("snapshot changed after remove: len = %d", len(s1))
	}
	if r.Count() != 2 {
		t.Errorf("Count = %d; want 2", r.Count())
	}
}
