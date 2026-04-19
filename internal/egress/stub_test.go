package egress

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestStubCreateListDelete(t *testing.T) {
	m := NewStub(silent())
	ctx := context.Background()

	p := &Profile{ID: 1, Name: "p1", Enabled: true, Priority: 100,
		SourceScopeID: 42, ExitPeerID: 7, Protocol: "tcp", DestPorts: "443"}
	res, err := m.Create(ctx, p, "10.200.0.7", "wg-gmesh")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if res.ID != 1 {
		t.Errorf("ID = %d", res.ID)
	}
	if res.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}

	got := m.List()
	if len(got) != 1 {
		t.Fatalf("list len = %d", len(got))
	}

	// Duplicate Create → ErrExists.
	if _, err := m.Create(ctx, p, "10.200.0.7", "wg-gmesh"); err != ErrExists {
		t.Errorf("second Create err = %v; want ErrExists", err)
	}

	if err := m.Delete(ctx, 1); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(m.List()) != 0 {
		t.Error("Delete didn't remove profile")
	}
	if err := m.Delete(ctx, 1); err != nil {
		t.Errorf("Delete idempotent: %v", err)
	}
}

func TestStubUpdate(t *testing.T) {
	m := NewStub(silent())
	ctx := context.Background()
	_, _ = m.Create(ctx, &Profile{ID: 1, Name: "a", ExitPeerID: 5},
		"10.200.0.5", "wg-gmesh")

	upd, err := m.Update(ctx, &Profile{ID: 1, Name: "b", ExitPeerID: 5},
		"10.200.0.5", "wg-gmesh")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if upd.Name != "b" {
		t.Errorf("Name = %q; want b", upd.Name)
	}
	if upd.CreatedAt.IsZero() || upd.UpdatedAt.IsZero() {
		t.Error("timestamps missing")
	}
	if upd.UpdatedAt.Before(upd.CreatedAt) {
		t.Error("UpdatedAt predates CreatedAt")
	}

	if _, err := m.Update(ctx, &Profile{ID: 99, Name: "x", ExitPeerID: 1},
		"10.200.0.1", "wg-gmesh"); err != ErrNotFound {
		t.Errorf("Update(missing) err = %v; want ErrNotFound", err)
	}
}

func TestProfileValidate(t *testing.T) {
	cases := []struct {
		name    string
		p       Profile
		wantErr bool
	}{
		{"empty name", Profile{ExitPeerID: 1}, true},
		{"no exit", Profile{Name: "x"}, true},
		{"bad priority", Profile{Name: "x", ExitPeerID: 1, Priority: 2000}, true},
		{"bad protocol", Profile{Name: "x", ExitPeerID: 1, Protocol: "sctp"}, true},
		{"ok tcp", Profile{Name: "x", ExitPeerID: 1, Protocol: "tcp"}, false},
		{"ok any", Profile{Name: "x", ExitPeerID: 1, Protocol: "any"}, false},
		{"ok pool", Profile{Name: "x", ExitPool: []int64{1, 2}, ExitWeights: []int32{50, 50}}, false},
		{"pool weights mismatch", Profile{Name: "x", ExitPool: []int64{1, 2}, ExitWeights: []int32{50}}, true},
		{"pool zero weights", Profile{Name: "x", ExitPool: []int64{1, 2}, ExitWeights: []int32{0, 0}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.p.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("Validate = %v; wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestTableID(t *testing.T) {
	if TableID(1) != 101 {
		t.Errorf("TableID(1) = %d", TableID(1))
	}
	if TableID(999) != 1099 {
		t.Errorf("TableID(999) = %d", TableID(999))
	}
	// Wraps at 1000 to avoid exceeding reserved range.
	if TableID(1000) != 100 {
		t.Errorf("TableID(1000) = %d; want 100", TableID(1000))
	}
}

func TestFwMark(t *testing.T) {
	m := FwMark(42)
	if m&0xF0000000 != 0x10000000 {
		t.Errorf("FwMark(42) = 0x%x; top nibble should be 0x1", m)
	}
	if m&0x0FFFFFFF != 42 {
		t.Errorf("FwMark(42) low bits = %d; want 42", m&0x0FFFFFFF)
	}
}

func TestRulePriority(t *testing.T) {
	if RulePriority(0) != 20000 {
		t.Errorf("RulePriority(0) = %d", RulePriority(0))
	}
	if RulePriority(500) != 20500 {
		t.Errorf("RulePriority(500) = %d", RulePriority(500))
	}
}

func TestProfileSource(t *testing.T) {
	if (&Profile{SourceScopeID: 7}).Source() != "scope:7" {
		t.Error("scope source label")
	}
	if (&Profile{SourceCIDR: "10.50.0.0/24"}).Source() != "cidr:10.50.0.0/24" {
		t.Error("cidr source label")
	}
	if (&Profile{}).Source() != "any" {
		t.Error("empty source label")
	}
}

func TestStubExitRoundtrip(t *testing.T) {
	m := NewStubExit(silent())
	ctx := context.Background()
	if m.IsEnabled() {
		t.Error("should start disabled")
	}
	if err := m.Enable(ctx, "wg-gmesh", []int64{1, 2}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !m.IsEnabled() {
		t.Error("enable didn't flip state")
	}
	if err := m.Disable(ctx); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := m.Disable(ctx); err != nil {
		t.Errorf("Disable idempotent: %v", err)
	}
	if m.IsEnabled() {
		t.Error("still enabled after Disable")
	}
}
