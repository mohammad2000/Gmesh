package circuit

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		c       Circuit
		wantErr bool
	}{
		{"empty name", Circuit{Source: 1, Hops: []int64{2}}, true},
		{"no source", Circuit{Name: "x", Hops: []int64{2}}, true},
		{"no hops", Circuit{Name: "x", Source: 1}, true},
		{"zero hop", Circuit{Name: "x", Source: 1, Hops: []int64{0, 2}}, true},
		{"source in hops", Circuit{Name: "x", Source: 1, Hops: []int64{1, 2}}, true},
		{"dup hops", Circuit{Name: "x", Source: 1, Hops: []int64{2, 2}}, true},
		{"bad cidr", Circuit{Name: "x", Source: 1, Hops: []int64{2}, DestCIDR: "oops"}, true},
		{"bad priority", Circuit{Name: "x", Source: 1, Hops: []int64{2}, Priority: 5000}, true},
		{"bad protocol", Circuit{Name: "x", Source: 1, Hops: []int64{2}, Protocol: "icmp"}, true},
		{"ok minimal", Circuit{Name: "x", Source: 1, Hops: []int64{2}}, false},
		{"ok long chain", Circuit{Name: "x", Source: 1, Hops: []int64{2, 3, 4}, Protocol: "tcp", DestPorts: "443"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.c.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v want=%v", err, c.wantErr)
			}
		})
	}
}

func TestRoleAssignment(t *testing.T) {
	c := Circuit{Source: 1, Hops: []int64{2, 3, 4}}
	cases := []struct {
		peer int64
		want Role
	}{
		{1, RoleSource},
		{2, RoleTransit},
		{3, RoleTransit},
		{4, RoleExit},
		{99, RoleNone},
	}
	for _, cc := range cases {
		if got := c.RoleFor(cc.peer); got != cc.want {
			t.Errorf("peer=%d got=%s want=%s", cc.peer, got, cc.want)
		}
	}
}

func TestNextHopPrevHop(t *testing.T) {
	c := Circuit{Source: 1, Hops: []int64{2, 3, 4}}
	if got := c.NextHop(1); got != 2 {
		t.Errorf("source next = %d; want 2", got)
	}
	if got := c.NextHop(2); got != 3 {
		t.Errorf("hop[0] next = %d; want 3", got)
	}
	if got := c.NextHop(3); got != 4 {
		t.Errorf("hop[1] next = %d; want 4", got)
	}
	if got := c.NextHop(4); got != 0 {
		t.Errorf("exit next = %d; want 0", got)
	}
	if got := c.PrevHop(2); got != 1 {
		t.Errorf("hop[0] prev = %d; want 1 (source)", got)
	}
	if got := c.PrevHop(3); got != 2 {
		t.Errorf("hop[1] prev = %d; want 2", got)
	}
	if got := c.PrevHop(4); got != 3 {
		t.Errorf("exit prev = %d; want 3", got)
	}
}

func TestSingleHopCircuit(t *testing.T) {
	c := Circuit{Name: "single", Source: 1, Hops: []int64{2}}
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.RoleFor(2) != RoleExit {
		t.Error("single-hop: hops[0] should be exit")
	}
	if c.NextHop(1) != 2 {
		t.Error("source→hops[0]")
	}
	if c.NextHop(2) != 0 {
		t.Error("exit has no next hop")
	}
}

func TestStubCRUD(t *testing.T) {
	m := NewStub(silent())
	ctx := context.Background()
	c := &Circuit{ID: 1, Name: "demo", Source: 1, Hops: []int64{2, 3}}
	if _, err := m.Create(ctx, c, "10.250.0.2", "wg-gmesh", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(ctx, c, "10.250.0.2", "wg-gmesh", 1); err != ErrExists {
		t.Errorf("dup → %v; want ErrExists", err)
	}
	if len(m.List()) != 1 {
		t.Error("list len")
	}
	c2 := &Circuit{ID: 1, Name: "demo-v2", Source: 1, Hops: []int64{2, 3, 4}}
	if _, err := m.Update(ctx, c2, "", "wg-gmesh", 1); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if len(m.List()) != 0 {
		t.Error("list after delete")
	}
}

func TestFwMarkDisjointFromEgress(t *testing.T) {
	// egress uses 0x1_______ ; circuit must use 0x2_______ so marks
	// never collide.
	if FwMark(1)&0xF0000000 != 0x20000000 {
		t.Errorf("FwMark(1) = 0x%x; expected 0x2_______", FwMark(1))
	}
}

func TestTableIDDisjointFromEgress(t *testing.T) {
	if tid := TableID(1); tid < 1000 || tid >= 2000 {
		t.Errorf("TableID(1) = %d; expected 1000..1999", tid)
	}
}

func TestFormatHops(t *testing.T) {
	if got := FormatHops(1, []int64{2, 3, 4}); got != "1→2→3→4" {
		t.Errorf("format = %q", got)
	}
}
