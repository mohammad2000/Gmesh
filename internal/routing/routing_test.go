package routing

import (
	"context"
	"testing"
)

func TestInMemoryRoundtrip(t *testing.T) {
	m := NewInMemory()
	ctx := context.Background()

	if err := m.Ensure(ctx, "10.200.0.5", "wg-gritiva", ""); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := m.Ensure(ctx, "10.200.0.6", "wg-gritiva", ""); err != nil {
		t.Fatalf("Ensure 2: %v", err)
	}
	if err := m.Ensure(ctx, "10.200.0.5", "wg-gritiva", ""); err != nil {
		t.Fatalf("Ensure idempotent: %v", err)
	}

	list := m.List()
	if len(list) != 2 {
		t.Errorf("List len = %d; want 2", len(list))
	}

	if err := m.Remove(ctx, "10.200.0.5", "wg-gritiva"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(m.List()) != 1 {
		t.Error("Remove did not drop route")
	}

	if err := m.Remove(ctx, "10.200.0.5", "wg-gritiva"); err != nil {
		t.Errorf("Remove idempotent: %v", err)
	}
}

func TestInMemoryPurgeStale(t *testing.T) {
	m := NewInMemory()
	ctx := context.Background()
	for _, ip := range []string{"10.200.0.5", "10.200.0.6", "10.200.0.7"} {
		if err := m.Ensure(ctx, ip, "wg-gritiva", ""); err != nil {
			t.Fatalf("Ensure %s: %v", ip, err)
		}
	}
	// Also a different iface — must NOT be touched.
	if err := m.Ensure(ctx, "10.200.0.99", "wg-other", ""); err != nil {
		t.Fatalf("Ensure on other iface: %v", err)
	}

	keep := map[string]struct{}{
		"10.200.0.5": {},
		"10.200.0.7": {},
	}
	n, err := m.PurgeStale(ctx, "wg-gritiva", keep)
	if err != nil {
		t.Fatalf("PurgeStale: %v", err)
	}
	if n != 1 {
		t.Errorf("PurgeStale removed %d; want 1", n)
	}
	got := m.List()
	if len(got) != 3 {
		t.Errorf("after purge len = %d; want 3 (2 wg-gritiva + 1 wg-other)", len(got))
	}
}

func TestNew(t *testing.T) {
	m := New(nil)
	if m == nil {
		t.Fatal("nil manager")
	}
}
