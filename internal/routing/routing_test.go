package routing

import (
	"context"
	"testing"
)

func TestInMemoryRoundtrip(t *testing.T) {
	m := NewInMemory()
	ctx := context.Background()

	if err := m.Ensure(ctx, "10.200.0.5", "wg-gritiva"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := m.Ensure(ctx, "10.200.0.6", "wg-gritiva"); err != nil {
		t.Fatalf("Ensure 2: %v", err)
	}
	if err := m.Ensure(ctx, "10.200.0.5", "wg-gritiva"); err != nil {
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

func TestNew(t *testing.T) {
	m := New(nil)
	if m == nil {
		t.Fatal("nil manager")
	}
}
