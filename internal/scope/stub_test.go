package scope

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func mustStub(t *testing.T) *StubManager {
	t.Helper()
	return NewStub(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestStubConnectDisconnect(t *testing.T) {
	m := mustStub(t)
	ctx := context.Background()

	p, err := m.Connect(ctx, Spec{
		ScopeID:       42,
		MeshIP:        "10.200.0.42",
		VethCIDR:      "10.50.42.0/30",
		VMVethIP:      "10.50.42.1",
		ScopeVethIP:   "10.50.42.2",
		GatewayMeshIP: "10.200.0.1",
		ListenPort:    51842,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if p.ID != 42 {
		t.Errorf("ID = %d", p.ID)
	}
	if p.Netns != "scope-42" {
		t.Errorf("Netns = %q; want scope-42", p.Netns)
	}
	if p.PublicKey == "" || p.PrivateKey == "" {
		t.Error("missing keypair")
	}
	if p.VethHost != "vh-s42" || p.VethScope != "vs-s42" {
		t.Errorf("veth names: %q / %q", p.VethHost, p.VethScope)
	}

	if len(m.List()) != 1 {
		t.Errorf("list len = %d; want 1", len(m.List()))
	}

	if err := m.Disconnect(ctx, 42); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if len(m.List()) != 0 {
		t.Error("list should be empty after disconnect")
	}
}

func TestStubDoubleConnectRejected(t *testing.T) {
	m := mustStub(t)
	ctx := context.Background()
	_, err := m.Connect(ctx, Spec{ScopeID: 1, MeshIP: "10.200.0.1", ListenPort: 51801})
	if err != nil {
		t.Fatalf("first Connect: %v", err)
	}
	_, err = m.Connect(ctx, Spec{ScopeID: 1, MeshIP: "10.200.0.1", ListenPort: 51801})
	if err != ErrAlreadyConnected {
		t.Errorf("err = %v; want ErrAlreadyConnected", err)
	}
}

func TestStubDisconnectMissing(t *testing.T) {
	m := mustStub(t)
	if err := m.Disconnect(context.Background(), 99); err != ErrNotConnected {
		t.Errorf("err = %v; want ErrNotConnected", err)
	}
}

func TestStubCustomNetnsName(t *testing.T) {
	m := mustStub(t)
	p, err := m.Connect(context.Background(), Spec{
		ScopeID: 7, MeshIP: "10.200.0.7", Netns: "custom-scope", ListenPort: 51807,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if p.Netns != "custom-scope" {
		t.Errorf("Netns = %q; want custom-scope", p.Netns)
	}
}

func TestStubKeypairIsValid(t *testing.T) {
	m := mustStub(t)
	p, _ := m.Connect(context.Background(), Spec{ScopeID: 1, MeshIP: "10.200.0.1", ListenPort: 51801})
	// Keys are base64 WG keypairs — 44 chars with trailing '='.
	if len(p.PrivateKey) != 44 || len(p.PublicKey) != 44 {
		t.Errorf("key lengths: priv=%d pub=%d", len(p.PrivateKey), len(p.PublicKey))
	}
}
