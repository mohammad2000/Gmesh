package ingress

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

	p := &Profile{
		ID: 1, Name: "admin-panel", Enabled: true,
		BackendPeerID: 2, BackendIP: "10.250.0.10", BackendPort: 8000,
		EdgePeerID: 3, EdgePort: 80, Protocol: "tcp",
	}
	res, err := m.Create(ctx, p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if res.ID != 1 || res.CreatedAt.IsZero() {
		t.Errorf("bad create result: %+v", res)
	}

	if _, err := m.Create(ctx, p); err != ErrExists {
		t.Errorf("duplicate Create → %v; want ErrExists", err)
	}

	if got := m.List(); len(got) != 1 {
		t.Errorf("list len = %d; want 1", len(got))
	}

	if err := m.Delete(ctx, 1); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := m.Delete(ctx, 1); err != nil {
		t.Errorf("Delete idempotent: %v", err)
	}
	if len(m.List()) != 0 {
		t.Error("list not empty after delete")
	}
}

func TestStubUpdate(t *testing.T) {
	m := NewStub(silent())
	ctx := context.Background()
	base := &Profile{ID: 1, Name: "a", Enabled: true,
		BackendIP: "10.0.0.1", BackendPort: 80, EdgePort: 8080, Protocol: "tcp"}
	if _, err := m.Create(ctx, base); err != nil {
		t.Fatalf("Create: %v", err)
	}
	upd := &Profile{ID: 1, Name: "a-renamed", Enabled: true,
		BackendIP: "10.0.0.2", BackendPort: 443, EdgePort: 8080, Protocol: "tcp"}
	got, err := m.Update(ctx, upd)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got.Name != "a-renamed" || got.BackendIP != "10.0.0.2" {
		t.Errorf("update didn't take: %+v", got)
	}
	if _, err := m.Update(ctx, &Profile{ID: 99, Name: "x", BackendIP: "1", BackendPort: 1, EdgePort: 1}); err != ErrNotFound {
		t.Errorf("Update(missing) → %v; want ErrNotFound", err)
	}
}

func TestProfileValidate(t *testing.T) {
	cases := []struct {
		name    string
		p       Profile
		wantErr bool
	}{
		{"missing name", Profile{BackendIP: "1", BackendPort: 1, EdgePort: 1}, true},
		{"missing backend ip", Profile{Name: "x", BackendPort: 1, EdgePort: 1}, true},
		{"missing backend port", Profile{Name: "x", BackendIP: "1", EdgePort: 1}, true},
		{"missing edge port", Profile{Name: "x", BackendIP: "1", BackendPort: 1}, true},
		{"bad protocol", Profile{Name: "x", BackendIP: "1", BackendPort: 1, EdgePort: 1, Protocol: "sctp"}, true},
		{"default protocol", Profile{Name: "x", BackendIP: "1", BackendPort: 1, EdgePort: 1}, false},
		{"udp ok", Profile{Name: "x", BackendIP: "1", BackendPort: 1, EdgePort: 1, Protocol: "udp"}, false},
		{"mtls reserved", Profile{Name: "x", BackendIP: "1", BackendPort: 1, EdgePort: 1, RequireMTLS: true}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.p.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestValidateNormalisesProtocol(t *testing.T) {
	p := Profile{Name: "x", BackendIP: "1", BackendPort: 1, EdgePort: 1, Protocol: "TCP"}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if p.Protocol != "tcp" {
		t.Errorf("protocol = %q; want lowercase tcp", p.Protocol)
	}
}
