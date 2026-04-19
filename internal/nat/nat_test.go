package nat

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTypeString(t *testing.T) {
	cases := map[Type]string{
		Open:               "open",
		FullCone:           "full_cone",
		RestrictedCone:     "restricted_cone",
		PortRestrictedCone: "port_restricted_cone",
		Symmetric:          "symmetric",
		Unknown:            "unknown",
	}
	for v, want := range cases {
		if got := v.String(); got != want {
			t.Errorf("%d.String() = %q; want %q", int(v), got, want)
		}
	}
}

func TestSupportsHolePunch(t *testing.T) {
	if !PortRestrictedCone.SupportsHolePunch() {
		t.Error("PortRestrictedCone should support hole-punch")
	}
	if Symmetric.SupportsHolePunch() {
		t.Error("Symmetric should NOT support hole-punch")
	}
	if !Symmetric.IsSymmetric() {
		t.Error("Symmetric.IsSymmetric should be true")
	}
}

func TestClassify(t *testing.T) {
	a := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}

	t.Run("cone — stable port", func(t *testing.T) {
		b := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}
		info := classify(a, b)
		if info.Type != PortRestrictedCone {
			t.Errorf("type = %v; want PortRestrictedCone", info.Type)
		}
		if !info.SupportsHolePunch {
			t.Error("SupportsHolePunch should be true")
		}
		if info.ExternalIP != "1.2.3.4" || info.ExternalPort != 5000 {
			t.Errorf("external mismatch: %s:%d", info.ExternalIP, info.ExternalPort)
		}
	})

	t.Run("symmetric — port varies", func(t *testing.T) {
		b := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5001}
		info := classify(a, b)
		if info.Type != Symmetric {
			t.Errorf("type = %v; want Symmetric", info.Type)
		}
		if info.SupportsHolePunch {
			t.Error("SupportsHolePunch should be false for symmetric")
		}
	})

	t.Run("symmetric — IP varies", func(t *testing.T) {
		b := &net.UDPAddr{IP: net.ParseIP("9.8.7.6"), Port: 5000}
		info := classify(a, b)
		if info.Type != Symmetric {
			t.Errorf("type = %v; want Symmetric", info.Type)
		}
	})

	t.Run("nil input", func(t *testing.T) {
		if info := classify(nil, a); info.Type != Unknown {
			t.Errorf("nil → type = %v; want Unknown", info.Type)
		}
	})
}

// fakeProbe returns pre-canned responses keyed by STUN server name.
type fakeProbe struct {
	responses map[string]*net.UDPAddr
	err       error
}

func (f *fakeProbe) QueryAll(_ context.Context, servers []string) ([]*net.UDPAddr, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([]*net.UDPAddr, len(servers))
	for i, s := range servers {
		out[i] = f.responses[s]
	}
	return out, nil
}

func TestDiscovererCaching(t *testing.T) {
	d := NewDiscoverer([]string{"stun-a:3478", "stun-b:3478"}, time.Second, 5*time.Second)
	d.Probe = &fakeProbe{responses: map[string]*net.UDPAddr{
		"stun-a:3478": {IP: net.ParseIP("1.2.3.4"), Port: 5000},
		"stun-b:3478": {IP: net.ParseIP("1.2.3.4"), Port: 5000},
	}}

	info1, err := d.Discover(context.Background(), false)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if info1.Type != PortRestrictedCone {
		t.Errorf("Type = %v; want PortRestrictedCone", info1.Type)
	}

	// Second call should hit cache.
	d.Probe = &fakeProbe{} // empty — would fail if called
	info2, err := d.Discover(context.Background(), false)
	if err != nil {
		t.Fatalf("Discover (cached): %v", err)
	}
	if info2.ExternalIP != info1.ExternalIP {
		t.Errorf("cache mismatch")
	}

	// Force refresh with working probe again.
	d.Probe = &fakeProbe{responses: map[string]*net.UDPAddr{
		"stun-a:3478": {IP: net.ParseIP("5.6.7.8"), Port: 9000},
		"stun-b:3478": {IP: net.ParseIP("5.6.7.8"), Port: 9000},
	}}
	info3, err := d.Discover(context.Background(), true)
	if err != nil {
		t.Fatalf("Discover (force): %v", err)
	}
	if info3.ExternalIP != "5.6.7.8" {
		t.Errorf("force refresh didn't take: %s", info3.ExternalIP)
	}
}

func TestDiscovererNeedsTwoServers(t *testing.T) {
	d := NewDiscoverer([]string{"only-one:3478"}, time.Second, time.Second)
	if _, err := d.Discover(context.Background(), false); err == nil {
		t.Error("expected error for single-server config")
	}
}

func TestResponderEcho(t *testing.T) {
	// Bind to an ephemeral port by asking the kernel.
	// The Responder struct takes a fixed port, so we work around for the test:
	// use port 0 via direct listen, then probe.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec
	_ = conn.Close()

	r := NewResponder(port, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()

	// Send probe.
	probe, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer probe.Close()

	payload := []byte{MagicByte, 0x01, 0x02, 0x03}
	if _, err := probe.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	_ = probe.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := probe.Read(buf)
	if err != nil {
		t.Fatalf("Read echo: %v", err)
	}
	if n != len(payload) || buf[0] != MagicByte {
		t.Errorf("echo mismatch: got %v", buf[:n])
	}
	if r.EchoCount() != 1 {
		t.Errorf("EchoCount = %d; want 1", r.EchoCount())
	}

	// Non-magic packet should be dropped.
	if _, err := probe.Write([]byte{0xAB, 0xCD}); err != nil {
		t.Fatalf("Write junk: %v", err)
	}
	_ = probe.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := probe.Read(buf); err == nil {
		t.Errorf("expected no reply to non-magic packet; got %d bytes", n)
	}
}
