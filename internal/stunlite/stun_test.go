package stunlite

import (
	"net/netip"
	"testing"

	"github.com/pion/stun/v2"
)

func TestRoundtrip(t *testing.T) {
	for _, a := range []string{"70.49.231.201:51828", "[2001:db8::7]:4500"} {
		addr := netip.MustParseAddrPort(a)
		tx := NewTxID()
		got, ok := ParseRequest(Request(tx))
		if !ok || got != tx {
			t.Fatal("request")
		}
		m, ok := ParseResponse(Response(tx, addr), tx)
		if !ok || m != addr {
			t.Fatalf("%s → %v %v", a, m, ok)
		}
		if _, ok := ParseResponse(Response(tx, addr), NewTxID()); ok {
			t.Fatal("accepted another transaction")
		}
	}
}

// Interop with a full STUN implementation (pion), both ways.
func TestPionInterop(t *testing.T) {
	addr := netip.MustParseAddrPort("203.0.113.9:40000")
	tx := NewTxID()
	m := &stun.Message{Raw: Response(tx, addr)}
	if err := m.Decode(); err != nil {
		t.Fatal(err)
	}
	var x stun.XORMappedAddress
	if err := x.GetFrom(m); err != nil || x.Port != 40000 || x.IP.String() != "203.0.113.9" {
		t.Fatalf("pion read %v %v", x, err)
	}
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, ok := ParseRequest(req.Raw); !ok {
		t.Fatal("pion request not recognised")
	}
	if _, ok := ParseRequest([]byte{0x04, 1, 2, 3}); ok {
		t.Fatal("relay frame taken for STUN")
	}
}
