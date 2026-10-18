package engine

import (
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/mohammad2000/Gmesh/internal/peer"
	"github.com/mohammad2000/Gmesh/internal/relay"
	"github.com/mohammad2000/Gmesh/internal/wireguard"
)

// okRelay answers every AUTH with AUTH_OK — enough for the engine's standby.
func okRelay(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, relay.MaxFrameSize)
		for {
			n, from, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			if typ, _, _ := relay.DecodeFrame(b[:n]); typ == relay.FrameAUTH {
				_, _ = c.WriteToUDP(relay.EncodeFrame(relay.FrameAUTHOK, nil), from)
			}
		}
	}()
	return c.LocalAddr().String()
}

func TestRelayFallbackAndReturn(t *testing.T) {
	eng, fw := setup(t)
	ctx := context.Background()
	res, err := eng.Join(ctx, "10.200.0.1", "wg-test", 51820, "10.200.0.0/16", "n")
	if err != nil {
		t.Fatal(err)
	}
	remote := relay.Key{7}.String()
	if err := eng.AddPeer(ctx, &peer.Peer{ID: 2, MeshIP: "10.200.0.2", PublicKey: remote, Endpoint: "203.0.113.5:51820"}, 0); err != nil {
		t.Fatal(err)
	}

	secret := []byte("relay-secret")
	pub, _ := relay.ParseKey(res.PublicKey)
	cred := relay.IssueCredential(secret, pub, time.Now().Add(time.Hour))
	conf := RelayConf{Relays: []string{okRelay(t)}, PublicKey: res.PublicKey, Expiry: cred.Expiry, MAC: base64.StdEncoding.EncodeToString(cred.MAC[:])}

	// A credential for another key is refused.
	bad := conf
	bad.PublicKey = relay.Key{1}.String()
	if err := eng.SetRelayConfig(ctx, bad); err == nil {
		t.Fatal("credential for another key accepted")
	}
	if err := eng.SetRelayConfig(ctx, conf); err != nil {
		t.Fatal(err)
	}
	eng.relayCheck(ctx)
	rp := eng.relay.peers[2]
	if rp == nil || rp.sess == nil {
		t.Fatalf("no standby session: %+v", rp)
	}
	fwd := rp.sess.LocalEndpoint().String()
	ep := func() string { fw.mu.Lock(); defer fw.mu.Unlock(); return fw.peers[remote].Endpoint }

	// Young peer without a handshake: left alone.
	eng.relayCheck(ctx)
	if ep() == fwd {
		t.Fatal("moved to the relay before the new-peer grace")
	}
	// Grace over, still no handshake → relay.
	rp.seen = time.Now().Add(-time.Minute)
	eng.relayCheck(ctx)
	if ep() != fwd {
		t.Fatalf("not on the relay: %s", ep())
	}
	if p, _ := eng.Peers.Get(2); p.Method != methodRelay {
		t.Errorf("method %d, want relay", p.Method)
	}

	// Traffic flows over the relay (WG reports the forwarder as endpoint).
	setDump := func(endpoint string, rx int64) {
		fw.mu.Lock()
		fw.dumps[remote] = wireguard.PeerDump{PublicKey: remote, Endpoint: endpoint, LastHandshake: time.Now(), RxBytes: rx}
		fw.mu.Unlock()
	}
	setDump(fwd, 100)
	rp.nextTry = time.Now().Add(-time.Second)
	eng.relayCheck(ctx)
	if ep() != "203.0.113.5:51820" {
		t.Fatalf("direct path not retried: %s", ep())
	}

	// The try fails: the peer's relayed packet roams WG back.
	setDump(fwd, 150)
	eng.relayCheck(ctx)
	if !rp.tryingSince.IsZero() || rp.onRelaySince.IsZero() {
		t.Fatal("failed try not noticed")
	}

	// Next try succeeds: WG stays direct and receives there.
	rp.nextTry = time.Now().Add(-time.Second)
	eng.relayCheck(ctx)
	setDump("203.0.113.5:51820", 400)
	rp.tryingSince = time.Now().Add(-time.Minute)
	eng.relayCheck(ctx)
	if !rp.onRelaySince.IsZero() {
		t.Fatal("still marked as relayed after the direct path worked")
	}
	if p, _ := eng.Peers.Get(2); p.Method != methodDirect {
		t.Errorf("method %d, want direct", p.Method)
	}

	st := eng.GetRelayStatus(ctx)
	if !st.Configured || len(st.Peers) != 1 || !st.Peers[0].Standby || st.Peers[0].OnRelay {
		t.Fatalf("status %+v", st)
	}

	// Removing the peer closes its standby.
	if err := eng.RemovePeer(ctx, 2); err != nil {
		t.Fatal(err)
	}
	eng.relayCheck(ctx)
	if len(eng.relay.peers) != 0 {
		t.Fatal("standby kept after the peer left")
	}
}
