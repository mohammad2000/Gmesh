package engine

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

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
	} else if got := eng.savedEndpoint(p); got != "203.0.113.5:51820" {
		t.Errorf("state would keep %q, want the direct endpoint", got)
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

	// Dial-in peers (VPN clients: no endpoint) and scopes get no standby.
	_ = eng.AddPeer(ctx, &peer.Peer{ID: 3, MeshIP: "10.200.0.3", PublicKey: relay.Key{8}.String()}, 0)
	_ = eng.AddPeer(ctx, &peer.Peer{ID: 4, MeshIP: "10.200.0.4", PublicKey: relay.Key{9}.String(), Type: peer.TypeScope, Endpoint: "10.50.0.2:51820"}, 0)
	eng.relayCheck(ctx)
	if eng.relay.peers[3] != nil || eng.relay.peers[4] != nil {
		t.Fatal("standby for a dial-in peer or a scope")
	}
	_ = eng.RemovePeer(ctx, 3)
	_ = eng.RemovePeer(ctx, 4)

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

func TestLoopbackNeverDirect(t *testing.T) {
	for ep, want := range map[string]bool{"": true, "127.0.0.1:45168": true, "[::1]:9": true, "192.168.2.40:51828": false, "[2001:db8::1]:51820": false} {
		if loopbackEP(ep) != want {
			t.Errorf("loopbackEP(%q) = %v", ep, !want)
		}
	}
	eps := []peer.Endpoint{{Address: "127.0.0.1:1", Priority: 1}, {Address: "198.51.100.7:51820", Kind: peer.EndpointKindRelay, Priority: 2}, {Address: "192.168.2.40:51828", Priority: 10}}
	if got := firstDirect(eps); got != "192.168.2.40:51828" {
		t.Errorf("firstDirect = %q", got)
	}
	rp := &relayPeer{lastDirect: "127.0.0.1:45168"}
	if got := (&Engine{}).directCandidate(&peer.Peer{Endpoints: eps}, rp); got != "192.168.2.40:51828" {
		t.Errorf("directCandidate = %q", got)
	}
}

// okWSRelay answers AUTH over a WebSocket.
func okWSRelay(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			_, b, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if typ, _, _ := relay.DecodeFrame(b); typ == relay.FrameAUTH {
				_ = c.Write(r.Context(), websocket.MessageBinary, relay.EncodeFrame(relay.FrameAUTHOK, nil))
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/v2/relay"
}

// UDP out is blocked: the standby comes up over the WebSocket, and later
// dials go there first.
func TestRelayFallsBackToWebSocket(t *testing.T) {
	eng, _ := setup(t)
	ctx := context.Background()
	res, _ := eng.Join(ctx, "10.200.0.1", "wg-test", 51820, "10.200.0.0/16", "n")
	_ = eng.AddPeer(ctx, &peer.Peer{ID: 2, MeshIP: "10.200.0.2", PublicKey: relay.Key{7}.String(), Endpoint: "203.0.113.5:51820"}, 0)
	dead, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	deadAddr := dead.LocalAddr().String()
	dead.Close() // nothing listens: like UDP that never gets an answer

	pub, _ := relay.ParseKey(res.PublicKey)
	cred := relay.IssueCredential([]byte("x"), pub, time.Now().Add(time.Hour))
	ws := okWSRelay(t)
	if err := eng.SetRelayConfig(ctx, RelayConf{Relays: []string{deadAddr + "|" + ws}, PublicKey: res.PublicKey, Expiry: cred.Expiry,
		MAC: base64.StdEncoding.EncodeToString(cred.MAC[:])}); err != nil {
		t.Fatal(err)
	}
	eng.relayCheck(ctx)
	rp := eng.relay.peers[2]
	if rp == nil || rp.sess == nil || relayDesc(rp) != ws {
		t.Fatalf("no websocket standby: %+v", rp)
	}
	if eng.relay.prefer[0] != 1 {
		t.Errorf("prefer = %d, want the websocket (1)", eng.relay.prefer[0])
	}
}

// Two relay servers: the standby links to both; one going silent is
// redialed without touching the other or the forwarder WireGuard uses.
func TestRelayTwoServers(t *testing.T) {
	eng, _ := setup(t)
	ctx := context.Background()
	res, _ := eng.Join(ctx, "10.200.0.1", "wg-test", 51820, "10.200.0.0/16", "n")
	_ = eng.AddPeer(ctx, &peer.Peer{ID: 2, MeshIP: "10.200.0.2", PublicKey: relay.Key{7}.String(), Endpoint: "203.0.113.5:51820"}, 0)
	pub, _ := relay.ParseKey(res.PublicKey)
	cred := relay.IssueCredential([]byte("x"), pub, time.Now().Add(time.Hour))
	r1, r2 := okRelay(t), okRelay(t)
	if err := eng.SetRelayConfig(ctx, RelayConf{Relays: []string{r1, r2}, PublicKey: res.PublicKey, Expiry: cred.Expiry,
		MAC: base64.StdEncoding.EncodeToString(cred.MAC[:])}); err != nil {
		t.Fatal(err)
	}
	eng.relayCheck(ctx)
	rp := eng.relay.peers[2]
	if rp == nil || rp.sess == nil || len(rp.sess.Links()) != 2 {
		t.Fatalf("want links to both relays: %+v", rp)
	}
	fwd := rp.sess.LocalEndpoint().String()
	rp.sess.DropLink(1)
	eng.relayCheck(ctx)
	if len(rp.sess.Links()) != 2 || rp.sess.LocalEndpoint().String() != fwd {
		t.Fatal("dropped link not redialed in place")
	}
	if st := eng.GetRelayStatus(ctx); !strings.Contains(st.Peers[0].Relay, r1) || !strings.Contains(st.Peers[0].Relay, r2) {
		t.Errorf("status relay %q", st.Peers[0].Relay)
	}
}

func TestRelayCoordinatedPunch(t *testing.T) {
	eng, fw := setup(t)
	ctx := context.Background()
	res, _ := eng.Join(ctx, "10.200.0.1", "wg-test", 51820, "10.200.0.0/16", "n")
	remote := relay.Key{7}.String()
	_ = eng.AddPeer(ctx, &peer.Peer{ID: 2, MeshIP: "10.200.0.2", PublicKey: remote, Endpoint: "203.0.113.5:51820"}, 0)
	pub, _ := relay.ParseKey(res.PublicKey)
	cred := relay.IssueCredential([]byte("x"), pub, time.Now().Add(time.Hour))
	_ = eng.SetRelayConfig(ctx, RelayConf{Relays: []string{okRelay(t)}, PublicKey: res.PublicKey, Expiry: cred.Expiry, MAC: base64.StdEncoding.EncodeToString(cred.MAC[:])})
	eng.relayCheck(ctx)
	rp := eng.relay.peers[2]
	fwd := rp.sess.LocalEndpoint().String()
	ep := func() string { fw.mu.Lock(); defer fw.mu.Unlock(); return fw.peers[remote].Endpoint }
	onRelay := func(rx int64) {
		fw.mu.Lock()
		fw.dumps[remote] = wireguard.PeerDump{PublicKey: remote, Endpoint: fwd, LastHandshake: time.Now(), RxBytes: rx}
		fw.mu.Unlock()
	}
	_ = eng.setEndpoint(ctx, func() *peer.Peer { p, _ := eng.Peers.Get(2); return p }(), fwd)
	onRelay(10)
	eng.relayCheck(ctx) // notices it's on the relay
	if rp.onRelaySince.IsZero() {
		t.Fatal("not on the relay")
	}

	// The peer announces its public WireGuard address and asks to punch.
	eng.relayPeerInfo(2, []byte(`{"v":1,"mapped":"198.51.100.4:41000","punch":true}`))
	eng.relayCheck(ctx)
	if ep() != "198.51.100.4:41000" || rp.tryingSince.IsZero() {
		t.Fatalf("did not punch back: endpoint %s", ep())
	}

	// That try failed (roamed back); our own next try aims at the
	// announced address rather than the stale WAN endpoint.
	onRelay(20)
	eng.relayCheck(ctx)
	rp.nextTry = time.Now().Add(-time.Second)
	eng.relayCheck(ctx)
	if ep() != "198.51.100.4:41000" {
		t.Fatalf("scheduled try went to %s", ep())
	}

	// Junk is ignored.
	eng.relayPeerInfo(2, []byte(`{"v":1,"mapped":"127.0.0.1:9"}`))
	eng.relayPeerInfo(2, []byte(`not json`))
	if rp.peerMapped.String() != "198.51.100.4:41000" {
		t.Fatalf("peerMapped overwritten: %v", rp.peerMapped)
	}
}

// Behind the same NAT the LAN path wins over the shared public address.
func TestRelaySameNATUsesLAN(t *testing.T) {
	eng, fw := setup(t)
	ctx := context.Background()
	res, _ := eng.Join(ctx, "10.200.0.1", "wg-test", 51820, "10.200.0.0/16", "n")
	remote := relay.Key{7}.String()
	_ = eng.AddPeer(ctx, &peer.Peer{ID: 2, MeshIP: "10.200.0.2", PublicKey: remote, Endpoint: "192.168.2.40:51828"}, 0)
	pub, _ := relay.ParseKey(res.PublicKey)
	cred := relay.IssueCredential([]byte("x"), pub, time.Now().Add(time.Hour))
	_ = eng.SetRelayConfig(ctx, RelayConf{Relays: []string{okRelay(t)}, PublicKey: res.PublicKey, Expiry: cred.Expiry, MAC: base64.StdEncoding.EncodeToString(cred.MAC[:])})
	eng.relayCheck(ctx)
	rp := eng.relay.peers[2]
	rp.lastDirect = "192.168.2.40:51828"
	fwd := rp.sess.LocalEndpoint().String()
	_ = eng.setEndpoint(ctx, func() *peer.Peer { p, _ := eng.Peers.Get(2); return p }(), fwd)
	fw.mu.Lock()
	fw.dumps[remote] = wireguard.PeerDump{PublicKey: remote, Endpoint: fwd, LastHandshake: time.Now(), RxBytes: 5}
	fw.mu.Unlock()
	eng.relayCheck(ctx)
	eng.relay.mapped = netip.MustParseAddrPort("70.49.231.201:52060")
	eng.relayPeerInfo(2, []byte(`{"v":1,"mapped":"70.49.231.201:51828","punch":true}`))
	eng.relayCheck(ctx)
	fw.mu.Lock()
	got := fw.peers[remote].Endpoint
	fw.mu.Unlock()
	if got != "192.168.2.40:51828" {
		t.Fatalf("punched at %s, want the LAN address", got)
	}
}

func TestIPv6CandidatesNeedLocalIPv6(t *testing.T) {
	c := []peer.Endpoint{{Address: "203.0.113.5:51820"}, {Address: "[2001:db8::5]:51820"}}
	if got := usableCandidates(c, false); len(got) != 1 || got[0].Address != "203.0.113.5:51820" {
		t.Fatalf("without IPv6: %+v", got)
	}
	if got := usableCandidates(c, true); len(got) != 2 {
		t.Fatalf("with IPv6: %+v", got)
	}
}
