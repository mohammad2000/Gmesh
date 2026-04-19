package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// startRelayHub emulates the GritivaCore backend's /ws/relay/{session}/{peer}
// handler: pairs clients by session_id, forwards {type:"relay_data"} frames.
func startRelayHub(t *testing.T) *httptest.Server {
	t.Helper()

	var mu sync.Mutex
	sessions := map[string][]*websocket.Conn{} // sessionID → connections

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/ws/relay/"), "/")
		if len(parts) != 2 {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		sid := parts[0]

		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusInternalError, "")

		mu.Lock()
		sessions[sid] = append(sessions[sid], c)
		mu.Unlock()
		defer func() {
			mu.Lock()
			list := sessions[sid]
			for i, x := range list {
				if x == c {
					list = append(list[:i], list[i+1:]...)
					break
				}
			}
			sessions[sid] = list
			mu.Unlock()
		}()

		ctx := context.Background()
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			// Forward to peers in same session.
			mu.Lock()
			peers := make([]*websocket.Conn, 0, len(sessions[sid]))
			for _, p := range sessions[sid] {
				if p != c {
					peers = append(peers, p)
				}
			}
			mu.Unlock()
			for _, p := range peers {
				_ = p.Write(ctx, websocket.MessageText, data)
			}
		}
	})
	return httptest.NewServer(handler)
}

func TestWSTunnelRoundtrip(t *testing.T) {
	hub := startRelayHub(t)
	defer hub.Close()

	wsURL := "ws" + strings.TrimPrefix(hub.URL, "http") + "/ws/relay/sessA/1"
	wsURL2 := "ws" + strings.TrimPrefix(hub.URL, "http") + "/ws/relay/sessA/2"

	wg1, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer wg1.Close()
	wg2, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer wg2.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t1, err := DialWSTunnel(ctx, WSTunnelConfig{
		PeerID: 1, SessionID: "sessA", URL: wsURL, WGEndpoint: wg1.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatalf("tunnel 1: %v", err)
	}
	defer t1.Close()

	t2, err := DialWSTunnel(ctx, WSTunnelConfig{
		PeerID: 2, SessionID: "sessA", URL: wsURL2, WGEndpoint: wg2.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatalf("tunnel 2: %v", err)
	}
	defer t2.Close()

	time.Sleep(50 * time.Millisecond) // let both register with the hub

	// wg1 writes to t1 local endpoint → travels via WS → t2 → wg2.
	if _, err := wg1.WriteToUDP([]byte("via-ws"), t1.LocalEndpoint()); err != nil {
		t.Fatalf("wg1 write: %v", err)
	}

	_ = wg2.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := wg2.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("wg2 read: %v", err)
	}
	if string(buf[:n]) != "via-ws" {
		t.Errorf("payload = %q", string(buf[:n]))
	}

	st := t1.Stats()
	if st.TxFrames == 0 {
		t.Errorf("tunnel stats empty: %+v", st)
	}
}

func TestWSFrameShape(t *testing.T) {
	// Spot-check that the JSON wire format matches the backend contract.
	f := wsFrame{Type: "relay_data", Data: base64.StdEncoding.EncodeToString([]byte("hi"))}
	raw, _ := json.Marshal(f)
	if !strings.Contains(string(raw), `"type":"relay_data"`) {
		t.Errorf("wire shape bad: %s", string(raw))
	}
}
