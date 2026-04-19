package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

// WSTunnel wraps WireGuard UDP datagrams in WebSocket frames addressed to
// the GritivaCore backend's existing `/ws/relay/{session_id}/{peer_id}`
// endpoint. The backend pairs two clients with the same session_id and
// forwards messages between them.
//
// This is the transport of last resort: works even when UDP is blocked
// entirely (schools, locked-down enterprise networks). Throughput is
// obviously lower than direct UDP because every packet does a TLS+base64
// round-trip.
//
// Wire format (JSON, matches existing backend):
//
//	{"type": "relay_data", "data": "<base64-encoded UDP payload>"}
type WSTunnel struct {
	PeerID    int64
	SessionID string
	URL       string // wss://api.gritiva.com/ws/relay/{session}/{peer}
	Log       *slog.Logger

	ws           *websocket.Conn
	localForward *net.UDPConn
	wgEndpoint   *net.UDPAddr

	startedAt time.Time
	closed    atomic.Bool
	cancel    context.CancelFunc

	stats struct {
		sync.Mutex
		txFrames, rxFrames uint64
		txBytes, rxBytes   uint64
	}
}

// WSTunnelConfig bundles the knobs for DialWSTunnel.
type WSTunnelConfig struct {
	PeerID      int64
	SessionID   string
	URL         string
	WGEndpoint  *net.UDPAddr // WG listen port (127.0.0.1:51820 etc)
	DialTimeout time.Duration
	Log         *slog.Logger
	// HTTPHeader bundles things like Authorization: Bearer <token>
	HTTPHeader map[string]string
}

// wsFrame is the JSON envelope the backend expects.
type wsFrame struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

// DialWSTunnel opens the WS, allocates a local UDP forwarder, and begins
// bridging traffic.
func DialWSTunnel(ctx context.Context, cfg WSTunnelConfig) (*WSTunnel, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.WGEndpoint == nil {
		return nil, errors.New("ws_tunnel: WGEndpoint is required")
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}

	dctx, dcancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer dcancel()

	opts := &websocket.DialOptions{}
	if len(cfg.HTTPHeader) > 0 {
		opts.HTTPHeader = make(map[string][]string, len(cfg.HTTPHeader))
		for k, v := range cfg.HTTPHeader {
			opts.HTTPHeader[k] = []string{v}
		}
	}

	ws, _, err := websocket.Dial(dctx, cfg.URL, opts)
	if err != nil {
		return nil, fmt.Errorf("ws dial %s: %w", cfg.URL, err)
	}
	ws.SetReadLimit(int64(MaxFrameSize) * 2) // allow JSON+base64 overhead

	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		ws.Close(websocket.StatusInternalError, "local bind failed") //nolint:errcheck
		return nil, fmt.Errorf("local bind: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	t := &WSTunnel{
		PeerID:       cfg.PeerID,
		SessionID:    cfg.SessionID,
		URL:          cfg.URL,
		Log:          cfg.Log,
		ws:           ws,
		localForward: local,
		wgEndpoint:   cfg.WGEndpoint,
		startedAt:    time.Now(),
		cancel:       cancel,
	}
	go t.wgToWsLoop(ctx)
	go t.wsToWgLoop(ctx)

	cfg.Log.Info("ws tunnel established",
		"peer_id", cfg.PeerID, "url", cfg.URL,
		"local_endpoint", local.LocalAddr().String())
	return t, nil
}

// LocalEndpoint returns the 127.0.0.1:PORT address WireGuard should dial.
func (t *WSTunnel) LocalEndpoint() *net.UDPAddr { return t.localForward.LocalAddr().(*net.UDPAddr) }

// Stats returns counters.
func (t *WSTunnel) Stats() Stats {
	t.stats.Lock()
	defer t.stats.Unlock()
	return Stats{
		TxFrames:   t.stats.txFrames,
		RxFrames:   t.stats.rxFrames,
		BytesTx:    t.stats.txBytes,
		BytesRx:    t.stats.rxBytes,
		ConnectedS: int64(time.Since(t.startedAt).Seconds()),
	}
}

// Close tears the tunnel down. Idempotent.
func (t *WSTunnel) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	t.cancel()
	_ = t.localForward.Close()
	return t.ws.Close(websocket.StatusNormalClosure, "bye")
}

// ── Loops ──────────────────────────────────────────────────────────────

func (t *WSTunnel) wgToWsLoop(ctx context.Context) {
	buf := make([]byte, MaxFrameSize)
	for {
		if t.closed.Load() {
			return
		}
		n, src, err := t.localForward.ReadFromUDP(buf)
		if err != nil {
			return
		}
		t.wgEndpoint = src
		payload := base64.StdEncoding.EncodeToString(buf[:n])
		msg, err := json.Marshal(wsFrame{Type: "relay_data", Data: payload})
		if err != nil {
			continue
		}
		if err := t.ws.Write(ctx, websocket.MessageText, msg); err != nil {
			t.Log.Debug("ws write error", "error", err)
			return
		}
		t.stats.Lock()
		t.stats.txFrames++
		t.stats.txBytes += uint64(n) //nolint:gosec
		t.stats.Unlock()
	}
}

func (t *WSTunnel) wsToWgLoop(ctx context.Context) {
	for {
		if t.closed.Load() {
			return
		}
		_, data, err := t.ws.Read(ctx)
		if err != nil {
			return
		}
		var frame wsFrame
		if err := json.Unmarshal(data, &frame); err != nil {
			continue
		}
		if frame.Type != "relay_data" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(frame.Data)
		if err != nil {
			continue
		}
		if t.wgEndpoint == nil {
			continue
		}
		if _, err := t.localForward.WriteToUDP(decoded, t.wgEndpoint); err != nil {
			continue
		}
		t.stats.Lock()
		t.stats.rxFrames++
		t.stats.rxBytes += uint64(len(decoded)) //nolint:gosec
		t.stats.Unlock()
	}
}
