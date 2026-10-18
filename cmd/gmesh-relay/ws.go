package main

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/mohammad2000/Gmesh/internal/relay"
)

// WSPath is where the WebSocket side of the relay listens. Each binary
// message is one relay frame — the same frames as over UDP.
const WSPath = "/v2/relay"

// wsClient is one WebSocket connection. Writes are serialised and bounded
// so a stalled TCP client can't hold up the forwarding loop for long.
type wsClient struct {
	c   *websocket.Conn
	ctx context.Context
	mu  sync.Mutex
}

func (w *wsClient) send(frame []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	ctx, cancel := context.WithTimeout(w.ctx, 2*time.Second)
	defer cancel()
	return w.c.Write(ctx, websocket.MessageBinary, frame)
}

// ServeWS runs the WebSocket listener (plain HTTP; TLS is the job of
// whatever fronts it — a Cloudflare Tunnel or a reverse proxy).
func (s *Server) ServeWS(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc(WSPath, func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		c.SetReadLimit(relay.MaxFrameSize)
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		cl := &wsClient{c: c, ctx: cctx}
		k := sink{ws: cl}
		defer func() { s.forget(k); _ = c.CloseNow() }()
		for {
			typ, b, err := c.Read(cctx)
			if err != nil {
				return
			}
			if typ == websocket.MessageBinary {
				s.handle(k, b)
			}
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "not found", http.StatusNotFound) })
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	s.Log.Info("gmesh-relay websocket listening", "addr", addr, "path", WSPath)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
