package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// upstream is the client's link to gmesh-relay: a connected UDP socket, or
// a WebSocket (wss://…) for networks where UDP doesn't get out. Each
// Write/Read is one relay frame either way.
type upstream interface {
	Write(b []byte) (int, error)
	Read(b []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// IsWS reports whether a relay address is a WebSocket URL.
func IsWS(addr string) bool {
	return strings.HasPrefix(addr, "wss://") || strings.HasPrefix(addr, "ws://")
}

func dialUpstream(ctx context.Context, addr string, timeout time.Duration) (upstream, net.Addr, error) {
	if IsWS(addr) {
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		c, _, err := websocket.Dial(dctx, addr, nil) //nolint:bodyclose
		if err != nil {
			return nil, nil, fmt.Errorf("dial relay websocket: %w", err)
		}
		c.SetReadLimit(MaxFrameSize)
		wctx, wcancel := context.WithCancel(context.WithoutCancel(ctx))
		return &wsUpstream{c: c, ctx: wctx, cancel: wcancel}, wsAddr(addr), nil
	}
	ra, err := net.ResolveUDPAddr("udp", strings.TrimPrefix(addr, "udp://"))
	if err != nil {
		return nil, nil, fmt.Errorf("resolve relay: %w", err)
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return nil, nil, fmt.Errorf("dial relay: %w", err)
	}
	return c, ra, nil
}

type wsAddr string

func (a wsAddr) Network() string { return "ws" }
func (a wsAddr) String() string  { return string(a) }

type wsUpstream struct {
	c      *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	wmu    sync.Mutex
	dmu    sync.Mutex
	dl     time.Time
}

var errWSClosed = errors.New("relay websocket closed")

func (w *wsUpstream) Write(b []byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	ctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
	defer cancel()
	if err := w.c.Write(ctx, websocket.MessageBinary, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsUpstream) Read(b []byte) (int, error) {
	w.dmu.Lock()
	dl := w.dl
	w.dmu.Unlock()
	ctx := w.ctx
	if !dl.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl)
		defer cancel()
	}
	for {
		typ, data, err := w.c.Read(ctx)
		if err != nil {
			if w.ctx.Err() != nil {
				return 0, errWSClosed
			}
			return 0, err
		}
		if typ == websocket.MessageBinary {
			return copy(b, data), nil
		}
	}
}

// SetReadDeadline: a deadline that fires mid-read closes a coder/websocket
// connection, so the client only uses it during the handshake.
func (w *wsUpstream) SetReadDeadline(t time.Time) error {
	w.dmu.Lock()
	w.dl = t
	w.dmu.Unlock()
	return nil
}

func (w *wsUpstream) Close() error {
	w.cancel()
	return w.c.Close(websocket.StatusNormalClosure, "bye")
}
