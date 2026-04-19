package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server is the HTTP surface. It listens on a dedicated Unix socket
// (default /run/gmesh-metrics.sock) and exposes:
//
//	GET /metrics     Prometheus text format
//	GET /healthz     200 OK if the daemon is alive (liveness probe)
//
// Scrape with:
//
//	curl --unix-socket /run/gmesh-metrics.sock http://localhost/metrics
type Server struct {
	SocketPath string
	Log        *slog.Logger

	ln  net.Listener
	srv *http.Server
}

// NewServer returns a ready-to-start Server.
func NewServer(socketPath string, log *slog.Logger) *Server {
	if socketPath == "" {
		socketPath = "/run/gmesh-metrics.sock"
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{SocketPath: socketPath, Log: log}
}

// Start binds the socket and serves in a goroutine. Returns a stop fn.
func (s *Server) Start() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(s.SocketPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir socket dir: %w", err)
	}
	_ = os.Remove(s.SocketPath)

	ln, err := net.Listen("unix", s.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", s.SocketPath, err)
	}
	if err := os.Chmod(s.SocketPath, 0o660); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod: %w", err)
	}
	s.ln = ln

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		s.Log.Info("metrics server listening", "socket", s.SocketPath)
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.Log.Error("metrics serve exited", "error", err)
		}
	}()

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
		_ = ln.Close()
		_ = os.Remove(s.SocketPath)
	}
	return stop, nil
}
