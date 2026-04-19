// Package rpc implements the gRPC server that exposes the gmeshd control
// plane over a Unix socket.
package rpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc"

	gmeshv1 "github.com/mohammad2000/Gmesh/gen/gmesh/v1"
	"github.com/mohammad2000/Gmesh/internal/config"
	"github.com/mohammad2000/Gmesh/internal/engine"
	"github.com/mohammad2000/Gmesh/internal/version"
)

// Server holds the gRPC server and the unix listener.
type Server struct {
	gmeshv1.UnimplementedGMeshServer

	Engine *engine.Engine
	Log    *slog.Logger
	cfg    config.SocketConfig
	grpc   *grpc.Server
	ln     net.Listener
}

// NewServer constructs a Server bound to the engine.
func NewServer(eng *engine.Engine, log *slog.Logger) *Server {
	return &Server{Engine: eng, Log: log, cfg: eng.Config.Socket}
}

// Start creates the unix socket, registers the service, and begins serving.
// The returned function stops the server (idempotent).
func (s *Server) Start() (stop func(), err error) {
	if err := os.MkdirAll(filepath.Dir(s.cfg.Path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir socket dir: %w", err)
	}
	// Remove any stale socket.
	_ = os.Remove(s.cfg.Path)

	ln, err := net.Listen("unix", s.cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", s.cfg.Path, err)
	}
	if err := os.Chmod(s.cfg.Path, os.FileMode(s.cfg.Mode)); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}

	gs := grpc.NewServer()
	gmeshv1.RegisterGMeshServer(gs, s)

	s.grpc = gs
	s.ln = ln

	go func() {
		s.Log.Info("gRPC server listening", "socket", s.cfg.Path)
		if err := gs.Serve(ln); err != nil && err != grpc.ErrServerStopped {
			s.Log.Error("gRPC serve exited", "error", err)
		}
	}()

	stop = func() {
		gs.GracefulStop()
		_ = ln.Close()
		_ = os.Remove(s.cfg.Path)
	}
	return stop, nil
}

// ── RPC handlers (minimal — real impls come in Phase 1+) ─────────────────

// Version returns build info.
func (s *Server) Version(_ context.Context, _ *gmeshv1.VersionRequest) (*gmeshv1.VersionResponse, error) {
	return &gmeshv1.VersionResponse{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildDate: version.BuildDate,
	}, nil
}

// Status returns the current engine state.
func (s *Server) Status(_ context.Context, _ *gmeshv1.StatusRequest) (*gmeshv1.StatusResponse, error) {
	return &gmeshv1.StatusResponse{
		Joined:     s.Engine.IsJoined(),
		MeshIp:     s.Engine.MeshIP(),
		Interface:  s.Engine.Interface(),
		PeerCount:  int32(s.Engine.Peers.Count()), //nolint:gosec // small number
	}, nil
}
