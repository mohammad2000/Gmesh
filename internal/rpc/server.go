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
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gmeshv1 "github.com/mohammad2000/Gmesh/gen/gmesh/v1"
	"github.com/mohammad2000/Gmesh/internal/config"
	"github.com/mohammad2000/Gmesh/internal/engine"
	"github.com/mohammad2000/Gmesh/internal/nat"
	"github.com/mohammad2000/Gmesh/internal/peer"
	"github.com/mohammad2000/Gmesh/internal/traversal"
	"github.com/mohammad2000/Gmesh/internal/version"
)

// Server exposes the gmesh.v1.GMesh service.
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

// ── Lifecycle ─────────────────────────────────────────────────────────

// Version returns build info.
func (s *Server) Version(_ context.Context, _ *gmeshv1.VersionRequest) (*gmeshv1.VersionResponse, error) {
	return &gmeshv1.VersionResponse{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildDate: version.BuildDate,
	}, nil
}

// Status returns the current engine state plus a peer snapshot.
func (s *Server) Status(ctx context.Context, _ *gmeshv1.StatusRequest) (*gmeshv1.StatusResponse, error) {
	peers, err := s.Engine.RefreshPeerStats(ctx)
	if err != nil {
		s.Log.Warn("RefreshPeerStats failed", "error", err)
		peers = s.Engine.Peers.Snapshot()
	}

	resp := &gmeshv1.StatusResponse{
		Joined:    s.Engine.IsJoined(),
		MeshIp:    s.Engine.MeshIP(),
		Interface: s.Engine.Interface(),
		PeerCount: int32(len(peers)), //nolint:gosec // bounded by node capacity
	}
	for _, p := range peers {
		if p.Status == peer.StatusConnected {
			resp.ActivePeers++
		}
		resp.Peers = append(resp.Peers, peerToProto(p))
	}
	return resp, nil
}

// Join brings up WG + generates keys.
func (s *Server) Join(ctx context.Context, in *gmeshv1.JoinRequest) (*gmeshv1.JoinResponse, error) {
	if in.MeshIp == "" {
		return nil, status.Error(codes.InvalidArgument, "mesh_ip is required")
	}
	if in.InterfaceName == "" {
		in.InterfaceName = "wg-gritiva"
	}
	if in.ListenPort == 0 {
		in.ListenPort = 51820
	}

	res, err := s.Engine.Join(ctx, in.MeshIp, in.InterfaceName, uint16(in.ListenPort), in.NetworkCidr, in.NodeId)
	if err != nil {
		if err == engine.ErrAlreadyJoined {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "join: %v", err)
	}

	return &gmeshv1.JoinResponse{
		PublicKey:            res.PublicKey,
		PrivateKeyEncrypted:  res.PrivateKey, // plain for now — Phase 8 adds Fernet
	}, nil
}

// Leave tears down the interface.
func (s *Server) Leave(ctx context.Context, in *gmeshv1.LeaveRequest) (*gmeshv1.LeaveResponse, error) {
	if err := s.Engine.Leave(ctx, in.Reason); err != nil {
		return nil, status.Errorf(codes.Internal, "leave: %v", err)
	}
	return &gmeshv1.LeaveResponse{}, nil
}

// ── Peers ──────────────────────────────────────────────────────────────

// AddPeer installs a peer.
func (s *Server) AddPeer(ctx context.Context, in *gmeshv1.AddPeerRequest) (*gmeshv1.AddPeerResponse, error) {
	if in.PeerId == 0 {
		return nil, status.Error(codes.InvalidArgument, "peer_id is required")
	}
	if in.PublicKey == "" {
		return nil, status.Error(codes.InvalidArgument, "public_key is required")
	}
	if in.MeshIp == "" {
		return nil, status.Error(codes.InvalidArgument, "mesh_ip is required")
	}

	allowed := in.AllowedIps
	if len(allowed) == 0 {
		allowed = []string{in.MeshIp + "/32"}
	}

	p := &peer.Peer{
		ID:         in.PeerId,
		Type:       peer.TypeVM,
		MeshIP:     in.MeshIp,
		PublicKey:  in.PublicKey,
		Endpoint:   in.Endpoint,
		AllowedIPs: allowed,
		Status:     peer.StatusConnecting,
	}
	if err := s.Engine.AddPeer(ctx, p, time.Duration(in.Keepalive)*time.Second); err != nil {
		if err == engine.ErrNotJoined {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "add_peer: %v", err)
	}
	return &gmeshv1.AddPeerResponse{Peer: peerToProto(p)}, nil
}

// RemovePeer removes a peer.
func (s *Server) RemovePeer(ctx context.Context, in *gmeshv1.RemovePeerRequest) (*gmeshv1.RemovePeerResponse, error) {
	if err := s.Engine.RemovePeer(ctx, in.PeerId); err != nil {
		if err == engine.ErrPeerNotFound {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "remove_peer: %v", err)
	}
	return &gmeshv1.RemovePeerResponse{}, nil
}

// UpdatePeer changes endpoint / allowed-ips / keepalive.
func (s *Server) UpdatePeer(ctx context.Context, in *gmeshv1.UpdatePeerRequest) (*gmeshv1.UpdatePeerResponse, error) {
	err := s.Engine.UpdatePeer(ctx, in.PeerId, in.Endpoint, in.AllowedIps, time.Duration(in.Keepalive)*time.Second)
	if err != nil {
		if err == engine.ErrPeerNotFound {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "update_peer: %v", err)
	}
	p, _ := s.Engine.Peers.Get(in.PeerId)
	return &gmeshv1.UpdatePeerResponse{Peer: peerToProto(p)}, nil
}

// ListPeers returns all peers + live stats.
func (s *Server) ListPeers(ctx context.Context, _ *gmeshv1.ListPeersRequest) (*gmeshv1.ListPeersResponse, error) {
	peers, err := s.Engine.RefreshPeerStats(ctx)
	if err != nil {
		s.Log.Warn("RefreshPeerStats failed", "error", err)
		peers = s.Engine.Peers.Snapshot()
	}
	resp := &gmeshv1.ListPeersResponse{}
	for _, p := range peers {
		resp.Peers = append(resp.Peers, peerToProto(p))
	}
	return resp, nil
}

// GetPeerStats returns a single peer with current stats.
func (s *Server) GetPeerStats(ctx context.Context, in *gmeshv1.GetPeerStatsRequest) (*gmeshv1.GetPeerStatsResponse, error) {
	if _, err := s.Engine.RefreshPeerStats(ctx); err != nil {
		s.Log.Warn("RefreshPeerStats failed", "error", err)
	}
	p, ok := s.Engine.Peers.Get(in.PeerId)
	if !ok {
		return nil, status.Error(codes.NotFound, "peer not found")
	}
	return &gmeshv1.GetPeerStatsResponse{Peer: peerToProto(p)}, nil
}

// ── NAT & traversal ────────────────────────────────────────────────────

// DiscoverNAT runs STUN classification.
func (s *Server) DiscoverNAT(ctx context.Context, in *gmeshv1.DiscoverNATRequest) (*gmeshv1.DiscoverNATResponse, error) {
	info, err := s.Engine.DiscoverNAT(ctx, in.ForceRefresh)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "nat discover: %v", err)
	}
	return &gmeshv1.DiscoverNATResponse{Nat: natToProto(info)}, nil
}

// HolePunch currently just runs the DIRECT strategy against remote_endpoint.
// Richer hole-punch methods land in Phase 3.
func (s *Server) HolePunch(ctx context.Context, in *gmeshv1.HolePunchRequest) (*gmeshv1.HolePunchResponse, error) {
	out, _, err := s.Engine.HolePunch(ctx, &traversal.PeerContext{
		PeerID:         in.PeerId,
		RemoteEndpoint: in.RemoteEndpoint,
		FireAtUnixMS:   in.FireAtUnixMs,
	})
	if err != nil && out == nil {
		return &gmeshv1.HolePunchResponse{Success: false, Error: err.Error()}, nil
	}
	resp := &gmeshv1.HolePunchResponse{
		Success:    out.Success,
		MethodUsed: gmeshv1.ConnectionMethod(out.Method),
		LatencyMs:  out.LatencyMS,
		Error:      out.Error,
	}
	return resp, nil
}

// natToProto converts an internal nat.Info to the wire format.
func natToProto(i *nat.Info) *gmeshv1.NATInfo {
	if i == nil {
		return nil
	}
	return &gmeshv1.NATInfo{
		NatType:           gmeshv1.NATType(i.Type),
		ExternalIp:        i.ExternalIP,
		ExternalPort:      uint32(i.ExternalPort),
		SupportsHolePunch: i.SupportsHolePunch,
		IsRelayCapable:    i.IsRelayCapable,
	}
}

// peerToProto converts an internal peer.Peer to the wire format.
func peerToProto(p *peer.Peer) *gmeshv1.Peer {
	if p == nil {
		return nil
	}
	pt := gmeshv1.PeerType_PEER_TYPE_VM
	if p.Type == peer.TypeScope {
		pt = gmeshv1.PeerType_PEER_TYPE_SCOPE
	}
	return &gmeshv1.Peer{
		Id:                 p.ID,
		Type:               pt,
		MeshIp:             p.MeshIP,
		PublicKey:          p.PublicKey,
		Endpoint:           p.Endpoint,
		AllowedIps:         p.AllowedIPs,
		Status:             gmeshv1.PeerStatus(p.Status),
		NatType:            gmeshv1.NATType(p.NATType),
		SupportsHolePunch:  p.SupportsHolePunch,
		IsRelayCapable:     p.IsRelayCapable,
		Method:             gmeshv1.ConnectionMethod(p.Method),
		RxBytes:            p.RxBytes,
		TxBytes:            p.TxBytes,
		LatencyMs:          p.LatencyMS,
		PacketLoss:         p.PacketLoss,
		LastHandshakeUnix:  p.LastHandshake.Unix(),
		ScopeId:            p.ScopeID,
	}
}
