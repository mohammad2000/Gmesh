// Package rpc implements the gRPC server that exposes the gmeshd control
// plane over a Unix socket.
package rpc

import (
	"context"
	"crypto/sha256"
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
	"github.com/mohammad2000/Gmesh/internal/audit"
	"github.com/mohammad2000/Gmesh/internal/config"
	"github.com/mohammad2000/Gmesh/internal/egress"
	"github.com/mohammad2000/Gmesh/internal/engine"
	"github.com/mohammad2000/Gmesh/internal/events"
	"github.com/mohammad2000/Gmesh/internal/firewall"
	"github.com/mohammad2000/Gmesh/internal/ingress"
	"github.com/mohammad2000/Gmesh/internal/anomaly"
	"github.com/mohammad2000/Gmesh/internal/circuit"
	"github.com/mohammad2000/Gmesh/internal/l7"
	"github.com/mohammad2000/Gmesh/internal/mtls"
	"github.com/mohammad2000/Gmesh/internal/nat"
	"github.com/mohammad2000/Gmesh/internal/pathmon"
	"github.com/mohammad2000/Gmesh/internal/peer"
	"github.com/mohammad2000/Gmesh/internal/policy"
	"github.com/mohammad2000/Gmesh/internal/quota"
	"github.com/mohammad2000/Gmesh/internal/relay"
	"github.com/mohammad2000/Gmesh/internal/scope"
	"github.com/mohammad2000/Gmesh/internal/traversal"
	"github.com/mohammad2000/Gmesh/internal/version"
)

// Server exposes the gmesh.v1.GMesh service.
type Server struct {
	gmeshv1.UnimplementedGMeshServer

	Engine *engine.Engine
	Log    *slog.Logger
	Audit  *audit.Logger
	cfg    config.SocketConfig
	grpc   *grpc.Server
	ln     net.Listener
}

// NewServer constructs a Server bound to the engine. If au is nil,
// per-RPC auditing is disabled but metrics are still recorded.
func NewServer(eng *engine.Engine, log *slog.Logger, au *audit.Logger) *Server {
	return &Server{Engine: eng, Log: log, Audit: au, cfg: eng.Config.Socket}
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

	unary := grpc.ChainUnaryInterceptor(
		newMetricsInterceptor(),
		newAuditInterceptor(s.Audit),
	)
	stream := grpc.ChainStreamInterceptor(newStreamMetricsInterceptor())
	gs := grpc.NewServer(unary, stream)
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
		Joined:     s.Engine.IsJoined(),
		MeshIp:     s.Engine.MeshIP(),
		Interface:  s.Engine.Interface(),
		PublicKey:  s.Engine.PubKey(),
		ListenPort: uint32(s.Engine.ListenPort()),
		PeerCount:  int32(len(peers)), //nolint:gosec // bounded by node capacity
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

	// Enumerate local LAN endpoints so the coordinator can propagate
	// them to other peers on the same subnet. Combined with the STUN
	// reflexive candidate, this gives downstream peers a prioritized
	// list: LAN (priority 10) → STUN (60).
	var candidates []*gmeshv1.PeerEndpoint
	for _, addr := range nat.LocalEndpoints(uint32(in.ListenPort)) {
		candidates = append(candidates, &gmeshv1.PeerEndpoint{
			Address:  addr,
			Type:     gmeshv1.EndpointType_ENDPOINT_LAN,
			Priority: 10,
		})
	}

	return &gmeshv1.JoinResponse{
		PublicKey:           res.PublicKey,
		PrivateKeyEncrypted: res.PrivateKey, // plain for now — Phase 8 adds Fernet
		Endpoints:           candidates,
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
		Endpoints:  endpointsFromProto(in.Endpoints, in.Endpoint),
		AllowedIPs: allowed,
		Status:     peer.StatusConnecting,
	}
	if in.RemoteNat != nil {
		p.NATType = int(in.RemoteNat.NatType)
		p.SupportsHolePunch = in.RemoteNat.SupportsHolePunch
		p.IsRelayCapable = in.RemoteNat.IsRelayCapable
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

// UpdatePeer changes endpoint / allowed-ips / keepalive / candidate list.
func (s *Server) UpdatePeer(ctx context.Context, in *gmeshv1.UpdatePeerRequest) (*gmeshv1.UpdatePeerResponse, error) {
	err := s.Engine.UpdatePeer(ctx, in.PeerId, in.Endpoint, in.AllowedIps, time.Duration(in.Keepalive)*time.Second)
	if err != nil {
		if err == engine.ErrPeerNotFound {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "update_peer: %v", err)
	}
	if len(in.Endpoints) > 0 {
		if p, ok := s.Engine.Peers.Get(in.PeerId); ok {
			p.Endpoints = endpointsFromProto(in.Endpoints, in.Endpoint)
		}
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

// ── Health ────────────────────────────────────────────────────────────

// HealthCheck returns a snapshot of every peer's current health (or a
// specific peer if peer_id != 0).
func (s *Server) HealthCheck(_ context.Context, in *gmeshv1.HealthCheckRequest) (*gmeshv1.HealthCheckResponse, error) {
	resp := &gmeshv1.HealthCheckResponse{}
	for _, p := range s.Engine.Peers.Snapshot() {
		if in.PeerId != 0 && p.ID != in.PeerId {
			continue
		}
		score := healthScoreForPeer(p)
		resp.Peers = append(resp.Peers, &gmeshv1.HealthCheckResponse_PeerHealth{
			PeerId:        p.ID,
			Status:        gmeshv1.HealthStatus(healthStatusFromScore(score)),
			Score:         int32(score), //nolint:gosec // 0..100
			LatencyMs:     p.LatencyMS,
			PacketLoss:    p.PacketLoss,
			HandshakeAgeS: int64(time.Since(p.LastHandshake).Seconds()),
		})
	}
	return resp, nil
}

// healthScoreForPeer is a simple point-in-time scorer for the HealthCheck
// RPC. The persistent health.Monitor uses a weighted formula; this one is
// intentionally coarser and cheaper.
func healthScoreForPeer(p *peer.Peer) int {
	score := methodWeight(p.Method)
	score += int(50 - min(int64(50), p.LatencyMS/4)) // fresher latency = more points
	if !p.LastHandshake.IsZero() {
		age := time.Since(p.LastHandshake).Seconds()
		switch {
		case age < 150:
			score += 20
		case age < 600:
			score += 10
		}
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score
}

func methodWeight(m int) int {
	switch m {
	case 1:
		return 50 // direct
	case 2:
		return 45 // upnp
	case 3, 4, 5:
		return 35 // hole-punched
	case 6, 7, 8:
		return 15 // relay / ws tunnel
	default:
		return 25
	}
}

func healthStatusFromScore(score int) int {
	switch {
	case score > 90:
		return 1 // excellent
	case score > 70:
		return 2 // good
	case score > 50:
		return 3 // degraded
	case score > 30:
		return 4 // poor
	default:
		return 5 // failing
	}
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// ── Event stream ──────────────────────────────────────────────────────

// SubscribeEvents is a server-streaming RPC: subscribers get a live feed
// of every engine event whose type matches the filter (empty = all).
// The stream closes when the client disconnects or the engine's context
// is canceled.
func (s *Server) SubscribeEvents(in *gmeshv1.SubscribeEventsRequest, stream gmeshv1.GMesh_SubscribeEventsServer) error {
	ch, cancel := s.Engine.Events.Subscribe(in.Types, 256)
	defer cancel()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			wire := &gmeshv1.Event{
				TimestampUnixMs: ev.Timestamp.UnixMilli(),
				Type:            ev.Type,
				PeerId:          formatPeerID(ev.PeerID),
				PayloadJson:     string(ev.Payload),
			}
			if err := stream.Send(wire); err != nil {
				return err
			}
		}
	}
}

func formatPeerID(id int64) string {
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("%d", id)
}

// subscriberCount is a small helper for diagnostics/tests.
func (s *Server) subscriberCount() int {
	if s.Engine == nil || s.Engine.Events == nil {
		return 0
	}
	return s.Engine.Events.SubscriberCount()
}

// eventsBus exposes the bus for in-process consumers.
func (s *Server) eventsBus() *events.Bus { return s.Engine.Events }

// ── Quota (Phase 13) ──────────────────────────────────────────────────

func (s *Server) CreateQuota(ctx context.Context, in *gmeshv1.CreateQuotaRequest) (*gmeshv1.QuotaResponse, error) {
	if in.Quota == nil {
		return nil, status.Error(codes.InvalidArgument, "quota required")
	}
	q, err := s.Engine.CreateQuota(ctx, quotaFromProto(in.Quota))
	if err != nil {
		if err == quota.ErrExists {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "create quota: %v", err)
	}
	return &gmeshv1.QuotaResponse{Quota: quotaToProto(q)}, nil
}

func (s *Server) UpdateQuota(ctx context.Context, in *gmeshv1.UpdateQuotaRequest) (*gmeshv1.QuotaResponse, error) {
	if in.Quota == nil {
		return nil, status.Error(codes.InvalidArgument, "quota required")
	}
	q, err := s.Engine.UpdateQuota(ctx, quotaFromProto(in.Quota))
	if err != nil {
		if err == quota.ErrNotFound {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "update quota: %v", err)
	}
	return &gmeshv1.QuotaResponse{Quota: quotaToProto(q)}, nil
}

func (s *Server) DeleteQuota(ctx context.Context, in *gmeshv1.DeleteQuotaRequest) (*gmeshv1.DeleteQuotaResponse, error) {
	if err := s.Engine.DeleteQuota(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete quota: %v", err)
	}
	return &gmeshv1.DeleteQuotaResponse{}, nil
}

func (s *Server) ListQuotas(_ context.Context, _ *gmeshv1.ListQuotasRequest) (*gmeshv1.ListQuotasResponse, error) {
	resp := &gmeshv1.ListQuotasResponse{}
	for _, q := range s.Engine.ListQuotas() {
		resp.Quotas = append(resp.Quotas, quotaToProto(q))
	}
	return resp, nil
}

func (s *Server) GetQuotaUsage(ctx context.Context, in *gmeshv1.GetQuotaUsageRequest) (*gmeshv1.GetQuotaUsageResponse, error) {
	resp := &gmeshv1.GetQuotaUsageResponse{}
	for _, q := range s.Engine.GetQuotaUsage(ctx, in.Id) {
		resp.Quotas = append(resp.Quotas, quotaToProto(q))
	}
	return resp, nil
}

func (s *Server) ResetQuota(ctx context.Context, in *gmeshv1.ResetQuotaRequest) (*gmeshv1.ResetQuotaResponse, error) {
	if err := s.Engine.ResetQuota(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "reset quota: %v", err)
	}
	return &gmeshv1.ResetQuotaResponse{}, nil
}

// ListPathStates exposes the active-probe state the engine's PathMon
// tracks for every peer target.
func (s *Server) ListPathStates(_ context.Context, _ *gmeshv1.ListPathStatesRequest) (*gmeshv1.ListPathStatesResponse, error) {
	if s.Engine == nil || s.Engine.PathMon == nil {
		return &gmeshv1.ListPathStatesResponse{}, nil
	}
	states := s.Engine.PathMon.List()
	out := make([]*gmeshv1.PathState, 0, len(states))
	for _, st := range states {
		out = append(out, pathStateToProto(st))
	}
	return &gmeshv1.ListPathStatesResponse{States: out}, nil
}

// ── L7 classifier (Phase 18) ──────────────────────────────────────────

func (s *Server) ListL7Flows(_ context.Context, in *gmeshv1.ListL7FlowsRequest) (*gmeshv1.ListL7FlowsResponse, error) {
	if s.Engine == nil || s.Engine.L7 == nil {
		return &gmeshv1.ListL7FlowsResponse{}, nil
	}
	flows := s.Engine.L7.Flows()
	out := make([]*gmeshv1.L7Flow, 0, len(flows))
	for _, f := range flows {
		if in.PeerId != 0 && f.PeerID != in.PeerId {
			continue
		}
		out = append(out, l7FlowToProto(f))
	}
	return &gmeshv1.ListL7FlowsResponse{Flows: out}, nil
}

func (s *Server) ListL7Totals(_ context.Context, in *gmeshv1.ListL7TotalsRequest) (*gmeshv1.ListL7TotalsResponse, error) {
	if s.Engine == nil || s.Engine.L7 == nil {
		return &gmeshv1.ListL7TotalsResponse{}, nil
	}
	totals := s.Engine.L7.Totals()
	out := make([]*gmeshv1.L7Total, 0, len(totals))
	for _, t := range totals {
		if in.PeerId != 0 && t.PeerID != in.PeerId {
			continue
		}
		out = append(out, &gmeshv1.L7Total{
			PeerId: t.PeerID, L7Proto: string(t.Protocol),
			Bytes: t.Bytes, Flows: int64(t.Flows),
		})
	}
	return &gmeshv1.ListL7TotalsResponse{Totals: out}, nil
}

func l7FlowToProto(f l7.Flow) *gmeshv1.L7Flow {
	return &gmeshv1.L7Flow{
		SrcIp: f.SrcIP, DstIp: f.DstIP,
		SrcPort: uint32(f.SrcPort), DstPort: uint32(f.DstPort),
		L4Proto: f.L4Proto, L7Proto: string(f.L7Proto),
		Confidence: f.Confidence,
		RxBytes:    f.RxBytes, TxBytes: f.TxBytes,
		PeerId:       f.PeerID,
		LastSeenUnix: f.LastSeen.Unix(),
	}
}

// ── Anomaly (Phase 21) ────────────────────────────────────────────────

func (s *Server) ListAnomalies(_ context.Context, in *gmeshv1.ListAnomaliesRequest) (*gmeshv1.ListAnomaliesResponse, error) {
	if s.Engine == nil || s.Engine.Anomaly == nil {
		return &gmeshv1.ListAnomaliesResponse{}, nil
	}
	var alerts []anomaly.Alert
	if in.PeerId != 0 {
		alerts = s.Engine.Anomaly.ForPeer(in.PeerId)
	} else {
		alerts = s.Engine.Anomaly.Recent(int(in.Limit))
	}
	out := make([]*gmeshv1.Anomaly, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, anomalyToProto(a))
	}
	return &gmeshv1.ListAnomaliesResponse{Alerts: out}, nil
}

func anomalyToProto(a anomaly.Alert) *gmeshv1.Anomaly {
	metrics := make(map[string]float64, len(a.Metrics))
	for k, v := range a.Metrics {
		metrics[k] = v
	}
	return &gmeshv1.Anomaly{
		Detector: a.Detector, PeerId: a.PeerID,
		Severity: a.Severity.String(), Message: a.Message,
		Metrics:      metrics,
		ObservedUnix: a.Observed.Unix(),
	}
}

// ── Circuits (Phase 19) ───────────────────────────────────────────────

func (s *Server) CreateCircuit(ctx context.Context, in *gmeshv1.CreateCircuitRequest) (*gmeshv1.CircuitResponse, error) {
	if in.Circuit == nil {
		return nil, status.Error(codes.InvalidArgument, "circuit required")
	}
	c := circuitFromProto(in.Circuit)
	res, err := s.Engine.CreateCircuit(ctx, c)
	if err != nil {
		if err == circuit.ErrExists {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "create circuit: %v", err)
	}
	return &gmeshv1.CircuitResponse{Circuit: circuitToProto(res)}, nil
}

func (s *Server) UpdateCircuit(ctx context.Context, in *gmeshv1.UpdateCircuitRequest) (*gmeshv1.CircuitResponse, error) {
	if in.Circuit == nil {
		return nil, status.Error(codes.InvalidArgument, "circuit required")
	}
	res, err := s.Engine.UpdateCircuit(ctx, circuitFromProto(in.Circuit))
	if err != nil {
		if err == circuit.ErrNotFound {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "update circuit: %v", err)
	}
	return &gmeshv1.CircuitResponse{Circuit: circuitToProto(res)}, nil
}

func (s *Server) DeleteCircuit(ctx context.Context, in *gmeshv1.DeleteCircuitRequest) (*gmeshv1.DeleteCircuitResponse, error) {
	if err := s.Engine.DeleteCircuit(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete circuit: %v", err)
	}
	return &gmeshv1.DeleteCircuitResponse{}, nil
}

func (s *Server) ListCircuits(_ context.Context, _ *gmeshv1.ListCircuitsRequest) (*gmeshv1.ListCircuitsResponse, error) {
	out := s.Engine.ListCircuits()
	resp := &gmeshv1.ListCircuitsResponse{Circuits: make([]*gmeshv1.Circuit, 0, len(out))}
	for _, c := range out {
		resp.Circuits = append(resp.Circuits, circuitToProto(c))
	}
	return resp, nil
}

func circuitFromProto(p *gmeshv1.Circuit) *circuit.Circuit {
	return &circuit.Circuit{
		ID: p.Id, Name: p.Name, Enabled: p.Enabled, Priority: p.Priority,
		Source: p.Source, Hops: append([]int64(nil), p.Hops...),
		Protocol: p.Protocol, DestCIDR: p.DestCidr, DestPorts: p.DestPorts,
	}
}

func circuitToProto(c *circuit.Circuit) *gmeshv1.Circuit {
	return &gmeshv1.Circuit{
		Id: c.ID, Name: c.Name, Enabled: c.Enabled, Priority: c.Priority,
		Source: c.Source, Hops: append([]int64(nil), c.Hops...),
		Protocol: c.Protocol, DestCidr: c.DestCIDR, DestPorts: c.DestPorts,
		CreatedAtUnix: c.CreatedAt.Unix(),
		UpdatedAtUnix: c.UpdatedAt.Unix(),
	}
}

// ── mTLS / SPIFFE (Phase 20) ──────────────────────────────────────────

func (s *Server) InitCA(_ context.Context, in *gmeshv1.InitCARequest) (*gmeshv1.InitCAResponse, error) {
	if s.Engine == nil || s.Engine.MTLS == nil {
		return nil, status.Error(codes.FailedPrecondition, "mtls CA not configured (set mtls.dir in config)")
	}
	caPEM, err := s.Engine.MTLS.InitCA(in.TrustDomain, in.Force)
	if err != nil {
		if err == mtls.ErrAlreadyInitialised {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "init ca: %v", err)
	}
	return &gmeshv1.InitCAResponse{
		CaPem:       caPEM,
		TrustDomain: s.Engine.MTLS.TrustDomain(),
	}, nil
}

func (s *Server) CAStatus(_ context.Context, _ *gmeshv1.CAStatusRequest) (*gmeshv1.CAStatusResponse, error) {
	resp := &gmeshv1.CAStatusResponse{}
	if s.Engine == nil || s.Engine.MTLS == nil {
		return resp, nil
	}
	m := s.Engine.MTLS
	resp.Loaded = m.Loaded()
	if !resp.Loaded {
		return resp, nil
	}
	resp.TrustDomain = m.TrustDomain()
	resp.CaPem = m.CACert()
	for _, c := range m.ListCerts(0) {
		resp.IssuedCount++
		if c.Revoked {
			resp.RevokedCount++
		}
	}
	return resp, nil
}

func (s *Server) IssueCert(_ context.Context, in *gmeshv1.IssueCertRequest) (*gmeshv1.IssueCertResponse, error) {
	if s.Engine == nil || s.Engine.MTLS == nil {
		return nil, status.Error(codes.FailedPrecondition, "mtls CA not configured")
	}
	req := mtls.CertRequest{
		PeerID:     in.PeerId,
		CommonName: in.CommonName,
		DNSNames:   in.DnsNames,
		SpiffeID:   in.SpiffeId,
	}
	for _, s := range in.IpAddrs {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, status.Errorf(codes.InvalidArgument, "bad ip_addr %q", s)
		}
		req.IPAddrs = append(req.IPAddrs, ip)
	}
	if in.ValidityDays > 0 {
		now := time.Now().UTC()
		req.NotBefore = now
		req.NotAfter = now.AddDate(0, 0, int(in.ValidityDays))
	}
	c, err := s.Engine.MTLS.IssueCert(req)
	if err != nil {
		if err == mtls.ErrNotInitialised {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "issue cert: %v", err)
	}
	return &gmeshv1.IssueCertResponse{
		Cert: &gmeshv1.IssuedCert{
			Serial: c.Serial, PeerId: c.PeerID,
			CommonName: c.CommonName, SpiffeId: c.SpiffeID,
			CertPem: c.CertPEM, KeyPem: c.KeyPEM, CaPem: c.CAPEM,
			NotBeforeUnix: c.NotBefore.Unix(),
			NotAfterUnix:  c.NotAfter.Unix(),
		},
	}, nil
}

func (s *Server) ListCerts(_ context.Context, in *gmeshv1.ListCertsRequest) (*gmeshv1.ListCertsResponse, error) {
	if s.Engine == nil || s.Engine.MTLS == nil {
		return &gmeshv1.ListCertsResponse{}, nil
	}
	summaries := s.Engine.MTLS.ListCerts(in.PeerId)
	out := make([]*gmeshv1.CertSummary, 0, len(summaries))
	for _, c := range summaries {
		out = append(out, certSummaryToProto(c))
	}
	return &gmeshv1.ListCertsResponse{Certs: out}, nil
}

func (s *Server) RevokeCert(_ context.Context, in *gmeshv1.RevokeCertRequest) (*gmeshv1.RevokeCertResponse, error) {
	if s.Engine == nil || s.Engine.MTLS == nil {
		return nil, status.Error(codes.FailedPrecondition, "mtls CA not configured")
	}
	if err := s.Engine.MTLS.RevokeCert(in.Serial, in.Reason); err != nil {
		if err == mtls.ErrNotFound {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "revoke: %v", err)
	}
	return &gmeshv1.RevokeCertResponse{}, nil
}

func (s *Server) ExportTrust(_ context.Context, _ *gmeshv1.ExportTrustRequest) (*gmeshv1.ExportTrustResponse, error) {
	if s.Engine == nil || s.Engine.MTLS == nil || !s.Engine.MTLS.Loaded() {
		return nil, status.Error(codes.FailedPrecondition, "mtls CA not initialised")
	}
	return &gmeshv1.ExportTrustResponse{
		CaPem:       s.Engine.MTLS.CACert(),
		TrustDomain: s.Engine.MTLS.TrustDomain(),
	}, nil
}

func certSummaryToProto(c mtls.Summary) *gmeshv1.CertSummary {
	out := &gmeshv1.CertSummary{
		Serial: c.Serial, PeerId: c.PeerID,
		CommonName: c.CommonName, SpiffeId: c.SpiffeID,
		NotBeforeUnix: c.NotBefore.Unix(),
		NotAfterUnix:  c.NotAfter.Unix(),
		Revoked:       c.Revoked,
		RevokeReason:  c.Reason,
	}
	if !c.RevokedAt.IsZero() {
		out.RevokedAtUnix = c.RevokedAt.Unix()
	}
	return out
}

// ── Policies (Phase 17) ───────────────────────────────────────────────

// ListPolicies returns every policy currently loaded.
func (s *Server) ListPolicies(_ context.Context, _ *gmeshv1.ListPoliciesRequest) (*gmeshv1.ListPoliciesResponse, error) {
	if s.Engine == nil || s.Engine.Policies == nil {
		return &gmeshv1.ListPoliciesResponse{}, nil
	}
	ps := s.Engine.Policies.List()
	out := make([]*gmeshv1.Policy, 0, len(ps))
	for _, p := range ps {
		out = append(out, policyToProto(p))
	}
	return &gmeshv1.ListPoliciesResponse{Policies: out}, nil
}

// ReloadPolicies re-reads the configured directory.
func (s *Server) ReloadPolicies(_ context.Context, _ *gmeshv1.ReloadPoliciesRequest) (*gmeshv1.ReloadPoliciesResponse, error) {
	if s.Engine == nil || s.Engine.Policies == nil || s.Engine.Config == nil {
		return &gmeshv1.ReloadPoliciesResponse{}, nil
	}
	dir := s.Engine.Config.Policies.Dir
	if dir == "" {
		return nil, status.Error(codes.FailedPrecondition, "policies.dir not configured")
	}
	ps, errs := policy.LoadDir(dir)
	s.Engine.Policies.Replace(ps)
	resp := &gmeshv1.ReloadPoliciesResponse{Loaded: int64(len(ps))}
	for _, err := range errs {
		resp.Errors = append(resp.Errors, err.Error())
	}
	return resp, nil
}

func policyToProto(p *policy.Policy) *gmeshv1.Policy {
	return &gmeshv1.Policy{
		Name:             p.Name,
		Source:           p.Source(),
		Event:            p.When.Event,
		PeerId:           p.When.PeerID,
		ProfileId:        p.When.ProfileID,
		DebounceS:        int32(p.When.DebounceSeconds),
		MinCount:         int32(p.When.MinCount),
		Action:           p.Do.Action,
		ActionProfileId:  p.Do.ProfileID,
		ActionToPeerId:   p.Do.ToPeerID,
		ActionQuotaId:    p.Do.QuotaID,
	}
}

func pathStateToProto(st pathmon.State) *gmeshv1.PathState {
	return &gmeshv1.PathState{
		PeerId:           st.Target.PeerID,
		MeshIp:           st.Target.MeshIP,
		Status:           st.Status.String(),
		ConsecutiveOk:    int64(st.ConsecutiveOK),
		ConsecutiveFail:  int64(st.ConsecutiveFail),
		LastRttUs:        st.LastRTT.Microseconds(),
		LossPct:          st.LossPct,
		Samples:          int64(st.Samples),
		LastSampleUnix:   st.LastSampleAt.Unix(),
		LastUpUnix:       st.LastUpAt.Unix(),
		LastDownUnix:     st.LastDownAt.Unix(),
	}
}

func quotaFromProto(p *gmeshv1.Quota) *quota.Quota {
	return &quota.Quota{
		ID: p.Id, Name: p.Name, Enabled: p.Enabled,
		EgressProfileID: p.EgressProfileId,
		Period:          quota.Period(p.Period),
		LimitBytes:      p.LimitBytes,
		WarnAt:          p.WarnAt, ShiftAt: p.ShiftAt, StopAt: p.StopAt,
		BackupProfileID: p.BackupProfileId,
		HardStop:        p.HardStop,
		AutoRollback:    p.AutoRollback,
	}
}

func quotaToProto(q *quota.Quota) *gmeshv1.Quota {
	return &gmeshv1.Quota{
		Id: q.ID, Name: q.Name, Enabled: q.Enabled,
		EgressProfileId: q.EgressProfileID,
		Period:          string(q.Period),
		LimitBytes:      q.LimitBytes,
		UsedBytes:       q.UsedBytes,
		WarnAt:          q.WarnAt, ShiftAt: q.ShiftAt, StopAt: q.StopAt,
		BackupProfileId:     q.BackupProfileID,
		HardStop:            q.HardStop,
		AutoRollback:        q.AutoRollback,
		ShiftedFromPeerId:   q.ShiftedFromPeerID,
		WarnFired:           q.WarnFired,
		ShiftFired:      q.ShiftFired,
		StopFired:       q.StopFired,
		PeriodStartUnix: q.PeriodStart.Unix(),
		PeriodEndUnix:   q.PeriodEnd.Unix(),
		CreatedAtUnix:   q.CreatedAt.Unix(),
		UpdatedAtUnix:   q.UpdatedAt.Unix(),
	}
}

// ── Ingress profiles (Phase 12) ───────────────────────────────────────

func (s *Server) CreateIngressProfile(ctx context.Context, in *gmeshv1.CreateIngressProfileRequest) (*gmeshv1.IngressProfileResponse, error) {
	if in.Profile == nil {
		return nil, status.Error(codes.InvalidArgument, "profile required")
	}
	p := ingressFromProto(in.Profile)
	res, err := s.Engine.CreateIngress(ctx, p)
	if err != nil {
		if err == ingress.ErrExists {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "create ingress: %v", err)
	}
	return &gmeshv1.IngressProfileResponse{Profile: ingressToProto(res)}, nil
}

func (s *Server) UpdateIngressProfile(ctx context.Context, in *gmeshv1.UpdateIngressProfileRequest) (*gmeshv1.IngressProfileResponse, error) {
	if in.Profile == nil {
		return nil, status.Error(codes.InvalidArgument, "profile required")
	}
	res, err := s.Engine.UpdateIngress(ctx, ingressFromProto(in.Profile))
	if err != nil {
		if err == ingress.ErrNotFound {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "update ingress: %v", err)
	}
	return &gmeshv1.IngressProfileResponse{Profile: ingressToProto(res)}, nil
}

func (s *Server) DeleteIngressProfile(ctx context.Context, in *gmeshv1.DeleteIngressProfileRequest) (*gmeshv1.DeleteIngressProfileResponse, error) {
	if err := s.Engine.DeleteIngress(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete ingress: %v", err)
	}
	return &gmeshv1.DeleteIngressProfileResponse{}, nil
}

func (s *Server) ListIngressProfiles(_ context.Context, _ *gmeshv1.ListIngressProfilesRequest) (*gmeshv1.ListIngressProfilesResponse, error) {
	resp := &gmeshv1.ListIngressProfilesResponse{}
	for _, p := range s.Engine.ListIngress() {
		resp.Profiles = append(resp.Profiles, ingressToProto(p))
	}
	return resp, nil
}

func ingressFromProto(p *gmeshv1.IngressProfile) *ingress.Profile {
	return &ingress.Profile{
		ID: p.Id, Name: p.Name, Enabled: p.Enabled,
		BackendPeerID: p.BackendPeerId, BackendScopeID: p.BackendScopeId,
		BackendIP: p.BackendIp, BackendPort: uint16(p.BackendPort), //nolint:gosec
		EdgePeerID: p.EdgePeerId, EdgePort: uint16(p.EdgePort), //nolint:gosec
		Protocol:       p.Protocol,
		AllowedSources: p.AllowedSourceCidrs,
		RequireMTLS:    p.RequireMtls,
	}
}

func ingressToProto(p *ingress.Profile) *gmeshv1.IngressProfile {
	return &gmeshv1.IngressProfile{
		Id: p.ID, Name: p.Name, Enabled: p.Enabled,
		BackendPeerId: p.BackendPeerID, BackendScopeId: p.BackendScopeID,
		BackendIp: p.BackendIP, BackendPort: uint32(p.BackendPort),
		EdgePeerId: p.EdgePeerID, EdgePort: uint32(p.EdgePort),
		Protocol:           p.Protocol,
		AllowedSourceCidrs: p.AllowedSources,
		RequireMtls:        p.RequireMTLS,
		CreatedAtUnix:      p.CreatedAt.Unix(),
		UpdatedAtUnix:      p.UpdatedAt.Unix(),
	}
}

// ── Egress profiles (Phase 11) ────────────────────────────────────────

// CreateEgressProfile installs a new egress profile on this node.
func (s *Server) CreateEgressProfile(ctx context.Context, in *gmeshv1.CreateEgressProfileRequest) (*gmeshv1.EgressProfileResponse, error) {
	if in.Profile == nil {
		return nil, status.Error(codes.InvalidArgument, "profile required")
	}
	prof := egressFromProto(in.Profile)
	res, err := s.Engine.CreateEgress(ctx, prof)
	if err != nil {
		if err == egress.ErrExists {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "create egress: %v", err)
	}
	return &gmeshv1.EgressProfileResponse{Profile: egressToProto(res)}, nil
}

// UpdateEgressProfile re-installs an existing profile.
func (s *Server) UpdateEgressProfile(ctx context.Context, in *gmeshv1.UpdateEgressProfileRequest) (*gmeshv1.EgressProfileResponse, error) {
	if in.Profile == nil {
		return nil, status.Error(codes.InvalidArgument, "profile required")
	}
	res, err := s.Engine.UpdateEgress(ctx, egressFromProto(in.Profile))
	if err != nil {
		if err == egress.ErrNotFound {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "update egress: %v", err)
	}
	return &gmeshv1.EgressProfileResponse{Profile: egressToProto(res)}, nil
}

// DeleteEgressProfile removes a profile.
func (s *Server) DeleteEgressProfile(ctx context.Context, in *gmeshv1.DeleteEgressProfileRequest) (*gmeshv1.DeleteEgressProfileResponse, error) {
	if err := s.Engine.DeleteEgress(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete egress: %v", err)
	}
	return &gmeshv1.DeleteEgressProfileResponse{}, nil
}

// ListEgressProfiles returns every active profile.
func (s *Server) ListEgressProfiles(_ context.Context, _ *gmeshv1.ListEgressProfilesRequest) (*gmeshv1.ListEgressProfilesResponse, error) {
	profs := s.Engine.ListEgress()
	resp := &gmeshv1.ListEgressProfilesResponse{}
	for _, p := range profs {
		resp.Profiles = append(resp.Profiles, egressToProto(p))
	}
	return resp, nil
}

// EnableExit installs the MASQUERADE ruleset so this node can act as an
// exit for other peers.
func (s *Server) EnableExit(ctx context.Context, in *gmeshv1.EnableExitRequest) (*gmeshv1.EnableExitResponse, error) {
	if err := s.Engine.EnableExit(ctx, in.AllowedPeerIds); err != nil {
		return nil, status.Errorf(codes.Internal, "enable exit: %v", err)
	}
	return &gmeshv1.EnableExitResponse{}, nil
}

// DisableExit tears the exit ruleset down.
func (s *Server) DisableExit(ctx context.Context, _ *gmeshv1.DisableExitRequest) (*gmeshv1.DisableExitResponse, error) {
	if err := s.Engine.DisableExit(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "disable exit: %v", err)
	}
	return &gmeshv1.DisableExitResponse{}, nil
}

func egressFromProto(p *gmeshv1.EgressProfile) *egress.Profile {
	return &egress.Profile{
		ID: p.Id, Name: p.Name, Enabled: p.Enabled, Priority: p.Priority,
		BackupExitPeerID: p.BackupExitPeerId,
		SourceScopeID: p.SourceScopeId, SourceCIDR: p.SourceCidr,
		Protocol: p.Protocol, DestCIDR: p.DestCidr, DestPorts: p.DestPorts,
		GeoIPCountries: p.GeoipCountries,
		ExitPeerID: p.ExitPeerId, ExitPool: p.ExitPool, ExitWeights: p.ExitWeights,
	}
}

func egressToProto(p *egress.Profile) *gmeshv1.EgressProfile {
	return &gmeshv1.EgressProfile{
		Id: p.ID, Name: p.Name, Enabled: p.Enabled, Priority: p.Priority,
		SourceScopeId: p.SourceScopeID, SourceCidr: p.SourceCIDR,
		Protocol: p.Protocol, DestCidr: p.DestCIDR, DestPorts: p.DestPorts,
		GeoipCountries: p.GeoIPCountries,
		ExitPeerId: p.ExitPeerID, ExitPool: p.ExitPool, ExitWeights: p.ExitWeights,
		BackupExitPeerId: p.BackupExitPeerID,
		CreatedAtUnix:    p.CreatedAt.Unix(),
		UpdatedAtUnix:    p.UpdatedAt.Unix(),
	}
}

// ── Scope ─────────────────────────────────────────────────────────────

// ScopeConnect builds the scope's netns + veth + WG-in-netns.
func (s *Server) ScopeConnect(ctx context.Context, in *gmeshv1.ScopeConnectRequest) (*gmeshv1.ScopeConnectResponse, error) {
	if in.ScopeId == 0 {
		return nil, status.Error(codes.InvalidArgument, "scope_id required")
	}
	if in.ScopeMeshIp == "" {
		return nil, status.Error(codes.InvalidArgument, "scope_mesh_ip required")
	}
	spec := scope.Spec{
		ScopeID:       in.ScopeId,
		Netns:         in.ScopeNetns,
		MeshIP:        in.ScopeMeshIp,
		VethCIDR:      in.VethCidr,
		VMVethIP:      in.VmVethIp,
		ScopeVethIP:   in.ScopeIp,
		GatewayMeshIP: in.GatewayMeshIp,
		ListenPort:    uint16(in.ListenPort), //nolint:gosec // bounded
	}
	p, err := s.Engine.ScopeConnect(ctx, spec)
	if err != nil {
		if err == scope.ErrAlreadyConnected {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "scope connect: %v", err)
	}
	return &gmeshv1.ScopeConnectResponse{Peer: scopePeerToProto(p)}, nil
}

// ScopeDisconnect tears the scope down.
func (s *Server) ScopeDisconnect(ctx context.Context, in *gmeshv1.ScopeDisconnectRequest) (*gmeshv1.ScopeDisconnectResponse, error) {
	if in.ScopeId == 0 {
		return nil, status.Error(codes.InvalidArgument, "scope_id required")
	}
	if err := s.Engine.ScopeDisconnect(ctx, in.ScopeId); err != nil {
		return nil, status.Errorf(codes.Internal, "scope disconnect: %v", err)
	}
	return &gmeshv1.ScopeDisconnectResponse{}, nil
}

// scopePeerToProto maps our internal scope.Peer to the gRPC Peer.
func scopePeerToProto(p *scope.Peer) *gmeshv1.Peer {
	if p == nil {
		return nil
	}
	return &gmeshv1.Peer{
		Id:         p.ID,
		Type:       gmeshv1.PeerType_PEER_TYPE_SCOPE,
		MeshIp:     p.MeshIP,
		PublicKey:  p.PublicKey,
		ScopeId:    p.ID,
		AllowedIps: []string{p.MeshIP + "/32"},
		Status:     gmeshv1.PeerStatus_PEER_STATUS_CONNECTING,
	}
}

// ── Firewall ──────────────────────────────────────────────────────────

// ApplyFirewall installs the provided rules atomically.
func (s *Server) ApplyFirewall(ctx context.Context, in *gmeshv1.ApplyFirewallRequest) (*gmeshv1.ApplyFirewallResponse, error) {
	rules := make([]firewall.Rule, 0, len(in.Rules))
	for _, r := range in.Rules {
		rules = append(rules, protoToRule(r))
	}
	applied, failed, errs := s.Engine.ApplyFirewall(ctx, rules, in.DefaultPolicy, in.ForceReset)
	resp := &gmeshv1.ApplyFirewallResponse{
		AppliedCount: int32(applied), //nolint:gosec // bounded
		FailedCount:  int32(failed),  //nolint:gosec
	}
	for _, e := range errs {
		resp.Errors = append(resp.Errors, e.Error())
	}
	return resp, nil
}

// ResetFirewall flushes gmesh rules.
func (s *Server) ResetFirewall(ctx context.Context, _ *gmeshv1.ResetFirewallRequest) (*gmeshv1.ResetFirewallResponse, error) {
	if err := s.Engine.ResetFirewall(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "reset firewall: %v", err)
	}
	return &gmeshv1.ResetFirewallResponse{}, nil
}

// GetFirewallStatus returns active rules + hit counts.
func (s *Server) GetFirewallStatus(ctx context.Context, _ *gmeshv1.GetFirewallStatusRequest) (*gmeshv1.GetFirewallStatusResponse, error) {
	backend, rules, hits, err := s.Engine.FirewallStatus(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "firewall status: %v", err)
	}
	resp := &gmeshv1.GetFirewallStatusResponse{
		Backend:     backend,
		ActiveRules: int32(len(rules)), //nolint:gosec
		HitCounts:   hits,
	}
	for _, r := range rules {
		resp.Rules = append(resp.Rules, ruleToProto(r))
	}
	return resp, nil
}

// protoToRule converts the wire format to the internal firewall.Rule.
func protoToRule(p *gmeshv1.FirewallRule) firewall.Rule {
	if p == nil {
		return firewall.Rule{}
	}
	return firewall.Rule{
		ID:          p.Id,
		Name:        p.Name,
		Enabled:     p.Enabled,
		Priority:    p.Priority,
		Action:      firewall.Action(p.Action),
		Protocol:    firewall.Protocol(p.Protocol),
		Source:      p.Source,
		Destination: p.Destination,
		PortRange:   p.PortRange,
		Direction:   firewall.ParseDirection(p.Direction),
		TCPFlags:    p.TcpFlags,
		ConnState:   p.ConnState,
		RateLimit:   p.RateLimit,
		RateBurst:   p.RateBurst,
		ScheduleRaw: p.Schedule,
		ExpiresAt:   p.ExpiresAt,
		Tags:        p.Tags,
	}
}

// ruleToProto goes the other direction.
func ruleToProto(r firewall.Rule) *gmeshv1.FirewallRule {
	dir := "inbound"
	switch r.Direction {
	case firewall.DirectionOutbound:
		dir = "outbound"
	case firewall.DirectionBoth:
		dir = "both"
	}
	return &gmeshv1.FirewallRule{
		Id:          r.ID,
		Name:        r.Name,
		Enabled:     r.Enabled,
		Priority:    r.Priority,
		Action:      gmeshv1.FirewallAction(r.Action),
		Protocol:    gmeshv1.FirewallProtocol(r.Protocol),
		Source:      r.Source,
		Destination: r.Destination,
		PortRange:   r.PortRange,
		Direction:   dir,
		TcpFlags:    r.TCPFlags,
		ConnState:   r.ConnState,
		RateLimit:   r.RateLimit,
		RateBurst:   r.RateBurst,
		Schedule:    r.ScheduleRaw,
		ExpiresAt:   r.ExpiresAt,
		Tags:        r.Tags,
	}
}

// ── Relay ──────────────────────────────────────────────────────────────

// SetupRelay dials gmesh-relay, authenticates, and repoints WG at the
// local forwarder. The relay_session_id in the request is treated as a
// string; we expect it to be either 16 bytes or a text form we hash into 16.
func (s *Server) SetupRelay(ctx context.Context, in *gmeshv1.SetupRelayRequest) (*gmeshv1.SetupRelayResponse, error) {
	if in.PeerId == 0 {
		return nil, status.Error(codes.InvalidArgument, "peer_id required")
	}
	if in.RelayEndpoint == "" {
		return nil, status.Error(codes.InvalidArgument, "relay_endpoint required")
	}

	// Build auth token. HMAC secret is loaded from Config.Relay.Secret
	// (matches gmesh-relay's `-secret` flag). Caller supplies the session
	// ID as a string; we hash it to 16 bytes so both peers in the same
	// relay session derive the same tag without coordinating a UUID wire
	// format.
	sid := sessionIDFromString(in.RelaySessionId)
	secret := []byte(s.Engine.Config.Relay.Secret)
	if len(secret) == 0 {
		return &gmeshv1.SetupRelayResponse{
			Ok:    false,
			Error: "relay.secret is not configured on this node",
		}, nil
	}
	tok := relay.SignToken(secret, sid, uint64(in.PeerId)) //nolint:gosec

	if _, err := s.Engine.SetupRelay(ctx, in.PeerId, in.RelayEndpoint, sid, tok); err != nil {
		return &gmeshv1.SetupRelayResponse{Ok: false, Error: err.Error()}, nil
	}
	return &gmeshv1.SetupRelayResponse{Ok: true}, nil
}

// AllocateWSTunnel opens a WS tunnel to backend_ws_url.
func (s *Server) AllocateWSTunnel(ctx context.Context, in *gmeshv1.AllocateWSTunnelRequest) (*gmeshv1.AllocateWSTunnelResponse, error) {
	if in.PeerId == 0 {
		return nil, status.Error(codes.InvalidArgument, "peer_id required")
	}
	if in.BackendWsUrl == "" {
		return nil, status.Error(codes.InvalidArgument, "backend_ws_url required")
	}
	if _, err := s.Engine.AllocateWSTunnel(ctx, in.PeerId, in.BackendWsUrl, nil); err != nil {
		return &gmeshv1.AllocateWSTunnelResponse{Ok: false, Error: err.Error()}, nil
	}
	return &gmeshv1.AllocateWSTunnelResponse{Ok: true}, nil
}

// sessionIDFromString hashes an opaque string into a 16-byte session ID.
// In the typical backend-driven flow, the backend already supplies 16 raw
// bytes (hex-encoded); if the string is exactly 32 hex chars we decode it,
// otherwise we take the first 16 bytes of SHA-256.
func sessionIDFromString(s string) [16]byte {
	var out [16]byte
	if len(s) == 32 {
		// Try hex.
		if b, err := hexDecode(s); err == nil && len(b) == 16 {
			copy(out[:], b)
			return out
		}
	}
	sum := sha256sum([]byte(s))
	copy(out[:], sum[:16])
	return out
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

// HolePunch runs the strategy ladder against remote_endpoint. If peer_id is
// set and known, the peer's stored remote NAT is used to pick the ladder.
func (s *Server) HolePunch(ctx context.Context, in *gmeshv1.HolePunchRequest) (*gmeshv1.HolePunchResponse, error) {
	var remoteNAT *nat.Info
	if p, ok := s.Engine.Peers.Get(in.PeerId); ok && p.NATType != 0 {
		remoteNAT = &nat.Info{Type: nat.Type(p.NATType)}
	}
	out, _, err := s.Engine.HolePunch(ctx,
		&traversal.PeerContext{
			PeerID:         in.PeerId,
			RemoteEndpoint: in.RemoteEndpoint,
			FireAtUnixMS:   in.FireAtUnixMs,
		},
		remoteNAT,
	)
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

// ── Small helpers (kept local to avoid new dependencies) ───────────────

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err1 := hexNibble(s[2*i])
		lo, err2 := hexNibble(s[2*i+1])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("hexDecode: bad char")
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("hex nibble: %q", c)
}

func sha256sum(b []byte) [32]byte {
	return sha256.Sum256(b)
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
	var eps []*gmeshv1.PeerEndpoint
	for _, e := range p.Endpoints {
		eps = append(eps, &gmeshv1.PeerEndpoint{
			Address:      e.Address,
			Type:         gmeshv1.EndpointType(e.Kind),
			Priority:     e.Priority,
			LastOkUnixMs: e.LastOK.UnixMilli(),
		})
	}
	return &gmeshv1.Peer{
		Id:                 p.ID,
		Type:               pt,
		MeshIp:             p.MeshIP,
		PublicKey:          p.PublicKey,
		Endpoint:           p.Endpoint,
		Endpoints:          eps,
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

// endpointsFromProto converts the wire candidate list into the internal
// peer.Endpoint slice. If the proto list is empty but a legacy
// `endpoint` string was provided, synthesize a single WAN candidate so
// older coordinators keep working.
func endpointsFromProto(in []*gmeshv1.PeerEndpoint, legacy string) []peer.Endpoint {
	if len(in) == 0 {
		if legacy == "" {
			return nil
		}
		return []peer.Endpoint{{
			Address:  legacy,
			Kind:     peer.EndpointKindWAN,
			Priority: 50,
		}}
	}
	out := make([]peer.Endpoint, 0, len(in))
	for _, e := range in {
		if e == nil || e.Address == "" {
			continue
		}
		prio := e.Priority
		if prio == 0 {
			// Default priorities matching the design: lan=10, wan=50,
			// stun=60, relay=100. Coordinators SHOULD set these explicitly.
			switch e.Type {
			case gmeshv1.EndpointType_ENDPOINT_LAN:
				prio = 10
			case gmeshv1.EndpointType_ENDPOINT_WAN:
				prio = 50
			case gmeshv1.EndpointType_ENDPOINT_STUN:
				prio = 60
			case gmeshv1.EndpointType_ENDPOINT_RELAY:
				prio = 100
			default:
				prio = 50
			}
		}
		out = append(out, peer.Endpoint{
			Address:  e.Address,
			Kind:     peer.EndpointKind(e.Type),
			Priority: prio,
			LastOK:   time.UnixMilli(e.LastOkUnixMs),
		})
	}
	return out
}
