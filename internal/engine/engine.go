// Package engine orchestrates the mesh lifecycle. It owns references to every
// other subsystem (wireguard, peer registry, nat discoverer, traversal, relay,
// firewall, routing, health) and exposes high-level verbs that the gRPC
// server calls in response to incoming requests.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/config"
	"github.com/mohammad2000/Gmesh/internal/crypto"
	"github.com/mohammad2000/Gmesh/internal/egress"
	"github.com/mohammad2000/Gmesh/internal/events"
	"github.com/mohammad2000/Gmesh/internal/firewall"
	"github.com/mohammad2000/Gmesh/internal/geoip"
	"github.com/mohammad2000/Gmesh/internal/health"
	"github.com/mohammad2000/Gmesh/internal/ingress"
	"github.com/mohammad2000/Gmesh/internal/nat"
	"github.com/mohammad2000/Gmesh/internal/pathmon"
	"github.com/mohammad2000/Gmesh/internal/peer"
	"github.com/mohammad2000/Gmesh/internal/policy"
	"github.com/mohammad2000/Gmesh/internal/quota"
	"github.com/mohammad2000/Gmesh/internal/relay"
	"github.com/mohammad2000/Gmesh/internal/routing"
	"github.com/mohammad2000/Gmesh/internal/scope"
	"github.com/mohammad2000/Gmesh/internal/state"
	"github.com/mohammad2000/Gmesh/internal/traversal"
	"github.com/mohammad2000/Gmesh/internal/wireguard"
)

// Responder interface decouples engine from internal/nat.Responder for tests.
type Responder interface {
	Start(ctx context.Context) error
	Stop()
}

// Engine is the central orchestrator.
type Engine struct {
	Config    *config.Config
	Log       *slog.Logger
	Peers     *peer.Registry
	NAT       *nat.Discoverer
	Responder Responder
	Trav      *traversal.Engine
	WG        wireguard.Manager
	Firewall  firewall.Backend
	Routing   routing.Manager
	Scope     scope.Manager
	Egress    egress.Manager
	Exit      egress.ExitManager
	Ingress   ingress.Manager
	Quota     quota.Manager
	Store     *state.Store
	Events    *events.Bus
	Monitor   *health.Monitor
	PathMon   *pathmon.Monitor
	GeoIP     geoip.Resolver
	Policies  *policy.Engine

	relayMu       sync.Mutex
	relaySessions map[int64]*relay.Session // peer_id → live relay session
	wsTunnels     map[int64]*relay.WSTunnel

	fwMu      sync.Mutex
	fwRules   []firewall.Rule
	fwDefault string

	// exitFailoverOriginal remembers each egress profile's original
	// exit_peer_id at the moment pathmon auto-failover kicked in, so the
	// pathUp listener can restore it when the original peer comes back.
	// Keyed by egress profile ID; value is the original peer ID.
	failoverMu           sync.Mutex
	exitFailoverOriginal map[int64]int64

	mu        sync.RWMutex
	joined    bool
	meshIP    string
	iface     string
	nodeID    string
	pubKey    string
	privKey   string
	keepalive time.Duration
}

// Options bundles the optional dependencies that vary between tests and
// production.
type Options struct {
	Log       *slog.Logger
	WG        wireguard.Manager // nil → auto-detect via wireguard.New
	Store     *state.Store      // nil → auto-create from cfg.State
	Responder Responder         // nil → real nat.Responder
	NAT       *nat.Discoverer   // nil → default with configured STUN servers
	Firewall  firewall.Backend  // nil → detect (nft → iptables → memory)
	Scope     scope.Manager     // nil → detect (Linux or stub)
	Routing   routing.Manager   // nil → detect (Linux or in-memory)
	Egress    egress.Manager    // nil → detect (Linux or stub)
	Exit      egress.ExitManager // nil → detect (Linux or stub)
	Ingress   ingress.Manager   // nil → detect (Linux or stub)
	Quota     quota.Manager     // nil → detect (Linux or stub)
	PathMon   *pathmon.Monitor  // nil → auto-built with platform prober
	GeoIP     geoip.Resolver    // nil → empty stub (no GeoIP profiles allowed)
}

// New wires an Engine together.
func New(cfg *config.Config, opts Options) (*Engine, error) {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	wg := opts.WG
	if wg == nil {
		m, err := wireguard.New(wireguard.BackendUnknown, log)
		if err != nil {
			return nil, fmt.Errorf("wireguard init: %w", err)
		}
		wg = m
	}

	store := opts.Store
	if store == nil {
		s, err := state.NewStore(cfg.State.Dir, cfg.State.File)
		if err != nil {
			return nil, fmt.Errorf("state store: %w", err)
		}
		store = s
	}

	discoverer := opts.NAT
	if discoverer == nil {
		discoverer = nat.NewDiscoverer(
			cfg.NAT.STUNServers,
			time.Duration(cfg.NAT.DiscoveryTimeoutS)*time.Second,
			time.Duration(cfg.NAT.CacheTTLSeconds)*time.Second,
		)
		discoverer.Log = log
	}

	responder := opts.Responder
	if responder == nil {
		responder = nat.NewResponder(cfg.NAT.UDPResponderPort, log)
	}

	trav := traversal.NewEngine()
	punch := traversal.UDPPuncher{}
	trav.Register(&traversal.DirectStrategy{Probe: &traversal.UDPProber{}, Log: log})
	trav.Register(&traversal.UPnPStrategy{InternalPort: cfg.WireGuard.ListenPort, Log: log})
	trav.Register(&traversal.StunHolePunchStrategy{Puncher: punch, Log: log})
	trav.Register(&traversal.SimultaneousOpenStrategy{Puncher: punch, Log: log})
	trav.Register(&traversal.BirthdayStrategy{Puncher: punch, Log: log})

	fw := opts.Firewall
	if fw == nil {
		fw = firewall.Detect(cfg.Firewall.UseNftables, cfg.Firewall.Table, cfg.Firewall.Chain, log)
	}
	sc := opts.Scope
	if sc == nil {
		sc = scope.New(log)
	}
	rt := opts.Routing
	if rt == nil {
		rt = routing.New(log)
	}
	eg := opts.Egress
	if eg == nil {
		eg = egress.New(log)
	}
	ex := opts.Exit
	if ex == nil {
		ex = egress.NewExit(log)
	}
	ig := opts.Ingress
	if ig == nil {
		ig = ingress.New(log)
	}

	bus := events.NewBus(log)

	qu := opts.Quota
	if qu == nil {
		qu = quota.New(log, &quotaBridgePublisher{bus: bus}, nil /* Switcher set after engine ready */)
	}

	pm := opts.PathMon
	if pm == nil {
		pm = pathmon.New(log, pathmon.Config{}, pathmon.NewPlatformProber(), &pathmonBridgePublisher{bus: bus})
	}

	var pol *policy.Engine
	// Policy engine is constructed here but its Actor is wired below —
	// same two-step pattern as quota.Switcher.
	pol = policy.New(nil, logShim{log})

	gi := opts.GeoIP
	if gi == nil {
		if path := cfg.GeoIP.CIDRFile; path != "" {
			csv := geoip.NewCSV(path)
			if err := csv.Load(); err != nil {
				log.Warn("geoip CSV load failed — GeoIP profiles will be rejected",
					"path", path, "error", err)
				gi = geoip.NewStub()
			} else {
				gi = csv
				log.Info("geoip CSV loaded", "path", path, "countries", len(csv.Countries()))
			}
		} else {
			gi = geoip.NewStub()
		}
	}

	e := &Engine{
		Config:        cfg,
		Log:           log,
		Peers:         peer.NewRegistry(),
		NAT:           discoverer,
		Responder:     responder,
		Trav:          trav,
		WG:            wg,
		Firewall:      fw,
		Routing:       rt,
		Scope:         sc,
		Egress:        eg,
		Exit:          ex,
		Ingress:       ig,
		Quota:         qu,
		PathMon:       pm,
		GeoIP:         gi,
		Policies:      pol,
		Store:         store,
		Events:        bus,
		relaySessions:        make(map[int64]*relay.Session),
		wsTunnels:            make(map[int64]*relay.WSTunnel),
		exitFailoverOriginal: make(map[int64]int64),
		keepalive:            time.Duration(cfg.WireGuard.KeepaliveSeconds) * time.Second,
	}

	if err := e.rehydrate(); err != nil {
		return nil, fmt.Errorf("rehydrate state: %w", err)
	}

	// Wire the quota Switcher now that the engine is fully built. The
	// quota Manager was constructed earlier without a Switcher because
	// the Engine didn't exist yet.
	if setter, ok := e.Quota.(quota.SwitcherSetter); ok {
		setter.SetSwitcher(&quotaSwitcher{e: e})
	}

	// Same pattern for the policy Actor — engine depends on itself.
	pol.Actor = &policyActor{e: e}
	if cfg.Policies.Dir != "" {
		ps, errs := policy.LoadDir(cfg.Policies.Dir)
		for _, err := range errs {
			log.Warn("policy load error", "error", err)
		}
		pol.Replace(ps)
		log.Info("policies loaded", "count", len(ps), "dir", cfg.Policies.Dir)
	}

	return e, nil
}

// rehydrate restores in-memory state from the on-disk file. Missing file = no-op.
func (e *Engine) rehydrate() error {
	st, err := e.Store.Load()
	if err != nil {
		return err
	}
	if !st.Node.Joined {
		return nil
	}
	e.mu.Lock()
	e.joined = true
	e.meshIP = st.Node.MeshIP
	e.iface = st.Node.Interface
	e.nodeID = st.Node.NodeID
	e.privKey = st.Node.PrivateKey
	e.pubKey = st.Node.PublicKey
	e.mu.Unlock()

	for _, p := range st.Peers {
		t := peer.TypeVM
		if p.Type == "scope" {
			t = peer.TypeScope
		}
		e.Peers.Upsert(&peer.Peer{
			ID:         p.ID,
			Type:       t,
			MeshIP:     p.MeshIP,
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIPs: p.AllowedIPs,
			Status:     peer.StatusConnecting, // will be refreshed by health loop
			ScopeID:    p.ScopeID,
		})
	}
	e.Log.Info("rehydrated", "peers", len(st.Peers), "mesh_ip", e.meshIP)
	return nil
}

// Start begins background loops. Canceling ctx stops them.
func (e *Engine) Start(ctx context.Context) error {
	if e.Responder != nil {
		if err := e.Responder.Start(ctx); err != nil {
			return fmt.Errorf("start udp responder: %w", err)
		}
	}
	if e.Firewall != nil {
		go e.firewallScheduler(ctx)
	}
	if e.Quota != nil {
		// 10s tick default; matches docs/roadmap-next.md.
		go e.Quota.Run(ctx, 10*time.Second)
	}
	if e.PathMon != nil {
		// Populate targets from the current peer registry and then run the
		// monitor loop. The engine does not track peer add/remove for path
		// monitoring yet — the health monitor's tick wakes it up, and new
		// peers pick up probing on the NEXT syncPathTargets call. We keep
		// that call lightweight enough to run every Monitor.Interval tick.
		e.syncPathTargets()
		// Register the auto-failover listener: on path_down for an exit
		// peer, swap any egress profile pointing at it to its
		// BackupExitPeerID; on path_up, restore.
		e.PathMon.AddListener(e.onPathTransition)
		go e.PathMon.Run(ctx)
		go e.pathTargetSyncLoop(ctx)
	}
	// Health monitor: polls peers, emits health_update + peer_connected/
	// peer_disconnected events.
	e.Monitor = health.NewMonitor(&peerSourceAdapter{e: e}, e.Events, e.Log)
	if e.Config != nil {
		if v := e.Config.Health.CheckIntervalSeconds; v > 0 {
			e.Monitor.Interval = time.Duration(v) * time.Second
		}
		if v := e.Config.Health.DegradedCheckIntervalSeconds; v > 0 {
			e.Monitor.DegradedInterval = time.Duration(v) * time.Second
		}
		if v := e.Config.Health.ReconnectFailingThreshold; v > 0 {
			e.Monitor.FailingTicksBeforeDisconnect = v
		}
	}
	go e.Monitor.Run(ctx)

	if e.Policies != nil {
		go e.runPolicyBus(ctx)
	}

	return nil
}

// emit is a small helper so we don't panic if Events is ever nil.
func (e *Engine) emit(evType string, peerID int64, payload any) {
	if e.Events != nil {
		e.Events.Publish(events.New(evType, peerID, payload))
	}
}

// peerSourceAdapter wires health.PeerSource to our engine without creating
// an import cycle between health and engine.
type peerSourceAdapter struct{ e *Engine }

func (a *peerSourceAdapter) Snapshot() []*peer.Peer {
	return a.e.Peers.Snapshot()
}
func (a *peerSourceAdapter) RefreshStats(ctx context.Context) error {
	_, err := a.e.RefreshPeerStats(ctx)
	return err
}

// Stop tears the engine down. Safe to call multiple times.
func (e *Engine) Stop(_ context.Context) error {
	if e.Responder != nil {
		e.Responder.Stop()
	}
	if e.WG != nil {
		_ = e.WG.Close()
	}
	return nil
}

// DiscoverNAT runs STUN-based NAT discovery (or returns cached result).
func (e *Engine) DiscoverNAT(ctx context.Context, forceRefresh bool) (*nat.Info, error) {
	return e.NAT.Discover(ctx, forceRefresh)
}

// SetupRelay dials the gmesh-relay server, authenticates, and hands back
// the local loopback endpoint WireGuard should dial to push traffic through
// the relay.
//
// The returned endpoint is already configured as the peer's Endpoint on the
// kernel WG interface, so no further action is needed by the caller beyond
// keeping the session alive (gmeshd owns it).
func (e *Engine) SetupRelay(ctx context.Context, peerID int64, relayAddr string, sessionID [16]byte, authToken relay.AuthToken) (*relay.Session, error) {
	e.relayMu.Lock()
	if prev, ok := e.relaySessions[peerID]; ok {
		e.relayMu.Unlock()
		_ = prev.Close()
		e.relayMu.Lock()
	}
	e.relayMu.Unlock()

	wgAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(e.Config.WireGuard.ListenPort)}
	sess, err := relay.DialSession(ctx, relay.Config{
		PeerID:     peerID,
		SessionID:  sessionID,
		AuthToken:  authToken,
		RelayAddr:  relayAddr,
		WGEndpoint: wgAddr,
		Log:        e.Log,
	})
	if err != nil {
		return nil, fmt.Errorf("dial relay: %w", err)
	}

	e.relayMu.Lock()
	e.relaySessions[peerID] = sess
	e.relayMu.Unlock()

	e.emit(events.TypeRelaySetup, peerID, map[string]any{
		"relay":          relayAddr,
		"local_endpoint": sess.LocalEndpoint().String(),
		"kind":           "udp",
	})

	// If the peer is in the registry, repoint its WG endpoint to the local
	// forwarder. Callers who pre-register the peer before calling SetupRelay
	// get transparent relay upgrade.
	if p, ok := e.Peers.Get(peerID); ok && e.IsJoined() {
		p.Endpoint = sess.LocalEndpoint().String()
		if err := e.WG.AddPeer(ctx, e.Interface(), wireguard.PeerConfig{
			PublicKey:                   p.PublicKey,
			Endpoint:                    p.Endpoint,
			AllowedIPs:                  p.AllowedIPs,
			PersistentKeepaliveInterval: e.keepalive,
		}); err != nil {
			e.Log.Warn("retarget WG peer to relay failed", "peer_id", peerID, "error", err)
		}
	}
	return sess, nil
}

// RelaySession returns the active relay Session for peerID, if any.
func (e *Engine) RelaySession(peerID int64) *relay.Session {
	e.relayMu.Lock()
	defer e.relayMu.Unlock()
	return e.relaySessions[peerID]
}

// TeardownRelay closes an active relay session. Idempotent.
func (e *Engine) TeardownRelay(peerID int64) {
	e.relayMu.Lock()
	sess := e.relaySessions[peerID]
	delete(e.relaySessions, peerID)
	e.relayMu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}
}

// ── Quota (Phase 13) ─────────────────────────────────────────────────

// CreateQuota installs a byte-quota policy.
func (e *Engine) CreateQuota(ctx context.Context, q *quota.Quota) (*quota.Quota, error) {
	return e.Quota.Create(ctx, q)
}

// UpdateQuota modifies an existing quota.
func (e *Engine) UpdateQuota(ctx context.Context, q *quota.Quota) (*quota.Quota, error) {
	return e.Quota.Update(ctx, q)
}

// DeleteQuota removes a quota.
func (e *Engine) DeleteQuota(ctx context.Context, id int64) error {
	return e.Quota.Delete(ctx, id)
}

// ListQuotas returns a snapshot.
func (e *Engine) ListQuotas() []*quota.Quota { return e.Quota.List() }

// GetQuotaUsage returns current live counters (one or all).
func (e *Engine) GetQuotaUsage(ctx context.Context, id int64) []*quota.Quota {
	// Force a tick so callers get fresh data.
	_ = e.Quota.Tick(ctx)
	if id == 0 {
		return e.Quota.List()
	}
	q, ok := e.Quota.Get(id)
	if !ok {
		return nil
	}
	return []*quota.Quota{q}
}

// ResetQuota zeroes a quota's counter and clears latches.
func (e *Engine) ResetQuota(ctx context.Context, id int64) error {
	return e.Quota.Reset(ctx, id)
}

// quotaBridgePublisher adapts events.Bus to quota.Publisher.
type quotaBridgePublisher struct{ bus *events.Bus }

func (q *quotaBridgePublisher) Publish(ev quota.Event) {
	// Our generic Event types live in internal/events; quota types map 1:1.
	q.bus.Publish(events.Event{
		Type:    ev.Type, // "quota_warning" etc.
		Payload: marshalJSONSilent(ev.Payload),
	})
}

// quotaSwitcher is the engine-backed Switcher wired after engine.New.
type quotaSwitcher struct{ e *Engine }

// SwapExitPeer implements quota.Switcher. Returns the profile's previous
// exit_peer_id so the quota Manager can remember it for auto_rollback.
func (s *quotaSwitcher) SwapExitPeer(ctx context.Context, egressProfileID, newExitPeerID int64) (int64, error) {
	profs := s.e.Egress.List()
	var target *egress.Profile
	for _, p := range profs {
		if p.ID == egressProfileID {
			target = p
			break
		}
	}
	if target == nil {
		return 0, fmt.Errorf("quota switcher: egress profile %d not found", egressProfileID)
	}
	prev := target.ExitPeerID
	target.ExitPeerID = newExitPeerID
	_, err := s.e.UpdateEgress(ctx, target)
	if err != nil {
		return 0, err
	}
	return prev, nil
}

// marshalJSONSilent returns json.Marshal(v) or nil on error.
func marshalJSONSilent(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// pathmonBridgePublisher adapts events.Bus to pathmon.Publisher so the
// path monitor's path_up / path_down events land on the main bus.
type pathmonBridgePublisher struct{ bus *events.Bus }

func (p *pathmonBridgePublisher) Publish(ev pathmon.Event) {
	p.bus.Publish(events.Event{
		Type:   ev.Type, // "path_up" | "path_down"
		PeerID: ev.PeerID,
		Payload: marshalJSONSilent(map[string]any{
			"mesh_ip":  ev.MeshIP,
			"rtt_ms":   ev.RTT.Milliseconds(),
			"loss_pct": ev.LossPct,
			"at_unix":  ev.At.Unix(),
		}),
	})
}

// ── Ingress profiles (Phase 12) ───────────────────────────────────────

// CreateIngress installs a DNAT profile so inbound traffic on this edge
// peer reaches the configured backend through the mesh.
func (e *Engine) CreateIngress(ctx context.Context, p *ingress.Profile) (*ingress.Profile, error) {
	res, err := e.Ingress.Create(ctx, p)
	if err != nil {
		return nil, err
	}
	e.emit(events.TypeScopeConnected, p.BackendScopeID, map[string]any{
		"kind":           "ingress_profile",
		"profile_id":     res.ID,
		"profile_name":   res.Name,
		"edge_port":      res.EdgePort,
		"backend":        fmt.Sprintf("%s:%d", res.BackendIP, res.BackendPort),
		"backend_peer":   res.BackendPeerID,
	})
	return res, nil
}

// UpdateIngress re-installs a profile.
func (e *Engine) UpdateIngress(ctx context.Context, p *ingress.Profile) (*ingress.Profile, error) {
	return e.Ingress.Update(ctx, p)
}

// DeleteIngress removes a profile.
func (e *Engine) DeleteIngress(ctx context.Context, profileID int64) error {
	return e.Ingress.Delete(ctx, profileID)
}

// ListIngress returns a snapshot.
func (e *Engine) ListIngress() []*ingress.Profile { return e.Ingress.List() }

// ── Egress profiles (Phase 11) ────────────────────────────────────────

// CreateEgress installs an egress profile. Looks up the exit peer's mesh
// IP from the registry so the manager can build the route table.
func (e *Engine) CreateEgress(ctx context.Context, p *egress.Profile) (*egress.Profile, error) {
	if err := e.resolveGeoIP(p); err != nil {
		return nil, err
	}
	if err := e.resolveExitPool(p); err != nil {
		return nil, err
	}
	exitIP := ""
	if len(p.ExitPool) == 0 {
		ip, err := e.exitPeerMeshIP(p.ExitPeerID)
		if err != nil {
			return nil, err
		}
		exitIP = ip
	}
	iface := e.Interface()
	if iface == "" {
		iface = e.Config.WireGuard.Interface
	}
	res, err := e.Egress.Create(ctx, p, exitIP, iface)
	if err != nil {
		return nil, err
	}
	e.emit(events.TypePeerAdded, p.ExitPeerID, map[string]any{
		"kind":          "egress_profile",
		"profile_id":    res.ID,
		"profile_name":  res.Name,
		"source":        res.Source(),
		"exit_peer_id":  res.ExitPeerID,
	})
	return res, nil
}

// UpdateEgress re-installs an existing profile.
func (e *Engine) UpdateEgress(ctx context.Context, p *egress.Profile) (*egress.Profile, error) {
	if err := e.resolveGeoIP(p); err != nil {
		return nil, err
	}
	if err := e.resolveExitPool(p); err != nil {
		return nil, err
	}
	exitIP := ""
	if len(p.ExitPool) == 0 {
		ip, err := e.exitPeerMeshIP(p.ExitPeerID)
		if err != nil {
			return nil, err
		}
		exitIP = ip
	}
	iface := e.Interface()
	if iface == "" {
		iface = e.Config.WireGuard.Interface
	}
	return e.Egress.Update(ctx, p, exitIP, iface)
}

// DeleteEgress removes a profile. Idempotent.
func (e *Engine) DeleteEgress(ctx context.Context, profileID int64) error {
	return e.Egress.Delete(ctx, profileID)
}

// ListEgress returns a snapshot of installed profiles.
func (e *Engine) ListEgress() []*egress.Profile { return e.Egress.List() }

// EnableExit turns this node into an exit peer for mesh traffic.
func (e *Engine) EnableExit(ctx context.Context, allowed []int64) error {
	iface := e.Interface()
	if iface == "" {
		iface = e.Config.WireGuard.Interface
	}
	return e.Exit.Enable(ctx, iface, allowed)
}

// DisableExit stops acting as an exit peer.
func (e *Engine) DisableExit(ctx context.Context) error { return e.Exit.Disable(ctx) }

// exitPeerMeshIP returns the mesh_ip string for the given exit peer ID.
// Falls back to a recognisable placeholder on the stub backend where no
// peers are actually registered.
func (e *Engine) exitPeerMeshIP(peerID int64) (string, error) {
	if peerID == 0 {
		return "", fmt.Errorf("egress: exit_peer_id=0")
	}
	p, ok := e.Peers.Get(peerID)
	if !ok {
		return "", fmt.Errorf("egress: exit peer %d not in registry", peerID)
	}
	if p.MeshIP == "" {
		return "", fmt.Errorf("egress: exit peer %d has empty mesh_ip", peerID)
	}
	return p.MeshIP, nil
}

// ── Scope peers ───────────────────────────────────────────────────────

// ScopeConnect builds the netns + veth + in-netns WG for a scope and adds
// its /32 route if we're joined to the mesh.
func (e *Engine) ScopeConnect(ctx context.Context, spec scope.Spec) (*scope.Peer, error) {
	p, err := e.Scope.Connect(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("scope connect: %w", err)
	}
	// Register the scope as a peer in our local registry so ListPeers and
	// HolePunch see it too. The scope's WG identity lives in its own netns;
	// from the engine's POV it's just another peer.
	pr := &peer.Peer{
		ID:         spec.ScopeID,
		Type:       peer.TypeScope,
		MeshIP:     spec.MeshIP,
		PublicKey:  p.PublicKey,
		Status:     peer.StatusConnecting,
		ScopeID:    spec.ScopeID,
		AllowedIPs: []string{spec.MeshIP + "/32"},
	}
	e.Peers.Upsert(pr)

	if e.IsJoined() && e.Routing != nil {
		if err := e.Routing.Ensure(ctx, spec.MeshIP, e.Interface()); err != nil {
			e.Log.Warn("scope route install failed", "error", err, "mesh_ip", spec.MeshIP)
		}
	}
	e.emit(events.TypeScopeConnected, spec.ScopeID, map[string]any{
		"mesh_ip":     spec.MeshIP,
		"netns":       p.Netns,
		"public_key":  p.PublicKey,
		"listen_port": p.ListenPort,
	})
	return p, nil
}

// ScopeDisconnect tears down the scope's networking and removes it from
// our peer registry + routing table.
func (e *Engine) ScopeDisconnect(ctx context.Context, scopeID int64) error {
	if err := e.Scope.Disconnect(ctx, scopeID); err != nil && err != scope.ErrNotConnected {
		return fmt.Errorf("scope disconnect: %w", err)
	}
	if p, ok := e.Peers.Get(scopeID); ok && e.Routing != nil {
		_ = e.Routing.Remove(ctx, p.MeshIP, e.Interface())
	}
	e.Peers.Remove(scopeID)
	e.emit(events.TypeScopeDisconnected, scopeID, nil)
	return nil
}

// ScopeList returns all active scope peers.
func (e *Engine) ScopeList() []*scope.Peer {
	if e.Scope == nil {
		return nil
	}
	return e.Scope.List()
}

// ── Firewall ──────────────────────────────────────────────────────────

// ApplyFirewall installs rules via the active backend. Remembers them in
// engine state so scheduled re-evaluation can re-apply when windows change.
func (e *Engine) ApplyFirewall(ctx context.Context, rules []firewall.Rule, defaultPolicy string, forceReset bool) (int, int, []error) {
	if e.Firewall == nil {
		return 0, 0, []error{errors.New("engine: firewall backend not configured")}
	}
	if forceReset {
		_ = e.Firewall.Reset(ctx)
	}
	if err := e.Firewall.Ensure(ctx); err != nil {
		return 0, len(rules), []error{err}
	}
	e.fwMu.Lock()
	e.fwRules = append(e.fwRules[:0], rules...)
	e.fwDefault = defaultPolicy
	e.fwMu.Unlock()
	applied, failed, errs := e.Firewall.Apply(ctx, rules, defaultPolicy)
	errStrs := make([]string, 0, len(errs))
	for _, er := range errs {
		errStrs = append(errStrs, er.Error())
	}
	evType := events.TypeFirewallApplied
	if failed > 0 {
		evType = events.TypeFirewallError
	}
	e.emit(evType, 0, map[string]any{
		"applied": applied,
		"failed":  failed,
		"errors":  errStrs,
		"backend": e.Firewall.Name(),
	})
	return applied, failed, errs
}

// ResetFirewall flushes the gmesh table.
func (e *Engine) ResetFirewall(ctx context.Context) error {
	if e.Firewall == nil {
		return errors.New("engine: firewall backend not configured")
	}
	e.fwMu.Lock()
	e.fwRules = nil
	e.fwDefault = ""
	e.fwMu.Unlock()
	return e.Firewall.Reset(ctx)
}

// FirewallStatus returns (backend name, live rules, hit counts).
func (e *Engine) FirewallStatus(ctx context.Context) (string, []firewall.Rule, map[int64]int64, error) {
	if e.Firewall == nil {
		return "", nil, nil, errors.New("engine: firewall backend not configured")
	}
	rules, err := e.Firewall.List(ctx)
	if err != nil {
		return e.Firewall.Name(), nil, nil, err
	}
	hits, _ := e.Firewall.HitCounts(ctx)
	return e.Firewall.Name(), rules, hits, nil
}

// firewallScheduler periodically re-applies the ruleset so rules with
// scheduled windows flip on and off at the right times. Cheap: only
// triggers re-apply when the set of live IDs changes.
func (e *Engine) firewallScheduler(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	var lastLive map[int64]bool
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			e.fwMu.Lock()
			rules := append([]firewall.Rule(nil), e.fwRules...)
			policy := e.fwDefault
			e.fwMu.Unlock()
			if len(rules) == 0 {
				continue
			}
			live := firewall.FilterLive(rules, now)
			cur := make(map[int64]bool, len(live))
			for _, r := range live {
				cur[r.ID] = true
			}
			if sameSet(cur, lastLive) {
				continue
			}
			if _, _, errs := e.Firewall.Apply(ctx, rules, policy); len(errs) > 0 {
				e.Log.Warn("firewall schedule re-apply failed", "errors", len(errs))
			} else {
				e.Log.Info("firewall schedule re-applied", "live", len(live))
			}
			lastLive = cur
		}
	}
}

func sameSet(a, b map[int64]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// AllocateWSTunnel opens a WebSocket tunnel through the backend's
// /ws/relay/{session_id}/{peer_id} endpoint. Used when UDP to gmesh-relay
// is blocked.
func (e *Engine) AllocateWSTunnel(ctx context.Context, peerID int64, url string, httpHeader map[string]string) (*relay.WSTunnel, error) {
	e.relayMu.Lock()
	if prev, ok := e.wsTunnels[peerID]; ok {
		e.relayMu.Unlock()
		_ = prev.Close()
		e.relayMu.Lock()
	}
	e.relayMu.Unlock()

	wgAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(e.Config.WireGuard.ListenPort)}
	t, err := relay.DialWSTunnel(ctx, relay.WSTunnelConfig{
		PeerID:     peerID,
		URL:        url,
		WGEndpoint: wgAddr,
		HTTPHeader: httpHeader,
		Log:        e.Log,
	})
	if err != nil {
		return nil, err
	}
	e.relayMu.Lock()
	e.wsTunnels[peerID] = t
	e.relayMu.Unlock()

	e.emit(events.TypeRelaySetup, peerID, map[string]any{
		"url":            url,
		"local_endpoint": t.LocalEndpoint().String(),
		"kind":           "ws",
	})

	if p, ok := e.Peers.Get(peerID); ok && e.IsJoined() {
		p.Endpoint = t.LocalEndpoint().String()
		if err := e.WG.AddPeer(ctx, e.Interface(), wireguard.PeerConfig{
			PublicKey:                   p.PublicKey,
			Endpoint:                    p.Endpoint,
			AllowedIPs:                  p.AllowedIPs,
			PersistentKeepaliveInterval: e.keepalive,
		}); err != nil {
			e.Log.Warn("retarget WG peer to ws tunnel failed", "peer_id", peerID, "error", err)
		}
	}
	return t, nil
}

// HolePunch runs the full strategy ladder selected from local + remote NAT.
// If remoteNAT is nil, the ladder falls back to "both unknown" which tries
// every method.
func (e *Engine) HolePunch(ctx context.Context, pc *traversal.PeerContext, remoteNAT *nat.Info) (*traversal.Outcome, []*traversal.Outcome, error) {
	local := nat.Unknown
	if li := e.NAT.Cached(); li != nil {
		local = li.Type
	}
	remote := nat.Unknown
	if remoteNAT != nil {
		remote = remoteNAT.Type
	}
	ladder := traversal.SelectLadder(traversal.Classification{Local: local, Remote: remote})
	return e.Trav.Run(ctx, ladder, pc)
}

// IsJoined reports whether Join() has been called.
func (e *Engine) IsJoined() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.joined
}

// MeshIP returns this node's assigned mesh IP.
func (e *Engine) MeshIP() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.meshIP
}

// Interface returns the WG interface name.
func (e *Engine) Interface() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.iface
}

// PublicKey returns this node's WG public key (empty before Join).
func (e *Engine) PublicKey() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.pubKey
}

// ── Lifecycle ──────────────────────────────────────────────────────────

// JoinResult is the outcome of a successful Join.
type JoinResult struct {
	PublicKey  string
	PrivateKey string // raw base64; caller is responsible for encrypting before sending over the wire
}

// Join generates keys, brings up the WG interface, and marks this node as joined.
func (e *Engine) Join(ctx context.Context, meshIP, iface string, listenPort uint16, networkCIDR, nodeID string) (*JoinResult, error) {
	e.mu.Lock()
	if e.joined {
		e.mu.Unlock()
		return nil, ErrAlreadyJoined
	}
	e.mu.Unlock()

	// Generate keypair.
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	// Build "meshIP/prefix" from network CIDR (e.g. 10.200.0.7/16).
	addrCIDR := meshIP
	if prefix := maskFromCIDR(networkCIDR); prefix != "" {
		addrCIDR = meshIP + "/" + prefix
	}

	// Bring up interface.
	if err := e.WG.CreateInterface(ctx, iface, addrCIDR, int(e.Config.WireGuard.MTU), listenPort); err != nil {
		return nil, fmt.Errorf("create interface: %w", err)
	}
	if err := e.WG.SetPrivateKey(ctx, iface, kp.Private); err != nil {
		// Best-effort cleanup.
		_ = e.WG.DeleteInterface(ctx, iface)
		return nil, fmt.Errorf("set private key: %w", err)
	}

	e.mu.Lock()
	e.joined = true
	e.meshIP = meshIP
	e.iface = iface
	e.nodeID = nodeID
	e.privKey = kp.Private
	e.pubKey = kp.Public
	e.mu.Unlock()

	if err := e.persist(); err != nil {
		e.Log.Warn("persist after Join failed", "error", err)
	}

	e.Log.Info("joined mesh",
		"mesh_ip", meshIP,
		"interface", iface,
		"listen_port", listenPort,
		"public_key", kp.Public,
	)

	e.emit(events.TypeMeshJoined, 0, map[string]any{
		"mesh_ip":     meshIP,
		"interface":   iface,
		"listen_port": listenPort,
		"public_key":  kp.Public,
		"node_id":     nodeID,
	})
	return &JoinResult{PublicKey: kp.Public, PrivateKey: kp.Private}, nil
}

// Leave tears down WireGuard and clears registry.
func (e *Engine) Leave(ctx context.Context, reason string) error {
	e.mu.Lock()
	joined := e.joined
	iface := e.iface
	e.mu.Unlock()

	if !joined {
		return nil
	}

	if err := e.WG.DeleteInterface(ctx, iface); err != nil {
		e.Log.Warn("delete interface failed", "error", err, "iface", iface)
	}

	e.mu.Lock()
	e.joined = false
	e.meshIP = ""
	e.iface = ""
	e.nodeID = ""
	e.privKey = ""
	e.pubKey = ""
	e.mu.Unlock()

	// Clear peer registry and persist.
	for _, p := range e.Peers.Snapshot() {
		e.Peers.Remove(p.ID)
	}
	if err := e.persist(); err != nil {
		e.Log.Warn("persist after Leave failed", "error", err)
	}

	e.Log.Info("left mesh", "reason", reason)
	e.emit(events.TypeMeshLeft, 0, map[string]any{"reason": reason})
	return nil
}

// ── Peers ──────────────────────────────────────────────────────────────

// AddPeer installs a peer on the WG interface and registers it.
func (e *Engine) AddPeer(ctx context.Context, p *peer.Peer, keepaliveOverride time.Duration) error {
	if !e.IsJoined() {
		return ErrNotJoined
	}
	ka := e.keepalive
	if keepaliveOverride > 0 {
		ka = keepaliveOverride
	}
	if err := e.WG.AddPeer(ctx, e.Interface(), wireguard.PeerConfig{
		PublicKey:                   p.PublicKey,
		Endpoint:                    p.Endpoint,
		AllowedIPs:                  p.AllowedIPs,
		PersistentKeepaliveInterval: ka,
	}); err != nil {
		return fmt.Errorf("wg add peer: %w", err)
	}
	e.Peers.Upsert(p)
	if e.Routing != nil && p.MeshIP != "" {
		if err := e.Routing.Ensure(ctx, p.MeshIP, e.Interface()); err != nil {
			e.Log.Warn("peer route install failed", "error", err, "mesh_ip", p.MeshIP)
		}
	}
	if err := e.persist(); err != nil {
		e.Log.Warn("persist after AddPeer failed", "error", err)
	}
	e.emit(events.TypePeerAdded, p.ID, map[string]any{
		"mesh_ip":    p.MeshIP,
		"endpoint":   p.Endpoint,
		"public_key": p.PublicKey,
	})
	return nil
}

// RemovePeer removes a peer from WG and from the registry.
func (e *Engine) RemovePeer(ctx context.Context, peerID int64) error {
	p, ok := e.Peers.Get(peerID)
	if !ok {
		return ErrPeerNotFound
	}
	if err := e.WG.RemovePeer(ctx, e.Interface(), p.PublicKey); err != nil {
		return fmt.Errorf("wg remove peer: %w", err)
	}
	e.Peers.Remove(peerID)
	if e.Routing != nil && p.MeshIP != "" {
		_ = e.Routing.Remove(ctx, p.MeshIP, e.Interface())
	}
	if err := e.persist(); err != nil {
		e.Log.Warn("persist after RemovePeer failed", "error", err)
	}
	e.emit(events.TypePeerRemoved, peerID, map[string]any{"mesh_ip": p.MeshIP})
	return nil
}

// UpdatePeer changes endpoint / allowed_ips / keepalive for an existing peer.
func (e *Engine) UpdatePeer(ctx context.Context, peerID int64, endpoint string, allowedIPs []string, keepalive time.Duration) error {
	p, ok := e.Peers.Get(peerID)
	if !ok {
		return ErrPeerNotFound
	}
	if endpoint != "" {
		p.Endpoint = endpoint
	}
	if allowedIPs != nil {
		p.AllowedIPs = allowedIPs
	}
	ka := e.keepalive
	if keepalive > 0 {
		ka = keepalive
	}
	if err := e.WG.AddPeer(ctx, e.Interface(), wireguard.PeerConfig{
		PublicKey:                   p.PublicKey,
		Endpoint:                    p.Endpoint,
		AllowedIPs:                  p.AllowedIPs,
		PersistentKeepaliveInterval: ka,
	}); err != nil {
		return fmt.Errorf("wg update peer: %w", err)
	}
	e.Peers.Upsert(p)
	if err := e.persist(); err != nil {
		e.Log.Warn("persist after UpdatePeer failed", "error", err)
	}
	return nil
}

// RefreshPeerStats pulls live stats from the WG interface and updates each
// peer in the registry. Returns the merged list.
func (e *Engine) RefreshPeerStats(ctx context.Context) ([]*peer.Peer, error) {
	if !e.IsJoined() {
		return e.Peers.Snapshot(), nil
	}
	dumps, err := e.WG.ListPeers(ctx, e.Interface())
	if err != nil {
		return nil, err
	}
	// Map dumps by public key for fast lookup.
	byKey := make(map[string]wireguard.PeerDump, len(dumps))
	for _, d := range dumps {
		byKey[d.PublicKey] = d
	}
	for _, p := range e.Peers.Snapshot() {
		d, ok := byKey[p.PublicKey]
		if !ok {
			continue
		}
		p.LastHandshake = d.LastHandshake
		p.RxBytes = d.RxBytes
		p.TxBytes = d.TxBytes
		if !d.LastHandshake.IsZero() && time.Since(d.LastHandshake) < 3*time.Minute {
			p.Status = peer.StatusConnected
		}
	}
	return e.Peers.Snapshot(), nil
}

// ── State persistence ──────────────────────────────────────────────────

func (e *Engine) persist() error {
	e.mu.RLock()
	st := state.State{
		Node: state.NodeState{
			MeshIP:     e.meshIP,
			Interface:  e.iface,
			ListenPort: e.Config.WireGuard.ListenPort,
			PrivateKey: e.privKey,
			PublicKey:  e.pubKey,
			NodeID:     e.nodeID,
			Joined:     e.joined,
		},
	}
	e.mu.RUnlock()

	for _, p := range e.Peers.Snapshot() {
		t := "vm"
		if p.Type == peer.TypeScope {
			t = "scope"
		}
		st.Peers = append(st.Peers, state.PeerEntry{
			ID:         p.ID,
			Type:       t,
			MeshIP:     p.MeshIP,
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIPs: p.AllowedIPs,
			ScopeID:    p.ScopeID,
		})
	}
	return e.Store.Save(&st)
}

// ── Errors ─────────────────────────────────────────────────────────────

var (
	ErrAlreadyJoined = errors.New("engine: already joined")
	ErrNotJoined     = errors.New("engine: not joined")
	ErrPeerNotFound  = errors.New("engine: peer not found")
)

// policyActor adapts the engine to policy.Actor. Kept thin — each
// method just delegates to an existing Engine verb.
type policyActor struct{ e *Engine }

func (a *policyActor) SwapExitPeer(ctx context.Context, profileID, newExitPeerID int64) error {
	profs := a.e.Egress.List()
	for _, p := range profs {
		if p.ID == profileID {
			p.ExitPeerID = newExitPeerID
			_, err := a.e.UpdateEgress(ctx, p)
			return err
		}
	}
	return fmt.Errorf("policy actor: egress profile %d not found", profileID)
}

func (a *policyActor) SetProfileEnabled(ctx context.Context, profileID int64, enabled bool) error {
	profs := a.e.Egress.List()
	for _, p := range profs {
		if p.ID == profileID {
			p.Enabled = enabled
			_, err := a.e.UpdateEgress(ctx, p)
			return err
		}
	}
	return fmt.Errorf("policy actor: egress profile %d not found", profileID)
}

func (a *policyActor) ResetQuota(ctx context.Context, quotaID int64) error {
	return a.e.ResetQuota(ctx, quotaID)
}

// logShim adapts slog.Logger to policy.Logger. Keeps the policy package
// free of a slog dependency.
type logShim struct{ l *slog.Logger }

func (s logShim) Debug(msg string, args ...any) { s.l.Debug(msg, args...) }
func (s logShim) Info(msg string, args ...any)  { s.l.Info(msg, args...) }
func (s logShim) Warn(msg string, args ...any)  { s.l.Warn(msg, args...) }

// runPolicyBus subscribes to the event bus and feeds each event into
// the policy engine. Runs until ctx is canceled.
func (e *Engine) runPolicyBus(ctx context.Context) {
	if e.Events == nil || e.Policies == nil {
		return
	}
	// Subscribe to every type — the policy engine filters by When.Event.
	ch, cancel := e.Events.Subscribe(nil, 64)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			pe := policy.Event{
				Type:      ev.Type,
				PeerID:    ev.PeerID,
				Timestamp: ev.Timestamp,
			}
			// Best-effort extract of egress_profile_id from quota / path events.
			if len(ev.Payload) > 0 {
				var probe struct {
					EgressProfileID int64 `json:"egress_profile_id"`
				}
				if err := json.Unmarshal(ev.Payload, &probe); err == nil {
					pe.ProfileID = probe.EgressProfileID
				}
			}
			e.Policies.OnEvent(ctx, pe)
		}
	}
}

// resolveExitPool fills ExitPoolMeshIPs from the peer registry so the
// Linux backend can install one route table per pool entry. No-op when
// the profile isn't using a pool.
func (e *Engine) resolveExitPool(p *egress.Profile) error {
	if len(p.ExitPool) == 0 {
		return nil
	}
	p.ExitPoolMeshIPs = make([]string, len(p.ExitPool))
	for i, peerID := range p.ExitPool {
		ip, err := e.exitPeerMeshIP(peerID)
		if err != nil {
			return fmt.Errorf("resolve exit_pool[%d] peer=%d: %w", i, peerID, err)
		}
		p.ExitPoolMeshIPs[i] = ip
	}
	return nil
}

// resolveGeoIP fills p.GeoIPCIDRs from p.GeoIPCountries using e.GeoIP.
// No-op when the profile doesn't use GeoIP. Returns an error if any
// requested country is unknown to the resolver.
func (e *Engine) resolveGeoIP(p *egress.Profile) error {
	if len(p.GeoIPCountries) == 0 {
		return nil
	}
	if e.GeoIP == nil {
		return fmt.Errorf("egress: geoip_countries set but no GeoIP resolver configured")
	}
	if err := geoip.Validate(e.GeoIP, p.GeoIPCountries); err != nil {
		return err
	}
	p.GeoIPCIDRs = geoip.CollectCIDRs(e.GeoIP, p.GeoIPCountries)
	return nil
}

// maskFromCIDR extracts "16" from "10.200.0.0/16". Returns "" if parse fails.
func maskFromCIDR(cidr string) string {
	for i := len(cidr) - 1; i >= 0; i-- {
		if cidr[i] == '/' {
			return cidr[i+1:]
		}
	}
	return ""
}

// syncPathTargets copies the current peer registry into the PathMon
// target list. Called at Start and on every health interval so newly
// added peers show up in the monitor without us wiring a subscription.
func (e *Engine) syncPathTargets() {
	if e.PathMon == nil || e.Peers == nil {
		return
	}
	wanted := make(map[int64]bool)
	for _, p := range e.Peers.Snapshot() {
		if p.MeshIP == "" {
			continue
		}
		wanted[p.ID] = true
		_ = e.PathMon.AddTarget(pathmon.Target{
			PeerID: p.ID, Name: p.MeshIP, MeshIP: p.MeshIP, Kind: "peer",
		})
	}
	for _, st := range e.PathMon.List() {
		if !wanted[st.Target.PeerID] {
			e.PathMon.RemoveTarget(st.Target.PeerID)
		}
	}
}

// pathTargetSyncLoop keeps PathMon's target set in line with the peer
// registry. Runs at 30s — new-peer latency is acceptable at that rate.
func (e *Engine) pathTargetSyncLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.syncPathTargets()
		}
	}
}

// onPathTransition is wired as a PathMon listener. It drives health-based
// egress failover using the BackupExitPeerID field on each profile:
//
//   - path_down(peer=P): for every egress profile whose ExitPeerID==P
//     AND BackupExitPeerID!=0, swap ExitPeerID to BackupExitPeerID.
//   - path_up(peer=P):   for every egress profile whose BackupExitPeerID==P?
//     No — we need the INVERSE: find profiles that previously shifted
//     AWAY from P and restore them. We detect that as ExitPeerID!=P and
//     BackupExitPeerID==current_exit_peer (i.e. the two values are
//     currently swapped). To avoid ambiguity the restore keys on an
//     internal markmap we keep: shiftedAway[profileID] = originalPeer.
//
// The listener runs synchronously in the pathmon goroutine; we kick off
// the actual Swap in a background goroutine to keep the listener fast
// and avoid deadlocks with engine mutexes during egress Update.
func (e *Engine) onPathTransition(_ context.Context, ev pathmon.Event) {
	go func() {
		tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		switch ev.Type {
		case "path_down":
			e.failoverDown(tctx, ev.PeerID)
		case "path_up":
			e.failoverUp(tctx, ev.PeerID)
		}
	}()
}

// failoverDown swaps any egress profile currently routing through
// peerID to its BackupExitPeerID. Remembers the previous peer in
// Engine.exitFailoverOriginal for later restore.
func (e *Engine) failoverDown(ctx context.Context, peerID int64) {
	profs := e.Egress.List()
	for _, p := range profs {
		if p.ExitPeerID != peerID || p.BackupExitPeerID == 0 {
			continue
		}
		e.failoverMu.Lock()
		e.exitFailoverOriginal[p.ID] = peerID
		e.failoverMu.Unlock()

		p.ExitPeerID = p.BackupExitPeerID
		if _, err := e.UpdateEgress(ctx, p); err != nil {
			e.Log.Warn("path failover swap failed",
				"profile", p.ID, "from_peer", peerID,
				"to_peer", p.BackupExitPeerID, "error", err)
			continue
		}
		e.Log.Info("path failover engaged",
			"profile", p.ID, "from_peer", peerID,
			"to_peer", p.BackupExitPeerID)
		if e.Events != nil {
			e.Events.Publish(events.Event{
				Type:   "path_failover",
				PeerID: peerID,
				Payload: marshalJSONSilent(map[string]any{
					"egress_profile_id": p.ID,
					"from_peer":         peerID,
					"to_peer":           p.BackupExitPeerID,
					"reason":            "path_down",
				}),
			})
		}
	}
}

// failoverUp restores any egress profile that had been failed-over
// AWAY from peerID, bringing ExitPeerID back to peerID.
func (e *Engine) failoverUp(ctx context.Context, peerID int64) {
	e.failoverMu.Lock()
	restores := make([]int64, 0)
	for profID, orig := range e.exitFailoverOriginal {
		if orig == peerID {
			restores = append(restores, profID)
		}
	}
	e.failoverMu.Unlock()
	if len(restores) == 0 {
		return
	}
	profs := e.Egress.List()
	byID := make(map[int64]*egress.Profile, len(profs))
	for _, p := range profs {
		byID[p.ID] = p
	}
	for _, pid := range restores {
		p, ok := byID[pid]
		if !ok {
			e.failoverMu.Lock()
			delete(e.exitFailoverOriginal, pid)
			e.failoverMu.Unlock()
			continue
		}
		p.ExitPeerID = peerID
		if _, err := e.UpdateEgress(ctx, p); err != nil {
			e.Log.Warn("path failover restore failed",
				"profile", pid, "to_peer", peerID, "error", err)
			continue
		}
		e.failoverMu.Lock()
		delete(e.exitFailoverOriginal, pid)
		e.failoverMu.Unlock()
		e.Log.Info("path failover restored",
			"profile", pid, "to_peer", peerID)
		if e.Events != nil {
			e.Events.Publish(events.Event{
				Type:   "path_restore",
				PeerID: peerID,
				Payload: marshalJSONSilent(map[string]any{
					"egress_profile_id": pid,
					"to_peer":           peerID,
					"reason":            "path_up",
				}),
			})
		}
	}
}
