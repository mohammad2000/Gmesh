# Roadmap

Phased delivery. Each phase ends with a working, testable deliverable.

## Phase 0 — Scaffold ✅

- [x] Repo layout, Go module, Makefile
- [x] Proto definition + generated code
- [x] Binary entry points (gmeshd / gmeshctl / gmesh-relay)
- [x] Internal package stubs with clear interfaces
- [x] systemd unit + .deb packaging skeleton
- [x] CI (build + test + lint + .deb artifact)
- [x] Architecture docs

## Phase 1 — Core WireGuard

- [ ] `wireguard.Manager` kernel backend via wgctrl
- [ ] Userspace wireguard-go fallback
- [ ] Interface create / destroy / up / down
- [ ] Key generation + Fernet encryption of private key
- [ ] Peer add / remove / update / list
- [ ] State persistence (`/var/lib/gmesh/state.json`)
- [ ] `gmeshctl peer` subcommands
- [ ] Unit tests for WG manager (mock backend)

**Exit criteria:** two gmeshd instances on the same LAN can be made to handshake
by manually issuing `AddPeer` RPCs with known endpoints. `gmeshctl status`
shows healthy peers.

## Phase 2 — NAT discovery & direct traversal

- [ ] STUN client (go-stun or pion/stun)
- [ ] NAT type classification (open/full/restricted/port-restricted/symmetric)
- [ ] UDP responder (:51822) for hole-punch probes
- [ ] DIRECT strategy (endpoint known, both public)
- [ ] UPnP port-map strategy
- [ ] Strategy engine + ladder logic
- [ ] Cache + TTL for NAT info
- [ ] Integration test: two gmeshd in docker-compose with simulated CGNAT

**Exit criteria:** gmeshd correctly classifies its own NAT and completes a
direct peer connection when both peers are reachable.

## Phase 3 — Hole punching

- [ ] STUN-assisted hole punch
- [ ] Simultaneous-open (coordinated fire_at timestamp)
- [ ] Birthday-punch (port range for symmetric NAT)
- [ ] Verification: handshake within N seconds of punch
- [ ] Rollback on failure
- [ ] Integration test: nftables-simulated symmetric NAT

**Exit criteria:** two gmeshd instances behind NAT successfully connect via
hole-punching in >80% of trials on a typical home router.

## Phase 4 — Relay & WS tunnel

- [ ] `gmesh-relay` daemon (DERP-style UDP forwarder)
- [ ] Relay auth (HMAC-signed session tokens)
- [ ] Relay client in gmeshd (SetupRelay RPC)
- [ ] WS-tunnel client (wraps WG UDP in WebSocket frames)
- [ ] Quality monitoring → switch from relay → direct when possible
- [ ] Integration test: symmetric NAT + UDP-blocked → falls back cleanly

**Exit criteria:** gmeshd works even when UDP is completely blocked between
two nodes.

## Phase 5 — Firewall

- [ ] nftables backend (atomic transactions, JSON API)
- [ ] iptables fallback
- [ ] Rule apply / reset / list / hit-counts
- [ ] Schedule-based rules (time-window checker)
- [ ] Rule templates (SSH-only, HTTP, database, etc.)
- [ ] Export/import
- [ ] Integration test: apply 1000-rule set and verify

**Exit criteria:** firewall state on gmeshd matches backend-authored state
deterministically, with sub-second apply time.

## Phase 6 — Routing + scope support

- [ ] `routing.Manager` real implementation (ip route)
- [ ] `/32` host-route per peer; conflict resolution
- [ ] ScopeConnect / ScopeDisconnect RPCs
- [ ] Per-scope netns WG (clean model: each scope has its own WG key + interface)
- [ ] Integration test: 3 VMs × 2 scopes each, full mesh connectivity

**Exit criteria:** scope-to-scope traffic across VMs works transparently.

## Phase 7 — Health + events

- [ ] Health scorer (already scaffolded in internal/health)
- [ ] Per-peer monitoring loop
- [ ] Event stream (SubscribeEvents RPC)
- [ ] Backend: frontend WebSocket subscriber (real-time topology / stats)

**Exit criteria:** Frontend Mesh UI updates in real time (no polling).

## Phase 8 — Python bridge + feature flag

- [ ] `agentNew/mesh_bridge.py` — gRPC client (~200 lines)
- [ ] Message translation: backend WS msg ↔ gRPC call
- [ ] Event forwarding: gmeshd Event stream → backend WS
- [ ] Feature flag `USE_GMESH=1` in agent systemd env
- [ ] Shadow mode: both Python mesh and gmeshd run, compare results

**Exit criteria:** with `USE_GMESH=1`, an agent's mesh behavior is
indistinguishable from the Python version to the backend.

## Phase 9 — Hardening & production tests

- [ ] Chaos tests: network partition, NAT change, relay death, agent restart
- [ ] Load test: 100 peers/node, 1000-peer mesh
- [ ] Throughput test (iperf3 through gmeshd tunnels)
- [ ] Memory/CPU profiling under load
- [ ] Prometheus metrics endpoint (`/metrics` on Unix socket)
- [ ] Audit log (every RPC, every WG mutation)

**Exit criteria:** sustained 24h test with 10+ real agent nodes passes without
degradation.

## Phase 10 — Migration

- [ ] Deploy gmesh .deb to all agent servers via OTA
- [ ] Flip `USE_GMESH=1` globally
- [ ] 72h soak
- [ ] Delete `agentNew/mesh/` from GritivaCore
- [ ] Remove mesh handlers from `agentNew/handlers/` (replaced by bridge)
- [ ] Drop Python mesh dependencies from `agentNew/requirements.txt`
- [ ] Update backend docs

**Exit criteria:** only gmesh in production. Python mesh deleted.
