# Roadmap — Phases 11 → 21

Phase 10 (migration of GritivaCore agent from Python mesh to gmesh) is
deliberately postponed to the end. The rationale: shadow mode
([Phase 8](migration-from-python.md)) already lets us run gmesh in
production alongside the legacy path. Deferring the switch buys us
months of real-world bake time while the new user-visible features
below land on top of a stable gmesh.

## Delivery order

```
Phase 11  Egress Profile          ✅ v0.4.0
Phase 12  Ingress Profile          ✅ v0.4.0
Phase 13  Quota Manager            ✅ v0.4.0
Phase 13.5 Quota hard-stop + auto_rollback   ✅ v0.5.0
Phase 14  Path Monitor (active)    ✅ v0.5.0   — includes auto-failover listener
Phase 15  GeoIP Resolver           ✅ v0.6.0
Phase 16  A/B Traffic Splitter     ✅ v0.6.0
Phase 17  Policy Engine (skeleton) ✅ v0.6.0   — YAML + debounce
Phase 18  eBPF L7 Classifier          ─┐  Tier 3: advanced features
Phase 19  Onion Circuit Manager        │  ✅ v0.8.0 (multi-hop source-routed path; NOT Tor-style)
Phase 20  Zero-Trust mTLS              │  ✅ v0.7.0 (CA + SPIFFE peer certs + revocation)
Phase 21  Connection Anomaly          ─┘
Phase 22  AI Topology Optimizer    — research track
Phase 23  Bandwidth Marketplace    — product track (separate)
Phase 10  GritivaCore migration    ✅ v0.7.0 (bridge shim wired into agent; per-VM cutover via USE_GMESH=1)
```

## Design decisions locked in

Six questions were raised before starting; here are the answers the
roadmap assumes. Revise in-place if any turns out wrong during impl.

| # | Question | Decision |
|---|----------|----------|
| 1 | What is a "project" in routing terms? | Reuse **scope** as the per-project isolation unit. A profile attaches to a scope (or bare source CIDR on the host). No new "Project" object in gmesh. |
| 2 | Egress vs ingress: same primitive or two? | **Two** — `EgressProfile` (outbound via peer) and `IngressProfile` (inbound through peer). They share a `Profile` base type but differ enough in state that combining them obscures things. |
| 3 | Identity model for zero-trust (Phase 20) | Phase 11-19: **WG public key = identity**. Phase 20: layer SPIFFE-like certs on top. Don't block Tier 1/2 on SPIFFE. |
| 4 | How do users author profiles? | (a) gRPC RPC for machines. (b) YAML on disk for GitOps. (c) UI (in GritivaCore backend, not gmesh) for humans. Source of truth is gRPC state — YAML/UI are thin shells. |
| 5 | Backward compat with Gritiva Share/Tunnel | Run Egress/Ingress profiles **side-by-side** with legacy Share/Tunnel for 3–6 months. Deprecate legacy once profile coverage is proven. |
| 6 | Priority: new features vs migration | **New features first** (Phase 11 → 21). Migration (Phase 10) last. gmesh already runs in shadow on production per Phase 8 — no urgency on the switch. |

## The 4 base scenarios → features that enable each

| Scenario                                   | Needs                              |
|--------------------------------------------|------------------------------------|
| A. VM1's project exits via Germany         | Phase 11 (Egress Profile)          |
| B. VM1's port 8000 exposed on Germany IP   | Phase 12 (Ingress Profile)         |
| C. VM2 scope via Germany, project port→VM1 | Phase 11 + 12 combined             |
| D. VM3 load-split on request-rate threshold| Phase 11 + 13 (Quota + splitting)  |

The 4 base scenarios need **only Tier 1** (Phases 11–13). Tier 2 and 3
extend capability for the 8 advanced scenarios from the conversation.

## Phase 11 — Egress Profile (first to build)

### Concept

"Traffic matching filter F on source node S exits the internet through
peer P instead of S's default gateway."

### Data model

```proto
message EgressProfile {
  int64  id              = 1;
  string name            = 2;
  bool   enabled         = 3;
  int32  priority        = 4;  // 0-1000; lower = earlier match

  // Match
  int64  source_scope_id = 5;  // 0 = bare host source
  string source_cidr     = 6;  // optional, e.g. "10.50.42.0/30"
  string protocol        = 7;  // "any" | "tcp" | "udp"
  string dest_cidr       = 8;  // "0.0.0.0/0" for all internet
  string dest_ports      = 9;  // "443" or "80,443" or ""
  repeated string geoip_countries = 10; // Phase 15 hook (optional)

  // Exit
  int64  exit_peer_id    = 11;
  // Optional Phase 16 hook:
  repeated int64 exit_pool   = 12;
  repeated int32 exit_weights = 13; // same length; sums to 100
}
```

### Mechanism

**Source node** (where traffic originates):

1. Per-profile routing table `100 + profile.id`.
2. `ip route add default via <exit_peer.mesh_ip> dev wg-gmesh table T`.
3. nftables mark rule in `gmesh-egress` table:
   `meta mark set <profile.id> oifname != wg-gmesh <filter>`
4. `ip rule add fwmark <profile.id> lookup T priority <1000 + profile.priority>`.

**Exit peer** (where traffic leaves to the internet):

1. Enable `net.ipv4.ip_forward=1` (idempotent).
2. Install MASQUERADE rule in `gmesh-exit` table:
   `oifname != wg-gmesh iifname wg-gmesh masquerade`
3. Allow FORWARD for traffic coming in on `wg-gmesh`.

### Coordination

Both nodes must agree. gmeshd on the source side does a gRPC call to
gmeshd on the exit side (via backend-mediated discovery) asking it to
`EnableExit()`. Backend records which peers are exit-capable.

### RPC additions

```
rpc CreateEgressProfile (EgressProfile) returns (EgressProfileResponse);
rpc UpdateEgressProfile (EgressProfile) returns (EgressProfileResponse);
rpc DeleteEgressProfile (int64)          returns (Empty);
rpc ListEgressProfiles  (Empty)          returns (EgressProfilesResponse);

// Exit-side verbs (called by the exit peer itself)
rpc EnableExit  (EnableExitRequest)  returns (Empty);
rpc DisableExit (DisableExitRequest) returns (Empty);
```

### CLI

```
gmeshctl egress create --name home-via-germany \
    --source-scope 42 --exit-peer 3 --dest 0.0.0.0/0 --priority 100

gmeshctl egress list
gmeshctl egress delete --id 1
gmeshctl egress enable --id 1 --exit
```

### Out of scope for Phase 11

- GeoIP filtering (Phase 15 hook reserved but not wired).
- Load balancing across exit pool (Phase 16 hook reserved).
- Bandwidth accounting (Phase 13).
- Kill-switch on exit failure (Phase 14 adds failover).

### Exit criteria

Two real Linux nodes + one exit VPS. Create a profile routing
curl https://api.ipify.org from a specific scope through the VPS.
`curl` returns the VPS's public IP, not the source node's.

## Phase 12 — Ingress Profile

### Concept

"Expose a backend service that lives on node B (possibly inside scope S)
on the public IP of edge peer E, port N."

### Data model

```proto
message IngressProfile {
  int64  id              = 1;
  string name            = 2;
  bool   enabled         = 3;

  // Backend
  int64  backend_peer_id = 4;
  int64  backend_scope_id = 5;  // 0 = on the peer itself, not in a scope
  string backend_ip      = 6;   // typically scope's mesh_ip or 127.0.0.1
  uint32 backend_port    = 7;

  // Edge exposure
  int64  edge_peer_id    = 8;
  uint32 edge_port       = 9;
  string protocol        = 10;  // "tcp" | "udp"

  // Phase 20 hook
  bool   require_mtls    = 11;
}
```

### Mechanism (edge peer)

nftables NAT:
```
nft add rule inet gmesh-ingress prerouting \
    tcp dport <edge_port> \
    dnat to <backend.mesh_ip>:<backend_port>

nft add rule inet gmesh-ingress postrouting \
    ip daddr <backend.mesh_ip> \
    masquerade
```

Routing: the edge peer already has `<backend.mesh_ip>/32 via wg-gmesh`
from Phase 6 routing. No new routes needed.

### Exit criteria

VM1 runs `python3 -m http.server 8000`. Create ingress profile
backend=(vm1, 8000), edge=(germany, 80). `curl http://<germany_ip>/`
returns VM1's directory listing.

## Phase 13 — Quota Manager

### Concept

Track bytes-per-period per egress profile. At thresholds, emit events
or shift traffic to a backup profile.

### Data model

```proto
message Quota {
  int64  id                 = 1;
  int64  egress_profile_id  = 2;
  string period             = 3;   // "hourly" | "daily" | "monthly"
  int64  limit_bytes        = 4;

  // Thresholds (fractions 0..1)
  double warn_at            = 5;   // e.g. 0.8 → emit event
  double shift_at           = 6;   // e.g. 0.95 → swap to backup
  double stop_at            = 7;   // 1.0 → drop matching traffic

  int64  backup_profile_id  = 8;
}
```

### Counters

Every rule generated by Phase 11 includes `counter` in its nft body
already (Phase 5 wire format). Quota Manager polls those counters every
10 s via `nft -j list table inet gmesh-egress`, maps rule handles → quota
IDs, aggregates, and compares to limits.

### Action table

| Threshold    | Action                                               |
|--------------|------------------------------------------------------|
| reach `warn` | Publish `quota_warning` event (for UI alert)         |
| reach `shift`| Swap active profile: `exit_peer_id = backup`         |
| reach `stop` | Insert an explicit DROP rule at priority 0           |
| period reset | Zero counters; remove stop rule; restore original    |

### Exit criteria

Set a 10 MB limit on a profile. curl a 100 MB file. After 10 MB,
traffic either shifts to backup profile or drops (per config), and an
event fires.

## Phases 14–17 (Tier 2) — sketch only

Full design happens when we get there; these placeholders let us reason
about hooks reserved in Phase 11 today.

**Phase 14 — Path Monitor**: active UDP prober between peers; measures
RTT/loss/jitter; stores 5-minute history; exposes `GetPathMetrics` RPC.
Failover logic reads from here.

**Phase 15 — GeoIP Resolver**: embed MaxMind GeoLite2 DB (or similar);
lookup destination country on connection; feed `EgressProfile.geoip_countries`
filter.

**Phase 16 — A/B Traffic Splitter**: extends Egress Profile with
`exit_pool` + `exit_weights`; nftables `numgen` picks exit at new-flow time.

**Phase 17 — Policy Engine**: YAML DSL → compiled profile set.
Example policy:
```yaml
policies:
  - match: {label: "production"}
    egress: {peer: germany}
  - match: {label: "dev"}
    egress: {peer: direct}
  - match: {protocol: bulk}
    egress: {best_bandwidth: true}
```
DSL compiles into concrete Egress/Ingress profiles.

## Phases 18–21 (Tier 3) — even rougher

**Phase 18 — eBPF L7**: CO-RE eBPF programs marking packets by SNI / HTTP
method / connection-type. Feeds into Policy Engine.

**Phase 19 — Onion Circuit**: nested WireGuard sessions across 3+ hops.
Each hop knows only the next. Separate relay binary `gmesh-onion-hop`.

**Phase 20 — Zero-Trust mTLS**: SPIFFE-style identities; mTLS between
peers (beyond WG); nftables rules tied to identity labels.

**Phase 21 — Anomaly Detection**: baseline per-peer connection
fingerprints; flag departures.

## Phase 22 — AI Topology Optimizer (research)

Traffic matrix collection → betweenness centrality → bottleneck
detection + shortcut suggestion. No ML initially; heuristic is fine.

## Phase 23 — Bandwidth Marketplace (separate product)

Out of scope for gmesh core. Would become a separate product
("Gritiva Exchange") built on top of Tier 1-3 primitives. Requires
identity federation, billing, SLA enforcement, legal framework.

## Non-goals

The following are **intentionally not** on this roadmap:

- True BGP anycast (requires ASN + BGP peering).
- Full TLS termination at edge (use a reverse proxy beside gmeshd).
- Layer-7 load balancing (keep it UDP/WG + L4 NAT).
- Multi-tenant billing in gmesh itself (belongs to the product layer).
