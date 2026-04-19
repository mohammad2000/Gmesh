# Circuits / onion paths (Phase 19)

A **Circuit** is an ordered list of peer IDs that a flow must traverse
before reaching the internet:

```
source_node  ──wg──▶  hop[0]  ──wg──▶  hop[1]  ──wg──▶ … ──▶ exit
```

Each hop sees only the encrypted WireGuard tunnel to the next hop.
The exit hop MASQUERADEs outbound to the internet, so replies flow
back through the same chain via conntrack.

## Honesty about "onion"

This is **not** Tor-style layered-encryption onion routing. True Tor
needs each hop to hold a layer-specific key and strip exactly one
layer before forwarding — that requires an application-layer cipher
stack we do not yet implement. What Circuits give you instead:

- **Source-routed path.** Traffic takes the exact chain of hops you
  specify; nothing else routes that flow.
- **E2E encryption between source and exit** via the WireGuard mesh.
  Intermediate hops see only ciphertext bound to the next hop's WG
  peer key.
- **Apparent origin** is the exit's public IP, same as single-hop
  egress — but with N-1 intermediate hops that an attacker must
  compromise before learning the source.

For true per-hop onion semantics (each hop knows only ±1 neighbour),
wrap this with an application-layer onion stack in a future phase.

## Role per node

Every node receives the same Circuit object; each node figures out its
role by comparing its own peer ID with the Circuit's `source` + `hops`:

| Role      | When                         | Kernel state installed                            |
|-----------|------------------------------|---------------------------------------------------|
| `source`  | local peer = `source`        | mark + per-circuit route to `hops[0]`             |
| `transit` | local peer in `hops[1..N-2]` | ip_forward + mark + route to `hops[i+1]`          |
| `exit`    | local peer = `hops[N-1]`     | ip_forward + MASQUERADE on iifname=wg-gmesh       |
| `none`    | peer not in path             | nothing (RPC still recorded for visibility)       |

## Data model

```proto
message Circuit {
  int64          id         = 1;
  string         name       = 2;
  bool           enabled    = 3;
  int32          priority   = 4;   // 0..1000, lower = earlier match
  int64          source     = 5;   // starting peer
  repeated int64 hops       = 6;   // ordered transit + exit
  string         protocol   = 7;   // "any" | "tcp" | "udp"
  string         dest_cidr  = 8;
  string         dest_ports = 9;
}
```

Validation:
- `source != 0`, `len(hops) >= 1`
- No hop may equal `source`
- No duplicate hops
- `dest_cidr` parses as CIDR if non-empty and not `0.0.0.0/0`
- `protocol` ∈ {"", "any", "tcp", "udp"}

## Kernel layout (Linux backend)

All rules live inside `inet gmesh-circuit`:

```
chain circuit_source_out   hook output      priority mangle
chain circuit_transit_fwd  hook forward     priority mangle
chain circuit_exit_fwd     hook forward     priority filter
chain circuit_exit_post    hook postrouting priority srcnat
```

Per circuit the backend additionally creates:

- Source: per-circuit routing table #`1000+id%1000`, default via `hops[0]`'s mesh IP through wg-gmesh. An `ip rule` steers packets tagged with fwmark `0x2______` to that table.
- Transit: same as source but with next-hop = `hops[i+1]`. The nft rule only marks traffic that arrived via wg-gmesh, so unrelated LAN flows never get snared.
- Exit: MASQUERADE on `iifname wg-gmesh oifname != wg-gmesh`, plus forward accept rules for established/related return traffic.

fwmark disjointness: circuits use the `0x2______` mark range, egress uses `0x1______`. Routing tables: circuits `1000..1999`, egress `100..199`. No collisions.

## CLI

```
gmeshctl circuit create --id N --name X \
    --source <source-peer> \
    --hop <transit-peer> [--hop <transit>] --hop <exit-peer> \
    [--protocol tcp --dest-ports 443] [--dest 0.0.0.0/0]
gmeshctl circuit list
gmeshctl circuit delete --id N
```

Operators must push the SAME circuit object to every node that appears
in the path (source + every hop). Each node's gmeshd figures out its
role independently from its `wireguard.self_peer_id` config entry.

## Config

```yaml
wireguard:
  self_peer_id: 1        # THIS node's peer ID in the mesh
```

Without `self_peer_id`, `gmeshctl circuit create` still installs the
Circuit but the node treats itself as role=none (no kernel state). The
RPC returns success so operators can run the same command across every
node in a mesh-wide config push without special-casing.

## Interaction with other features

- **Egress profile** and **Circuit** are mutually exclusive for a
  single destination: the fwmark spaces are disjoint, but if a flow
  matches both, the first-hit policy route wins. Pick one per
  destination.
- **pathmon** still probes each peer in the mesh; a `path_down` on an
  intermediate hop leaves the circuit broken until the operator
  removes or rebuilds it. Phase 19.5 will auto-rebuild.
- **quota** does not track circuit traffic yet — add a `counter`
  on the source rule and poll it separately for bandwidth
  accounting.
- **mTLS**: circuits carry WireGuard traffic, so mTLS above the
  circuit (e.g. ingress profile terminating TLS on the exit node)
  works exactly as with single-hop egress.

## Typical use

- **Privacy**: egress through two hops in different jurisdictions
  before reaching the internet.
- **Reachability chaining**: VM A behind residential CGNAT cannot
  host services; VM B is the only public endpoint; VM C has the
  quota budget. Chain `A → B → C → internet` so A's replies ride
  B→A on the mesh and the public IP is C's.
- **Testing**: run `source = exit` on one machine to exercise
  role=source + role=exit inside one node (conceptually a loop; only
  useful for nft rule testing). Multi-hop needs real separate nodes.

## What's NOT in Phase 19

- Layered encryption per hop (full Tor-style onion).
- Automatic rebuild on `path_down` of an intermediate hop.
- Cross-node coordination: you push the circuit manually to every
  node. A future change will let the source node push the circuit
  object to all hops via the event bus, using mTLS peer certs for
  authentication.
- Quota/accounting bound to a circuit.
