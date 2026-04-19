# Architecture

## Why a separate daemon?

The Python mesh code in the GritivaCore agent grew into one of the heaviest,
most performance-sensitive subsystems in the project. Problems we're solving
by moving it out:

1. **Performance.** Python async + subprocess calls to `wg`, `ip`, `iptables`
   sit in the hot path for every peer operation. A single agent with 50+ peers
   spends a non-trivial chunk of time shelling out. Go + `wgctrl` talks to the
   kernel WireGuard netlink directly.

2. **Isolation.** When the agent crashes or is restarted for an OTA update,
   the mesh stays up. A separate systemd unit with its own restart policy is
   the right boundary.

3. **Testability.** A daemon with a gRPC surface can be integration-tested in
   isolation (docker-compose with 3+ nodes, netns-simulated NAT) without
   booting the whole GritivaCore stack.

4. **Reuse.** Any future language — Rust agent, Go agent, CLI tool — can
   drive the mesh through the same proto API.

## Process topology

```
┌────────────────────────────────────────────────────────────┐
│  node: a GritivaCore agent machine                         │
│                                                            │
│  ┌──────────────────────────┐                              │
│  │ gritiva-agent.service     │  Python                     │
│  │  (handlers, terminal,     │                             │
│  │   file-manager, scope,    │                             │
│  │   service-manager, mesh   │                             │
│  │   bridge)                 │                             │
│  └──────────┬───────────────┘                              │
│             │ gRPC over Unix socket (/run/gmesh.sock)      │
│             ▼                                              │
│  ┌──────────────────────────┐                              │
│  │ gmeshd.service            │  Go                         │
│  │  — engine orchestration   │                             │
│  │  — wireguard (kernel + wg-go)                           │
│  │  — NAT/STUN                                             │
│  │  — hole punching                                        │
│  │  — relay client                                         │
│  │  — nftables firewall                                    │
│  │  — routing                                              │
│  │  — health monitoring                                    │
│  └──────────┬───────────────┘                              │
│             │ UDP :51820 (WireGuard)                       │
└─────────────┼──────────────────────────────────────────────┘
              │
              ▼
      ╔══════════════════╗              ╔══════════════════╗
      ║   peer node       ║              ║  gmesh-relay      ║
      ║   (direct)        ║              ║  (DERP-style)     ║
      ╚══════════════════╝              ╚══════════════════╝
```

## Responsibility split

| Concern                              | Owner                |
|--------------------------------------|----------------------|
| REST API, auth, persistence (DB)     | GritivaCore backend  |
| WebSocket bus, agent commands        | GritivaCore backend  |
| Agent lifecycle, terminal, files,    | GritivaCore agent    |
| service manager, OTA updates         |                      |
| Mesh join/leave, peer mgmt,          | **gmeshd (this)**    |
| WireGuard, NAT, traversal, relay,    |                      |
| firewall, routing, health            |                      |
| Scope (namespace + cgroup lifecycle) | gscope (C library)   |

The backend protocol — the WebSocket messages `mesh_join`,
`mesh_add_peer`, `mesh_hole_punch_result`, `scope_mesh_connect`, etc — stays
**unchanged**. The Python mesh bridge translates those into gRPC calls to
gmeshd and translates gmeshd events into WebSocket responses. From the
backend's perspective, nothing changes.

## Control flow examples

### Agent startup & join

```
1. agent starts up
2. agent connects to backend WS with auth token
3. backend → agent: {"type": "mesh_join", "mesh_ip": "10.200.0.7", ...}
4. agent → gmeshd (gRPC Join): mesh_ip=10.200.0.7, port=51820, ...
5. gmeshd generates WG keypair, brings up wg-gritiva, runs STUN discovery
6. gmeshd returns JoinResponse{public_key, nat_info, endpoint}
7. agent → backend WS: {"type": "mesh_joined", ...backend-protocol...}
8. backend: auto_connect_peers → sends mesh_add_peer for every existing peer
```

### Peer connection (direct)

```
1. backend → agent: {"type": "mesh_add_peer", "peer_id": 42, ...}
2. agent → gmeshd (AddPeer): ...
3. gmeshd: traversal engine picks ConnectionMethod=DIRECT (both public)
4. gmeshd: wg set peer <pubkey> endpoint=1.2.3.4:51820 allowed-ips=10.200.0.8/32
5. gmeshd: waits for handshake via ping
6. gmeshd: emits Event{type:"peer_connected", peer_id:42, method:DIRECT}
7. agent subscribed to event stream → forwards backend WS
```

### Peer connection (symmetric NAT → relay)

```
1. strategy engine traverses ladder: DIRECT→UPNP→STUN→SIMOPEN→BIRTHDAY (all fail)
2. engine: request relay from backend (via agent)
3. backend allocates relay session via gmesh-relay
4. agent → gmeshd (SetupRelay): relay_endpoint=relay.gritiva.com:4500, session=abc
5. gmeshd: open UDP socket to relay, register session, route WG packets through it
6. gmeshd: engine emits peer_connected with method=RELAY
```

## State & durability

| State                       | Location                                                  |
|-----------------------------|-----------------------------------------------------------|
| Peer list (authoritative)   | Backend DB (`mesh_peers`, `mesh_peer_connections`)       |
| Firewall rule authored      | Backend DB (`mesh_firewall_rules`)                       |
| Daemon in-memory peer state | gmeshd memory + `/var/lib/gmesh/state.json`              |
| Daemon private key          | Encrypted in state.json (Fernet, shared key with backend) |
| Live kernel state           | WireGuard interface, nftables table, route table          |

On restart, gmeshd rehydrates from state.json, compares against live kernel
state, and reconciles. If state.json is missing, it waits for the agent to
replay the peer set via AddPeer calls (backend provides this via
`auto_connect_peers`).

## Failure modes

| Failure                           | Behavior                                       |
|-----------------------------------|------------------------------------------------|
| gmeshd crashes                    | systemd restarts in <5s; existing WG tunnels   |
|                                   | survive (kernel owns them); state rehydrates   |
| agent crashes                     | gmeshd keeps mesh alive; agent reconnects and  |
|                                   | subscribes to events; any missed peer commands |
|                                   | are replayed by backend on reconnect           |
| Unix socket deleted               | gmeshd detects on next accept and recreates    |
| nftables backend unavailable      | fall back to iptables; log warning             |
| Kernel WG unavailable             | fall back to wireguard-go userspace            |

## Security

- Unix socket: mode 0660, root-only by default. Same trust boundary as the
  agent (both run as root on the managed node).
- WireGuard private keys: never cross the gRPC boundary in plaintext.
  gmeshd generates them, returns encrypted (Fernet) blobs for backend storage,
  and holds the live key in memory + on-disk in state.json (mode 0600).
- No network listener by default — only the Unix socket. `gmesh-relay` is a
  separate binary with its own auth model.
- gRPC API has no user auth (it's the Unix socket boundary that gatekeeps).
  If ever exposed over TCP, add mTLS; out of scope for Phase 1.

## See also

- [protocol.md](protocol.md) — gRPC API reference.
- [deployment.md](deployment.md) — install, upgrade, rollback.
- [migration-from-python.md](migration-from-python.md) — cutover plan.
- [roadmap.md](roadmap.md) — phased delivery.
