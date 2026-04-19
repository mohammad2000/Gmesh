# Gmesh

**Go-based WireGuard mesh networking daemon.**

Gmesh is a standalone daemon (`gmeshd`) that owns everything about a node's mesh
membership: WireGuard interface lifecycle, NAT discovery, hole-punching, relay,
nftables firewall, routing, and peer health monitoring. It exposes a gRPC API
over a Unix socket so any process (the GritivaCore Python agent, a CLI, another
service) can drive it.

It replaces the Python mesh implementation that previously lived inside
[GritivaCore's agent](https://github.com/mohammad2000/GritivaCore/tree/main/agentNew/mesh).
The GritivaCore backend protocol is preserved — only the agent-side networking
logic moves into Go.

## Why Go

We considered C (following the `gscope` precedent) and Rust. Go wins because:

- **`wireguard-go`** is Cloudflare/WireGuard's userspace implementation,
  already battle-tested by Tailscale. We import it instead of reimplementing.
- Networking-heavy code (STUN, UDP/TCP, WebSockets, gRPC) is a first-class
  ecosystem in Go — much less plumbing than C.
- Single static binary, trivial cross-compilation, easy `.deb` packaging.
- Tailscale (literally this problem, solved) is written in Go — we follow that
  playbook.

## Architecture

```
┌─────────────────────────────────────────────┐
│  GritivaCore agent (Python)                  │
│  ┌──────────────────────────────────────┐    │
│  │ mesh_bridge.py (thin gRPC client)     │    │
│  └──────────────┬───────────────────────┘    │
└─────────────────┼────────────────────────────┘
                  │ gRPC over Unix socket
                  │ /run/gmesh.sock
┌─────────────────┼────────────────────────────┐
│  gmeshd (this project — systemd service)     │
│  ┌──────────────┴──────────────────────┐     │
│  │  engine/    — orchestration loop     │     │
│  │  peer/      — state + quality        │     │
│  │  nat/       — STUN, type detection   │     │
│  │  traversal/ — hole-punch, UPnP,      │     │
│  │               SimOpen, Birthday      │     │
│  │  wireguard/ — kernel wg + wg-go      │     │
│  │  relay/     — UDP + WS tunnel client │     │
│  │  firewall/  — nftables (atomic)      │     │
│  │  routing/   — ip route mgmt          │     │
│  │  health/    — scoring + event stream │     │
│  │  rpc/       — gRPC server            │     │
│  └─────────────────────────────────────┘     │
└───────────────────────────────────────────────┘
            │                            │
            │ WireGuard UDP :51820       │
            │                            │
            ▼                            ▼
    ┌──────────────┐               ┌──────────────┐
    │   peer       │               │ gmesh-relay  │
    │  (direct)    │               │  (DERP-like) │
    └──────────────┘               └──────────────┘
```

Three binaries ship from this repo:

| Binary | Purpose |
|--------|---------|
| `gmeshd` | The per-node daemon. Listens on `/run/gmesh.sock`, manages WireGuard, runs all networking. |
| `gmeshctl` | CLI for operators / debugging. Talks to `gmeshd` over the Unix socket. |
| `gmesh-relay` | DERP-style relay server. Run centrally (like Tailscale's DERP). Peers behind symmetric NAT fall back to it. |

## Status

🚧 **Phase 0 — scaffold.** Not yet functional. See [docs/roadmap.md](docs/roadmap.md).

## Quick start (once built)

```bash
# Build
make build                 # → bin/gmeshd, bin/gmeshctl, bin/gmesh-relay

# Install as systemd service
sudo make install

# Check status
gmeshctl status
```

## Build dependencies

- Go ≥ 1.23
- protoc ≥ 3.20 (for proto regeneration)
- `make`, `git`
- Linux kernel with WireGuard (kernel ≥ 5.6 or DKMS) — falls back to userspace wg-go otherwise

## Repo layout

```
cmd/               # binaries (gmeshd, gmeshctl, gmesh-relay)
internal/          # packages not meant for external import
api/proto/         # .proto definitions (canonical source of truth for the API)
gen/               # generated protobuf code (checked in)
pkg/               # public reusable helpers (empty for now)
scripts/           # build/install/test scripts
systemd/           # unit files
debian/            # .deb packaging
docs/              # architecture, protocol, deployment, migration notes
test/              # integration + e2e test harnesses
.github/workflows/ # CI (lint, test, build, .deb artifacts)
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Contributing

Internal project for Gritiva. External PRs welcome once we're past Phase 2.
