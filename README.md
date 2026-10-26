# Gmesh

[![CI](https://github.com/mohammad2000/Gmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/mohammad2000/Gmesh/actions/workflows/ci.yml)

**Go-based WireGuard mesh networking daemon.**

Gmesh is a standalone daemon (`gmeshd`) that owns everything about a node's mesh
membership: WireGuard interface lifecycle, NAT discovery, hole-punching, relay,
nftables firewall, routing, and peer health monitoring. It exposes a gRPC API
over a Unix socket so any process (the Gritiva agent, a CLI, another service)
can drive it.

It is the network layer of [Gritiva](https://gritiva.com), where it runs on
Linux servers, inside isolated scopes, and on Windows and macOS machines.

## Why Go

We considered C (following the `gscope` precedent) and Rust. Go wins because:

- **`wireguard-go`** is the official WireGuard userspace implementation,
  already proven at scale in other mesh products. We import it instead of
  reimplementing it.
- Networking-heavy code (STUN, UDP/TCP, WebSockets, gRPC) is a first-class
  ecosystem in Go, with much less plumbing than C.
- Single static binary, trivial cross-compilation, easy `.deb` packaging.
- Tailscale (literally this problem, solved) is written in Go, and we follow that
  playbook.

## Architecture

```
┌─────────────────────────────────────────────┐
│  Gritiva agent (Go)                          │
│  ┌──────────────────────────────────────┐    │
│  │ mesh client (gRPC)                    │    │
│  └──────────────┬───────────────────────┘    │
└─────────────────┼────────────────────────────┘
                  │ gRPC over Unix socket
                  │ /run/gmesh.sock
┌─────────────────┼────────────────────────────┐
│  gmeshd (this project, a system service)     │
│  ┌──────────────┴──────────────────────┐     │
│  │  engine/    : orchestration loop     │     │
│  │  peer/      : state + quality        │     │
│  │  nat/       : STUN, type detection   │     │
│  │  traversal/ : hole-punch, UPnP,      │     │
│  │               SimOpen, Birthday      │     │
│  │  wireguard/ : kernel wg + wg-go      │     │
│  │  relay/     : UDP + WS tunnel client │     │
│  │  firewall/  : nftables, WFP          │     │
│  │  routing/   : ip route mgmt          │     │
│  │  health/    : scoring + event stream │     │
│  │  rpc/       : gRPC server            │     │
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

**In production since April 2026** as the network layer of Gritiva: Linux
hosts on kernel WireGuard, isolated scopes (a network namespace with its own
WireGuard interface each), and Windows (wintun, as the `GritivaMesh` service)
and macOS (utun) machines on wireguard-go. The control plane is the Gritiva
backend; each machine's agent drives gmeshd over the local socket.

| Area | State |
|---|---|
| WireGuard lifecycle, peers, per-peer routes, state restored after a restart | Production |
| Endpoint candidates (LAN, STUN, global IPv6) and the endpoint racer | Production |
| Hole punching coordinated through the relay; peers behind the same NAT aim at each other's LAN address | Production |
| Relay fallback (protocol v2): UDP, or a WebSocket on TCP/443 where UDP is blocked; several relays at once; a dead relay is noticed in about 25 s; a node on TCP re-tests UDP every 30 min | Production |
| Firewall: nftables on Linux, WFP on Windows; rules only ever apply to the mesh interface | Production |
| Scopes (netns + veth + in-namespace WireGuard) | Production (Linux) |
| Health events, Prometheus metrics, audit log | Production |
| Control socket auth (kernel peer credentials, optional token) | Production |
| Egress / exit pools, ingress, circuits, quota, policy, L7, mTLS CA, anomaly detection | Experimental |

### Known limitations

- **Some feature state is in memory.** Relay settings and connected scopes are
  saved and restored; egress, ingress, circuit and quota settings are re-sent
  by the control plane after a restart.
- **Egress profiles are IPv4 only.** IPv6 is used for direct paths between
  peers.
- On macOS and Windows, path monitoring, L7 and policy routing are stubs.
- The installer packages are for Debian and Ubuntu on x86-64; Linux arm64 is
  next.

## Quick start

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
- Linux kernel with WireGuard (kernel ≥ 5.6 or DKMS); otherwise it falls back to userspace wg-go

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

Apache 2.0, see [LICENSE](LICENSE).

## Contributing

Built for Gritiva; issues and PRs are welcome. `make lint test` must pass
(golangci-lint v1.62, `go test -race`).
