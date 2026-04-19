# Scope peers (clean model)

Gmesh treats each scope as a first-class WireGuard peer with its own
crypto identity, living inside a dedicated Linux network namespace. This
is a deliberate departure from the legacy GritivaCore model, where scopes
were "logical only" entries sharing the parent VM's WG interface.

## Why clean?

- **Crypto identity.** A scope has its own keypair. Remote peers add the
  scope as a separate peer with `allowed_ips=<scope_mesh_ip>/32`. There's
  no fate-sharing with the parent VM's key.
- **Enforceable isolation.** A scope can't impersonate the parent VM and
  vice versa. If the scope's private key leaks, only the scope is
  compromised.
- **Migration.** Moving a scope to a new VM doesn't invalidate its
  identity — its keypair travels with it.
- **Audit.** `wg show` inside the scope netns lists the scope's handshakes
  and traffic counters independently of the VM's.

## Topology per scope

```
Host                                         scope-{id} netns
─────                                         ──────────────────
eth0 (public IP)                              wg-scope  10.200.x.y/16
  │                                             │       (own keypair,
  │  iptables DNAT :<port> ───┐                 │       listen :<port>)
  ▼                            ▼                ▼
vh-s{id}  10.50.{id}.1/30 ◄── veth ──►  vs-s{id}  10.50.{id}.2/30
                                         ip route default via 10.50.{id}.1
```

Typical addressing:

| Component       | Address                        |
|-----------------|--------------------------------|
| Scope mesh IP   | 10.200.x.y (from the mesh /16) |
| Veth CIDR       | 10.50.{scope_id}.0/30          |
| VM veth IP      | 10.50.{scope_id}.1             |
| Scope veth IP   | 10.50.{scope_id}.2             |
| WG listen port  | 51830 + scope_id (convention)  |

The veth CIDR ranges are chosen by the backend and passed in via the
`ScopeConnect` RPC; gmeshd does not allocate them.

## Lifecycle

### Connect

The caller (GritivaCore backend via agent) sends `ScopeConnect` with:

```
scope_id, scope_mesh_ip, scope_netns, veth_cidr, vm_veth_ip,
scope_ip, gateway_mesh_ip, listen_port
```

gmeshd executes, in order:

1. `sysctl -w net.ipv4.ip_forward=1` (best-effort; usually set elsewhere)
2. `ip netns add <netns>` (skipped if exists)
3. `ip link add <vh> type veth peer name <vs>`
4. `ip link set <vs> netns <netns>`
5. `ip addr add <VMVethIP>/30 dev <vh>`
6. `ip -n <netns> addr add <ScopeVethIP>/30 dev <vs>`
7. `ip link set <vh> up` + `ip -n <netns> link set <vs> up`
8. `ip -n <netns> route add default via <VMVethIP>`
9. `ip -n <netns> link add wg-scope type wireguard`
10. `ip -n <netns> addr add <MeshIP>/16 dev wg-scope`
11. `ip netns exec <netns> wg set wg-scope private-key <tmp> listen-port <port>`
12. `ip -n <netns> link set wg-scope up`
13. `iptables -t nat -A PREROUTING -p udp --dport <port> -j DNAT --to-destination <ScopeVethIP>:<port>`
14. `iptables -A FORWARD -d <ScopeVethIP> -p udp --dport <port> -j ACCEPT`

The generated keypair is returned in `ScopeConnectResponse.Peer.PublicKey`;
the private key stays inside gmeshd (persisted in state.json per Phase 1)
so the scope's WG interface can be reconfigured across restarts.

### Disconnect

Reverse in best-effort order:

1. Delete DNAT + FORWARD rules (by spec)
2. `ip link del <vh>` (also removes the netns end)
3. `ip netns del <netns>`

All steps log on failure but continue; a partially-torn-down scope is
preferable to a half-alive one.

## Backends

`scope.New(log)` picks at runtime:

- **LinuxManager** — Linux with `ip`, `wg`, `iptables` on PATH. Real impl.
- **StubManager** — everything else (macOS dev, test runners). Generates a
  real WG keypair, remembers the spec, but issues no kernel commands.

The engine, RPC server, and gmeshctl don't know which backend is active —
the Manager interface abstracts it.

## CLI

```bash
gmeshctl scope connect \
    --id 42 \
    --mesh-ip 10.200.0.42 \
    --veth-cidr 10.50.42.0/30 \
    --vm-veth-ip 10.50.42.1 \
    --scope-ip 10.50.42.2 \
    --gateway-mesh-ip 10.200.0.1 \
    --listen-port 51842

gmeshctl scope disconnect --id 42
```

The `--netns` flag is optional; it defaults to `scope-<id>`.

## Integration with routing

When a scope connects AND the host is joined to the mesh, gmeshd installs
a `/32` host route for the scope's mesh IP pointing at `wg-gritiva`. This
is technically redundant if the scope also routes via its own veth, but it
provides a fallback path if anything in the netns is mis-configured.

See [`internal/routing/linux.go`](../internal/routing/linux.go) for the
`ip route replace` invocation used for conflict-free installation.

## What's not yet done

- **Port allocation.** The backend picks `listen_port` per scope; gmeshd
  trusts the choice. A pool-based allocator (with conflict detection via
  `ss -luln`) would be a nice addition.
- **IPv6 veth.** We only assign IPv4 on the veth pair. Scopes talking
  IPv6 over the mesh work (the WG interface carries both families), but
  local veth routing is IPv4-only.
- **Per-scope firewall.** Nothing prevents you from authoring firewall
  rules against `source=10.200.0.<scope>`, but the firewall package
  doesn't yet have a dedicated "scope-scoped" helper. Phase 9 adds that.
- **Userspace WG fallback in netns.** If the kernel WG module isn't
  available in a namespace, `ip link add type wireguard` fails. Running
  wireguard-go inside the netns (like the Tailscale model) would cover
  that case; Phase 1.5's userspace WG path extends naturally here.

## Compatibility with the GritivaCore backend

The backend's `scope_mesh_connect` WebSocket message maps 1:1 onto our
`ScopeConnectRequest`. The Python mesh bridge in Phase 8 will:

```python
await gmesh.ScopeConnect(
    scope_id=msg["scope_id"],
    scope_mesh_ip=msg["mesh_ip"],
    scope_netns=msg.get("namespace", f"scope-{msg['scope_id']}"),
    veth_cidr=msg["veth_cidr"],
    vm_veth_ip=msg["vm_veth_ip"],
    scope_ip=msg["scope_ip"],
    gateway_mesh_ip=msg["gateway_ip"],
    listen_port=msg.get("listen_port", 51830 + msg["scope_id"]),
)
```

Backend messages that still reference the legacy "shared WG" model get
translated on the bridge side — the clean model is an agent-side concern,
not a backend contract change.
