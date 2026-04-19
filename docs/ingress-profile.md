# Ingress Profile (Phase 12)

An **Ingress Profile** exposes a backend service that lives on a mesh
peer on the public IP of a different "edge" peer via nftables DNAT.
Typical use: a home VM runs an admin panel on :8000; we want it
reachable as `https://<vps-public-ip>/` without forwarding residential
router ports.

## Mechanism (edge peer)

For each active profile the Linux backend installs three rules in the
shared `inet gmesh-ingress` table:

| Chain / Hook                       | Priority | Rule                                                                                  |
|------------------------------------|----------|---------------------------------------------------------------------------------------|
| `prerouting` (type nat)            | dstnat   | `<proto> dport <edge_port> dnat ip to <backend_ip>:<backend_port>`                    |
| `forward` (type filter)            | filter   | `ip daddr <backend_ip> <proto> dport <backend_port> ct state new,established,related accept` |
| `postrouting` (type nat)           | srcnat   | `ip daddr <backend_ip> <proto> dport <backend_port> masquerade`                       |

`dnat ip to` (not bare `dnat to`) is required because the `inet` table
is dual-family; nftables needs the explicit v4/v6 disambiguation.

The MASQUERADE on `postrouting` rewrites the source so return packets
come back to the edge (where conntrack holds state) rather than trying
to route back through the backend's own ISP.

## No special setup on the backend

The backend peer just needs the edge peer in its WG `AllowedIPs`
(already true for every mesh member). No ingress-specific config on the
backend.

## Example: expose home VM :8000 through a VPS

```
# On the edge VPS (peer ID 3 of the mesh):
gmeshctl ingress create \
    --id 1 --name home-panel \
    --backend-peer 1 --backend-ip 10.250.0.1 --backend-port 8000 \
    --edge-peer 3 --edge-port 80 --protocol tcp
```

Then from anywhere on the public internet:

```
$ curl http://<vps-public-ip>/
<contents served by the home VM on 10.250.0.1:8000>
```

## Filter options

```
# Only allow traffic from two CIDRs:
gmeshctl ingress create \
    --id 2 --name admin-panel \
    --backend-ip 10.250.0.1 --backend-port 8443 \
    --edge-peer 3 --edge-port 443 --protocol tcp \
    --allow-source 203.0.113.0/24 --allow-source 198.51.100.0/24
```

The `--allow-source` flag (repeatable) is compiled into an
`ip saddr { ... }` nft match that runs before the DNAT. Traffic from
any other IP falls through without matching, gets handled by the
default kernel stack (usually dropped or reset).

## Host-kernel requirements

- **nftables on PATH.** The stub backend runs everywhere, but writes no
  kernel state.
- **ip_forward enabled.** gmeshd does `sysctl -w net.ipv4.ip_forward=1`
  on first create (best-effort).
- **No iptables default-DROP on FORWARD.** If the node has UFW / a
  firewall daemon with `FORWARD` policy `DROP`, the DNATed packet will
  be silently dropped before reaching `forward`. Fix:
  `iptables -I FORWARD -i wg-gmesh -j ACCEPT`
  `iptables -I FORWARD -o wg-gmesh -j ACCEPT`

## Key design choices

- **Shared table with atomic re-apply**. Every Create / Update / Delete
  flushes the three chains and re-installs every live profile's rules
  in a single `nft -f -` transaction. A partial failure rolls back
  cleanly.
- **`type route` not required**. Unlike egress (where we re-route
  locally-originated traffic), ingress packets are already on their
  final route — the edge just rewrites destination.
- **MASQUERADE vs SNAT**. MASQUERADE auto-derives the source IP from the
  outgoing interface, which is what we want because the return path
  is determined by kernel routing to the backend's mesh_ip. Explicit
  SNAT would require tracking which interface the mesh_ip routes to.

## What's NOT in Phase 12

- **TLS termination** — `require_mtls` field reserved, implementation
  in Phase 20.
- **HTTP L7 routing / virtual hosts** — out of scope; keep a real
  reverse proxy (nginx / caddy) next to gmeshd and point it at the
  backend.
- **Health checks / automatic failover** — if the backend goes down,
  the DNAT still sends packets there and they time out. Phase 14's
  Path Monitor will add liveness-driven profile swaps.

## RPCs

```
rpc CreateIngressProfile (CreateIngressProfileRequest) returns (IngressProfileResponse);
rpc UpdateIngressProfile (UpdateIngressProfileRequest) returns (IngressProfileResponse);
rpc DeleteIngressProfile (DeleteIngressProfileRequest) returns (DeleteIngressProfileResponse);
rpc ListIngressProfiles  (ListIngressProfilesRequest)  returns (ListIngressProfilesResponse);
```

## CLI

```
gmeshctl ingress create --id N --name X \
    --backend-ip IP --backend-port P --edge-peer E --edge-port Q \
    [--backend-peer N] [--backend-scope N] \
    [--protocol tcp|udp] [--allow-source CIDR]
gmeshctl ingress list
gmeshctl ingress delete --id N
```

## Troubleshooting

**curl to edge-peer:edge-port hangs / times out.**

1. `nft list table inet gmesh-ingress` on the edge — all three chains
   must have a matching rule with your profile's ports.
2. `iptables -L FORWARD -nv` — if policy is DROP and your traffic
   isn't matching an ACCEPT line, UFW / host firewall is blocking.
   Add explicit ACCEPT rules for `wg-gmesh`.
3. From the edge, can you reach backend directly via mesh?
   `curl http://<backend_ip>:<backend_port>/` — if this fails, the
   issue is mesh connectivity, not ingress DNAT.
4. Backend has AllowedIPs for the edge peer? `wg show` on the backend;
   the edge's mesh_ip (`/32`) must be listed.

**Return traffic drops / connection hangs mid-flow.**
Conntrack state mismatch — most commonly from a backend that rebooted.
`conntrack -L | grep <backend_ip>` shows the stale entry; flush with
`conntrack -F` on the edge to force re-tracking.
