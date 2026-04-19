# Egress Profile (Phase 11)

An **Egress Profile** routes selected outbound traffic through a mesh
peer acting as an exit node instead of the local default gateway.
Typical use: a home VM behind residential ISP wants specific workloads
to appear to come from a datacenter VPS's public IP.

## Mechanism (source node)

For each active profile the Linux backend installs:

1. **Routing table** numbered `100 + (profile.id mod 1000)`.
2. **Default route** in that table: `default via <exit_peer.mesh_ip> dev wg-gmesh`.
3. **nftables rules** in `inet gmesh-egress`:
   - Chain `egress_mark_pre` (hook `prerouting`, priority `mangle`) — catches
     traffic forwarded from scopes.
   - Chain `egress_mark_out` (hook `output` with `type route`, priority
     `mangle`) — catches locally-originated traffic on the host.
   Both chains carry the same match + `meta mark set <fwmark>`.
4. **ip rule** `from all fwmark <fwmark> lookup <table>` at priority
   `20000 + profile.priority`.

The fwmark uses the top nibble `0x1` + 28 bits of profile ID, so it's
safely in its own mark space (`0x10000000..0x1FFFFFFF`). TableID and
RulePriority helpers in `internal/egress/egress.go` keep allocation
deterministic.

## Mechanism (exit node)

The exit peer runs `gmeshctl egress exit enable` once, which installs
table `inet gmesh-exit` with two chains:

```
chain forward { type filter hook forward priority filter;
    iifname "wg-gmesh" oifname != "wg-gmesh" accept;
    iifname != "wg-gmesh" oifname "wg-gmesh" ct state established,related accept; }
chain postrouting { type nat hook postrouting priority srcnat;
    iifname "wg-gmesh" oifname != "wg-gmesh" masquerade; }
```

Plus `sysctl -w net.ipv4.ip_forward=1`. The exit doesn't know anything
about specific profiles — it just MASQUERADEs any mesh traffic asking to
egress.

## Example: all host traffic via a VPS

```
# On the VPS exit node:
gmeshctl egress exit enable

# On the home node (peer ID 3 is the VPS):
gmeshctl egress create \
    --id 1 --name home-via-vps \
    --exit-peer 3 --dest 0.0.0.0/0 --priority 100
```

Verify:

```
curl https://api.ipify.org
# → <VPS public IP>  (before the profile: <home ISP IP>)
```

## Filter options

```
gmeshctl egress create \
    --id 2 --name https-via-vps \
    --exit-peer 3 \
    --protocol tcp \
    --dest-ports 443,8443 \
    --priority 50          # higher-priority (lower number) match

gmeshctl egress create \
    --id 3 --name scope7-via-vps \
    --exit-peer 3 \
    --source-scope 7 \
    --dest 0.0.0.0/0

gmeshctl egress create \
    --id 4 --name cidr-match \
    --exit-peer 3 \
    --source-cidr 10.50.42.0/30 \
    --dest 0.0.0.0/0
```

`priority` is the application order: lower wins. A `--dest-ports 443`
rule at priority 50 supersedes a catch-all at priority 100.

## Key design choices

- **fwmark indirection** (instead of `ip rule from <cidr>`) — lets us
  use full nftables matching (L4 ports, conntrack state, protocol) and
  still hand the packet to the right routing table.
- **Two chain hooks** — `prerouting` alone misses locally-originated
  packets; `output` alone misses scope-forwarded packets. Both cover
  both cases.
- **`type route` for output** — makes sure packets re-run the routing
  decision AFTER the mark is applied. Without it, the mark has no
  effect on already-routed traffic.
- **No DROP on exit failure** — if the exit peer goes down, packets
  follow the per-profile route table, hit the dead peer, and time out.
  A kill-switch (drop instead of leak) is reserved for Phase 14's
  Path Monitor.

## What's NOT in Phase 11

- **Load balancing** across an `exit_pool` — reserved in proto, wired in
  Phase 16.
- **GeoIP destination filtering** — reserved in proto, wired in Phase 15.
- **Quota / rate-triggered shift** — Phase 13.
- **Return-traffic failover with zero drop** — Phase 14.

## RPCs

```
rpc CreateEgressProfile (CreateEgressProfileRequest) returns (EgressProfileResponse);
rpc UpdateEgressProfile (UpdateEgressProfileRequest) returns (EgressProfileResponse);
rpc DeleteEgressProfile (DeleteEgressProfileRequest) returns (DeleteEgressProfileResponse);
rpc ListEgressProfiles  (ListEgressProfilesRequest)  returns (ListEgressProfilesResponse);
rpc EnableExit          (EnableExitRequest)          returns (EnableExitResponse);
rpc DisableExit         (DisableExitRequest)         returns (DisableExitResponse);
```

## CLI

```
gmeshctl egress create --id N --name X --exit-peer P [--source-scope S | --source-cidr C]
                       [--protocol tcp|udp|any] [--dest CIDR] [--dest-ports N,N]
                       [--priority 0..1000]
gmeshctl egress list
gmeshctl egress delete --id N
gmeshctl egress exit enable      # on the node that will serve as exit
gmeshctl egress exit disable
```

## Backends

`egress.New()` picks at runtime:

- **`linux`** — `ip route` + `ip rule` + `nft -f -` shell-outs. Needs
  `ip` and `nft` on PATH; running as root.
- **`stub`** — macOS dev + unit tests. Stores profiles in memory; no
  kernel side-effects. Emits the same events.

## Troubleshooting

**Traffic still exits through the home ISP after creating a profile.**
1. `ip rule show | grep fwmark` — should list your 0x1XXXXXXX mark.
2. `ip route show table <table>` — should show `default via <exit_ip>`.
3. `nft list table inet gmesh-egress` — should show both `egress_mark_*`
   chains with a matching `meta mark set` rule.
4. On the exit peer: `nft list table inet gmesh-exit` — MASQUERADE must
   be installed. Run `gmeshctl egress exit enable` if missing.
5. Exit peer's AllowedIPs (`wg show`) must cover the destinations the
   source wants to reach. For "all internet via exit", AllowedIPs on the
   SOURCE side must include `0.0.0.0/0` for the exit peer — otherwise
   kernel WG drops the outbound packet.

**Return traffic is dropped.** Check `conntrack -L | grep MASQUERADE` on
the exit. If the exit peer was restarted after the flow started,
conntrack state is gone; the flow dies. New connections work; no
zero-drop failover yet (Phase 14).
