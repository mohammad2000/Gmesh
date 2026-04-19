# Firewall

gmeshd ships a three-tier firewall pipeline. Rules authored in the
GritivaCore backend DB are pushed down via gRPC, translated into either an
nftables script or a list of iptables commands, then atomically replaced.

## Backend selection

At boot, `firewall.Detect` picks the best backend in this order:

1. **nftables** (default) — if `nft` is on PATH and
   `firewall.use_nftables: true` in config. Atomic, fast, JSON-introspectable.
2. **iptables** — if only `iptables` exists. Approximated atomicity via
   chain flush + replay; slower; no hit-count parsing yet.
3. **memory** — in-process stub on dev hosts without either binary. All
   operations succeed, rules are kept in memory so `list` and `status` work.

Override in config:

```yaml
firewall:
  table: gmesh         # nft table name
  chain: GMESH         # iptables chain prefix (becomes GMESH_INPUT, etc.)
  use_nftables: true
```

## Layout on Linux

### nftables

```
table inet gmesh {
    chain mesh_input   { type filter hook input   priority filter; policy ...; }
    chain mesh_output  { type filter hook output  priority filter; policy ...; }
    chain mesh_forward { type filter hook forward priority filter; policy ...; }
}
```

Every `ApplyFirewall` RPC renders a full script with `add table` followed
by `delete table` (to drop any previous state) then a fresh recreation.
`nft -f -` executes that transaction atomically; partial failures roll
back automatically.

### iptables

Custom chains `GMESH_INPUT`, `GMESH_OUTPUT`, `GMESH_FORWARD` are hooked
via `-j` from the built-in chains. Apply = flush chain + re-insert
rule-by-rule. Not atomic — a mid-apply failure leaves the chain partial.

## Rule schema

See [`internal/firewall/firewall.go`](../internal/firewall/firewall.go)
and the [proto definition](../api/proto/gmesh/v1/gmesh.proto#L237).

| Field         | Type    | Example                                |
|---------------|---------|----------------------------------------|
| `action`      | enum    | `allow` / `deny` / `limit` / `log`     |
| `protocol`    | enum    | `any` / `tcp` / `udp` / `icmp` / `icmpv6` |
| `source`      | string  | `10.200.0.5/32` or `any`               |
| `destination` | string  | CIDR or `any`                          |
| `port_range`  | string  | `80` / `80-443` / `22,80,443`          |
| `direction`   | string  | `inbound` / `outbound` / `both`        |
| `conn_state`  | string  | `NEW,ESTABLISHED,RELATED`              |
| `rate_limit`  | string  | `100/s`, `1000/m`, `5/h`               |
| `schedule`    | string  | JSON; see "Schedules" below            |
| `expires_at`  | int64   | Unix seconds; 0 = never                |

Actions:

- **allow** → `accept` in nft, `-j ACCEPT` in iptables
- **deny** → `drop` / `-j DROP`
- **limit** → `limit rate N/U accept` (with optional `burst N packets`)
- **log** → `log prefix "gmesh: " accept` (logs, then accepts)

## Schedules

Time-bounded rules carry a JSON schedule string in the `schedule` field:

```json
{
  "windows": [
    { "start": "09:00", "end": "17:00", "days": ["mon","tue","wed","thu","fri"] }
  ],
  "timezone": "America/Montreal"
}
```

Semantics:

- Multiple windows are OR'd; a rule is live if now falls in ANY window.
- `days` empty = every day.
- `end < start` wraps midnight.
- `timezone` is any IANA zone; bad zones silently fall back to UTC.
- No `schedule` field = always live.

The engine runs a 30 s scheduler loop (`firewallScheduler` in
[engine.go](../internal/engine/engine.go)) that re-applies the ruleset
whenever the set of live rule IDs changes — e.g. at 09:00 sharp a
business-hours rule flips on and the nft script is rewritten.

## Expiry

A rule with `expires_at > 0` is treated as inactive once the Unix time
passes. The scheduler loop picks this up within 30 s.

## Templates

Canned rulesets are compiled into the binary
([`internal/firewall/templates.go`](../internal/firewall/templates.go)):

| Name            | Intent                                               |
|-----------------|------------------------------------------------------|
| `ssh-only`      | Permit TCP/22 from mesh + established, deny rest     |
| `web-server`    | Open 80 + 443 inbound                                |
| `postgres`      | 5432 from mesh only                                  |
| `dns`           | 53/udp + 53/tcp inbound                              |
| `ssh-ratelimit` | SSH allowed but new sessions throttled (5/minute)    |
| `mesh-only`     | Allow anything from 10.200.0.0/16, deny rest         |

Apply via `gmeshctl firewall templates apply --name ssh-only --reset`.
The backend's DB-authored rules remain the source of truth; templates
are for quick bootstrapping and demos.

## Performance

Apply of 1000 rules through the gRPC → engine → translator → memory
backend path measured at **~430 ms** end-to-end on an M-series Mac in
development mode. Real nftables `nft -f -` adds parsing + transaction
commit of roughly 50 – 200 ms for 1000 rules on a commodity Linux VM
(measured separately in Phase 9 chaos tests).

## CLI

```bash
gmeshctl firewall status
gmeshctl firewall apply --file rules.json --policy deny --reset
gmeshctl firewall reset
gmeshctl firewall templates list
gmeshctl firewall templates apply --name ssh-only
```

The JSON rule file is a top-level array of proto-compatible rule objects:

```json
[
  { "id": 1, "name": "allow ssh", "enabled": true, "priority": 100,
    "action": 1, "protocol": 2, "port_range": "22",
    "direction": "inbound", "conn_state": "NEW,ESTABLISHED" }
]
```

See `FirewallAction` + `FirewallProtocol` enum values in the proto file
for numeric codes (1=allow, 2=deny, …).

## What's not yet wired

- Per-rule comment encoding (`r<id>`) is rendered into nft output but
  `HitCounts` currently matches via `fmt.Sscanf("r%d", ...)` only. Future
  work: switch to nft rule handles for exact matching.
- iptables hit-count parsing (`iptables -vnxL` output walk). Returns an
  empty map for now.
- Cross-family policies (IPv6-only rules). Our translator targets `inet`
  which covers both — fine for the common case — but per-family
  overrides aren't exposed.
