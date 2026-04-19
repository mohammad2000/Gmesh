# End-to-end scenario matrix

The four base scenarios that motivated Tier 1 (Phases 11–13) and their
verification status on a live 2-node Linux integration environment
(core + fsn1).

Topology:

```
  core (100.71.50.46)              fsn1 (100.89.201.68)
  mesh_ip 10.250.0.1               mesh_ip 10.250.0.20
  public  174.93.143.156           public  188.245.175.144
  (residential ISP, CGNAT)         (Hetzner Falkenstein)
         │                                   │
         └────────── wg-gmesh tunnel ────────┘
```

## Scenario B — Public port forwarding (Ingress)

> "VM's port 8000 forwarded to VPS so it's reachable from a public domain."

```
# On core (the "home VM"):
python3 -m http.server 8099  →  listens on 10.250.0.1:8099

# On fsn1 (the "VPS edge"):
gmeshctl ingress create \
    --id 1 --name web --backend-ip 10.250.0.1 --backend-port 8099 \
    --edge-peer 3 --edge-port 8080 --protocol tcp
```

**Test from any internet client:**

```
$ curl http://188.245.175.144:8080/
<h1>hello from gritivacore</h1>
```

**Status: ✅ VERIFIED** — full tunnel from public internet → fsn1:8080 →
nft DNAT → wg-gmesh → core:8099 → response back via MASQUERADE
conntrack.

## Scenario C — Same node has both ingress + egress

> "One machine both accepts traffic in (from a VPS front) and sends
> traffic out (through a VPS exit)."

**Setup:** keep Scenario B's ingress on fsn1, additionally install an
egress profile on core that sends HTTPS traffic via fsn1:

```
gmeshctl egress create \
    --id 5 --name core-port443-via-fsn1 \
    --exit-peer 3 --dest 1.1.1.1/32 --dest-ports 443 --protocol tcp
```

**Verify both work:**

```
# Ingress unchanged:
$ curl http://188.245.175.144:8080/
<h1>hello from gritivacore</h1>          ✅

# Egress: HTTPS to 1.1.1.1 from core goes via fsn1's public IP.
# (Limited to one destination to demonstrate the principle without
# breaking Tailscale management — see Phase 11 guards.)
```

Both nftables tables coexist without interference:

```
$ nft list tables
table inet gmesh-egress      # on core
table inet gmesh-ingress     # on fsn1
```

**Status: ✅ VERIFIED** (ingress side). Egress portion has the known
Phase 11 limitation for `dest=0/0 + bare host` flows on nodes with
nested overlays — using a specific dest CIDR / port sidesteps the
issue. See `docs/egress-profile.md` troubleshooting.

## Scenario A — Scope-based egress

> "A specific project's traffic (not the whole machine) exits through
> the VPS."

**Setup:**

```
# Create scope + dedicated WG interface in its own netns:
gmeshctl scope connect --id 42 --mesh-ip 10.250.0.42 \
    --veth-cidr 10.60.42.0/30 \
    --vm-veth-ip 10.60.42.1 --scope-ip 10.60.42.2 \
    --listen-port 52099

# Egress scoped to the project's veth CIDR:
gmeshctl egress create --id 10 --name scope42-via-fsn1 \
    --source-scope 42 --source-cidr 10.60.42.0/30 \
    --exit-peer 3 --dest 0.0.0.0/0 --priority 50
```

**Expected:** `ip netns exec scope-42 curl ipify.org` returns fsn1's
public IP (not core's).

**Status: ⚠️ PARTIAL** — nftables installs correctly:

```
chain egress_mark_pre {
    oifname != @protected_oif
    ip daddr != @protected_daddr
    ip saddr 10.60.42.0/30          # scope-specific match
    counter
    meta mark set 0x1000000a
    comment "egress-10"
}
```

Scope-based source matching works; what still needs an operator step
is ensuring the scope netns is visible to the shell running `curl`.
The scope netns is created by `gmeshd` as `scope-42` (bind-mounted at
`/var/run/netns/scope-42`); `ip netns exec scope-42 <cmd>` should
work host-wide but requires `ip` iproute2 ≥ 4.10 and no restrictive
systemd unit sandboxing.

## Scenario D — Quota triggers egress profile shift

> "Above a traffic threshold, shift part of the load to a cheaper exit."

**Setup:**

```
# Primary egress via VPS.
gmeshctl egress create --id 1 --name primary --exit-peer 3 \
    --dest 0.0.0.0/0 --dest-ports 443 --protocol tcp

# Backup (would normally be a different peer; demo uses same).
gmeshctl egress create --id 2 --name backup --exit-peer 3 \
    --dest 0.0.0.0/0 --dest-ports 443 --protocol tcp

# 1 GB monthly quota, warn at 80%, shift to backup at 95%.
gmeshctl quota create --id 1 --name monthly \
    --profile 1 --limit-bytes $((1024*1024*1024)) \
    --period monthly --warn-at 0.80 --shift-at 0.95 \
    --backup-profile 2
```

**Evaluator ticks every 10 s. When counter crosses threshold:**

- `gmeshctl quota list` shows `WARN` or `SHIFTED` status.
- Event stream emits `quota_warning` / `quota_shift`.
- On shift: gmeshd automatically flips profile 1's `exit_peer_id` to 2.
- On period rollover: counter zeroes, latches clear, profile can be
  restored by listening for `quota_reset` in your automation.

**Status: ✅ MECHANISM VERIFIED** — unit tests cover warn/shift/stop/
reset + period rollover (10 tests). Live Linux test created the quota
and saw the evaluator tick every 10s, but the test period had no
traffic so `used_bytes` stayed 0. The `counter` keyword is now
installed in every egress rule as of v0.4.0 so production traffic
accumulates into the counter immediately.

Full production verification needs a real workload running through
the primary profile — any HTTPS flow for a few minutes demonstrates
the counter counting up and the automatic shift at threshold.

## Summary

| Scenario | Feature chain             | Status                                                 |
|----------|---------------------------|--------------------------------------------------------|
| **A**    | Scope + Egress Profile    | ⚠️ Nft rules correct; netns visibility follow-up       |
| **B**    | Ingress Profile           | ✅ Full end-to-end verified                            |
| **C**    | Egress + Ingress coexist  | ✅ Both profiles coexist cleanly                       |
| **D**    | Egress + Quota + switcher | ✅ Mechanism verified; awaits prod traffic for counter |

## Known limitations (deferred)

1. **Bare-host `dest=0/0` egress on nodes with nested overlays.**
   Outer WG packets can inherit the egress fwmark and re-route
   through wg-gmesh causing an encapsulation loop. Phase 11 guards
   protect management traffic (Tailscale, LAN) but the edge case
   remains. Scope-based or port-specific profiles avoid it.
   Real fix: conntrack-aware mark in Phase 14 + Path Monitor's
   kill-switch.

2. **Quota hard DROP.** `quota_stop` is an event only. Automatic DROP
   rule at the stop threshold lands in Phase 13.5.

3. **Quota rollback on reset.** At period rollover, the backup-shifted
   profile stays shifted. Operators listen for `quota_reset` and
   manually `UpdateEgressProfile` to restore. Phase 13.5 adds an
   optional `auto_rollback` flag.
