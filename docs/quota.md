# Quota (Phase 13)

A **Quota** attaches a byte budget to an egress profile. When the
profile's nftables counter crosses configured thresholds, the Quota
Manager emits events and (optionally) swaps the profile's exit peer to
a cheaper or unmetered backup.

## Data model

```proto
message Quota {
  int64  id                = 1;
  string name              = 2;
  bool   enabled           = 3;

  int64  egress_profile_id = 4;
  string period            = 5;   // hourly | daily | weekly | monthly
  int64  limit_bytes       = 6;

  double warn_at           = 7;   // 0..1 → emit quota_warning
  double shift_at          = 8;   // 0..1 → emit quota_shift + auto-swap
  double stop_at           = 9;   // 0..1 → emit quota_stop (Phase 13.5 adds DROP)

  int64  backup_profile_id = 10;  // required if shift_at > 0
}
```

Thresholds are fractions of `limit_bytes`. Typical settings:

```
warn_at  = 0.80    # alert at 80 %
shift_at = 0.95    # flip to backup at 95 %
stop_at  = 1.00    # event only, for now
```

## Evaluator loop

`quota.Manager.Run` ticks every **10 s** (configured in
`Engine.Start`). One tick per quota does:

1. Roll over the period if `now >= period_end` — zeroes `used_bytes`,
   clears latches, resets the nft counter, emits `quota_reset`.
2. Read the live byte count from the CounterReader. On Linux this is
   the nftables counter attached to the egress profile's mark rule; on
   macOS / tests it's an in-memory counter.
3. Compare `used / limit` to the thresholds. For each crossing:
   - Latch the corresponding `*_fired` flag so the event fires once.
   - Publish the event.
4. If `quota_shift` fired AND `backup_profile_id != 0` AND an engine
   `Switcher` is wired, call `SwapExitPeer` to atomically update the
   egress profile's exit peer. From the data-plane's perspective this
   is a rule flush + replay inside `nft -f -` — all traffic routes
   through the backup peer's mesh IP from the next packet forward.

## Events

| Type             | When                                    | Payload fields                                  |
|------------------|-----------------------------------------|-------------------------------------------------|
| `quota_warning`  | used ≥ limit × warn_at (rising edge)    | egress_profile_id, used_bytes, limit_bytes, fraction |
| `quota_shift`    | used ≥ limit × shift_at (rising edge)   | + backup_profile_id                             |
| `quota_stop`     | used ≥ limit × stop_at (rising edge)    | same shape as warning                           |
| `quota_reset`    | period rollover OR manual reset         | reason                                          |

All events surface on the same gRPC `SubscribeEvents` stream as every
other engine event.

## nftables counter

Every egress profile mark rule carries `counter` as of Phase 13:

```
add rule inet gmesh-egress egress_mark_out
    oifname != @protected_oif ip daddr != @protected_daddr
    <profile-specific filter>
    counter
    meta mark set 0x1XXXXXXX
    comment "egress-<id>"
```

`nft -j list table inet gmesh-egress` returns each rule's `packets` +
`bytes` counter. The Quota Manager's Linux CounterReader parses that
JSON, matches by the `egress-<id>` comment, and extracts `bytes`.

## Reset semantics

- **Period rollover**: automatic at window boundary.
  - Hourly: on the hour in UTC
  - Daily: 00:00 UTC
  - Weekly: Monday 00:00 UTC
  - Monthly: day 1, 00:00 UTC
- **Manual reset** (`gmeshctl quota reset`): zeros counter +
  clears latches + emits `quota_reset` with reason=manual.

## CLI

```
gmeshctl quota create \
    --id 1 --name home-vps-cap \
    --profile 5 --limit-bytes $((1024*1024*1024*1024)) \
    --period monthly \
    --warn-at 0.80 --shift-at 0.95 \
    --backup-profile 6

gmeshctl quota list
gmeshctl quota usage              # forces a tick + dumps live state
gmeshctl quota usage --id 1       # single quota
gmeshctl quota reset --id 1
gmeshctl quota delete --id 1
```

Sample `quota list` output:

```
ID  NAME          PROFILE  PERIOD   LIMIT         USED         PERCENT  STATUS
1   home-vps-cap  5        monthly  1099511627776 873812039172 79.5%    ok
2   mobile-tether 8        daily    10737418240   9664576421   90.0%    WARN
```

## Interaction with egress

- A Quota stores **egress_profile_id** (the watched profile) and
  **backup_profile_id** (where to shift).
- Creating a quota does **not** install any nftables rule — it piggybacks
  on the egress profile's existing counter.
- Shift swaps the egress profile's `exit_peer_id` in place. The profile
  still exists; its routing flips to the backup peer. Ingress profiles,
  firewall rules, other egress profiles on the same table are
  untouched.

## Limits in Phase 13

- **No hard DROP at stop.** `quota_stop` emits an event but doesn't
  install a DROP rule. Adding a DROP with priority 0 in the
  egress_mark chain is Phase 13.5. For now, operators handle
  `quota_stop` by disabling the profile manually (or scripting an
  event listener).
- **Counter is cumulative within a period.** No per-second rate view.
  For rate, subscribe to `quota_warning` crossings on finer-grained
  quotas (e.g. hourly). Bandwidth-over-time dashboards come with
  Phase 9's Prometheus metrics (`gmesh_quota_bytes{quota_id="1"}` is
  reserved).
- **Single backup.** `backup_profile_id` is a scalar. For a three-tier
  cascade, chain quotas: quota-on-primary shifts to backup-1;
  quota-on-backup-1 shifts to backup-2; etc.

## Example: monthly 1 TB cap with automatic fallback

```
# Primary: all VPS egress (profile 5).
gmeshctl egress create --id 5 --name vps-primary \
    --exit-peer 3 --dest 0.0.0.0/0 --priority 100

# Backup: home ISP direct (profile 6; exit-peer is the node itself).
gmeshctl egress create --id 6 --name home-direct \
    --exit-peer 1 --dest 0.0.0.0/0 --priority 200

# 1 TB monthly cap: at 80 % warn, at 95 % flip to home-direct.
gmeshctl quota create --id 1 --name vps-tier \
    --profile 5 --period monthly \
    --limit-bytes $((1024*1024*1024*1024)) \
    --warn-at 0.80 --shift-at 0.95 \
    --backup-profile 6
```

When `used >= 973 GB` (95 %), gmeshd:

1. Emits `quota_shift` with egress_profile_id=5, backup_profile_id=6.
2. Swaps profile 5's exit_peer_id from 3 (VPS) to 1 (home node).
3. nft rules re-installed in a single transaction; new flows use home
   ISP directly. Existing TCP flows keep conntrack state and complete
   on the old path until they end.
4. At month rollover, quota resets, counter zeroes, and gmeshd
   swaps profile 5 back to VPS automatically (Phase 13.5 adds the
   "rollback on reset" flag; for now, use an event listener that
   calls `UpdateEgressProfile` to flip back).

## Non-goals

- Cross-host quota aggregation. Each node's quota tracks only its own
  traffic. Fleet-wide "project consumed 5 TB across 3 exits" lives in
  the GritivaCore backend, fed by `SubscribeEvents` + the Prometheus
  bytes counter.
- Prepayment / billing integration. Belongs in the backend; gmeshd
  just emits usage events.
- Predictive budgeting ("at current rate you'll hit cap in 3 days").
  Trivial to compute at the backend by observing the counter's
  derivative over time; not needed inside gmeshd.
