# A/B Traffic Splitter / Exit Pool (Phase 16)

An egress profile can declare a **weighted pool** of exit peers instead
of a single `exit_peer_id`. gmesh distributes new flows across the
pool via nftables `numgen`, keyed by weight.

## Data model

```proto
message EgressProfile {
  int64          exit_peer_id = 11;
  repeated int64 exit_pool    = 12;  // weighted peer IDs
  repeated int32 exit_weights = 13;  // same length as exit_pool
  ...
}
```

- `exit_pool` and `exit_weights` must have the same length.
- Weights need not sum to 100; gmesh treats them as relative counters
  (e.g. `[3, 1]` = 75 %/25 %).
- Sum must be > 0.
- When `exit_pool` is set, `exit_peer_id` is ignored.

## CLI

```
gmeshctl egress create --id 7 --name ab-split \
    --exit-pool 3 --exit-pool 5 \
    --exit-weights 70 --exit-weights 30 \
    --dest-ports 443 --protocol tcp
```

## Linux backend

For N pool entries the backend installs:

1. One routing table per entry: `default via <mesh_ip_i> dev wg-gmesh
   table PoolTableID(profile_id, i)`.
2. One `ip rule` per entry: `from fwmark <PoolFwMark(id, i)> lookup
   <PoolTableID(id, i)>`. Priorities are staggered so rules don't
   collide with the profile's own single-exit priority space.
3. One nft rule with a `numgen inc mod <sum_weights>` vmap:

```
meta mark set numgen inc mod 100 map {
    0-69   : 0x1000007,   # peer 3
    70-99  : 0x2000007,   # peer 5
}
ct mark set meta mark
```

`numgen inc` gives deterministic round-robin; swap to `numgen random`
for a statistical distribution.

## Interaction with pathmon auto-failover

`BackupExitPeerID` on the profile is a **single-exit** concept and is
ignored when `exit_pool` is set. For pool-level failover, drop a peer
from the pool (Update) or watch `path_down` events and update weights
accordingly — a future phase will wire this automatically.

## Interaction with quota

The nft counter is attached to the single pool-scoped rule — all pool
traffic shares one counter. Quota shifts (`quota_shift`) still swap
the profile's `exit_peer_id`, but on a pool profile this is a no-op
until an operator removes `exit_pool` first. Use quotas on a
single-exit profile; use pools for steady-state distribution.
