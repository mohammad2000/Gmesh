# Hole punching

Gmesh implements three NAT-traversal strategies (plus plain `DIRECT` and
`UPnP`). The engine picks a ladder based on the local + remote NAT types
and tries methods in order until one succeeds or all are exhausted.

## Strategies

### `STUN_HOLE_PUNCH`

Both peers know each other's external endpoint from STUN / backend
coordination. Each sends a short burst of UDP probes to the remote's
external endpoint; the first outgoing packet creates the local NAT pinhole,
and once both have sent, bidirectional pinholes are open.

- **Parameters:** 8 probes, 100 ms spacing, 2 s reply window.
- **Works for:** open ↔ any, FullCone ↔ cone/restricted,
  PortRestrictedCone ↔ PortRestrictedCone.
- **Fails for:** symmetric NAT on either side (remote's return port is
  unpredictable).

### `SIMULTANEOUS_OPEN`

The backend picks a `fire_at_unix_ms` in the near future and sends it to
both peers. Each waits until that exact moment, then fires a tight burst
(5 probes, 10 ms spacing). This defeats NATs that only hold outgoing state
for a narrow window and need the reverse probe to arrive nearly
simultaneously.

- **Parameters:** `max_wait` = 3 s (refuses fire_at beyond that); 5 probes,
  10 ms spacing, 1.5 s reply window.
- **Clock sensitivity:** NTP-synced nodes only. fire_at drift > 100 ms
  degrades success rate.

### `BIRTHDAY_PUNCH`

For symmetric NATs. The remote NAT picks a new external port per
destination, but ports are usually contiguous. Send 256 probes to shuffled
destination ports centered on the remote's last-seen port; statistically,
one probe hits the right (future) port before the NAT allocates it for
the return path.

- **Parameters:** 256 probes by default, 5 ms spacing, 3 s reply window.
- **Success rate:** ~50 % on commodity symmetric NATs, higher if both
  sides birthday-punch simultaneously.
- **Important:** This consumes egress bandwidth briefly (~1 MB for 256
  probes × 4 kB). Running two at once is fine; fleet-wide coordination
  would need rate-limiting.

## Strategy ladder

`SelectLadder(Classification{Local, Remote})` returns a method list in
preferred order. See [`internal/traversal/ladder.go`](../internal/traversal/ladder.go).

| Classification                       | Ladder |
|--------------------------------------|--------|
| both Open                            | `[DIRECT]` |
| one Open, one non-symmetric          | `DIRECT → UPNP → STUN_HOLE_PUNCH` |
| both cone/restricted/port-restricted | `UPNP → STUN → SIMOPEN → BIRTHDAY → RELAY` |
| any Symmetric                        | `UPNP → STUN → SIMOPEN → BIRTHDAY → RELAY → WS_TUNNEL` |
| both Unknown                         | everything |

## Port-sharing limitation

On Linux, once WireGuard is bound to `:51820` (kernel module), userspace
cannot open a second listener on the same port — `net.ListenUDP` returns
`EADDRINUSE`. The `LocalAddr` option on each strategy therefore binds
**ephemeral** ports for probes, not the WG port.

For **cone NATs** this is fine: the pinhole opened by any source port
serves as an endpoint-independent mapping, so a WG handshake from the WG
port still traverses the NAT. For stricter NATs, the pinhole is
source-port-specific and won't help WG.

**The clean fix** is to switch to userspace WireGuard (wireguard-go)
which gives Gmesh full control over the UDP socket, letting probe and
handshake share a port. Scheduled for Phase 1.5 if measurements show it's
needed in production.

Tailscale solves the same problem by running wireguard-go exclusively.
For deployments where every NAT is cone (most home / small-office), the
kernel-WG path is sufficient.

## Verification

Each `Outcome` carries `Success` + `LatencyMS` + `Error`. A strategy
reports success when it receives **any** UDP reply to its probes on the
socket. Real connectivity verification (WireGuard handshake completing)
happens at a higher layer in Phase 7's health monitor — once the peer is
installed with the endpoint the strategy validated.

Failed attempts emit a debug log and return `Success: false`. The
strategy engine moves to the next method in the ladder without rolling
back any NAT state (nothing to roll back — probes don't leave lasting
side-effects).

## Telemetry

Every attempt is logged with peer_id, method, and RTT / error. Phase 9
will expose these as Prometheus metrics:

```
gmesh_holepunch_attempts_total{method="stun_hole_punch",outcome="success"}
gmesh_holepunch_latency_ms_bucket{method="birthday_punch",le="500"}
```

Fleet operators can see which method dominates for their NAT mix and tune
ladders accordingly (e.g. skip `DIRECT` on carrier-NAT-only fleets).
