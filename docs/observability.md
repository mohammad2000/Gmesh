# Observability

Gmeshd exposes three observation surfaces:

1. **Event stream** — live push feed over gRPC server-streaming
   (`SubscribeEvents` RPC).
2. **HealthCheck RPC** — point-in-time per-peer health snapshot.
3. **Structured logs** — `log/slog` JSON or text output to journald.

Phase 9 adds a Prometheus `/metrics` endpoint. This doc covers what
already ships.

## Event stream

The daemon runs an in-process event bus ([`internal/events/events.go`](../internal/events/events.go)).
Every state change inside gmeshd publishes an `Event` with a type tag, an
optional `peer_id`, a timestamp, and a JSON payload whose schema depends
on the type. Subscribers attach via gRPC and drain the stream until they
disconnect.

### Types shipped today

| Type                 | Emitted by                               | Payload fields                                           |
|----------------------|------------------------------------------|----------------------------------------------------------|
| `mesh_joined`        | `Join` RPC                               | mesh_ip, interface, listen_port, public_key, node_id     |
| `mesh_left`          | `Leave` RPC                              | reason                                                   |
| `peer_added`         | `AddPeer` RPC                            | mesh_ip, endpoint, public_key                            |
| `peer_removed`       | `RemovePeer` RPC                         | mesh_ip                                                  |
| `peer_connected`     | Health monitor (rising edge from FAILING)| score, status, previous                                  |
| `peer_disconnected`  | Health monitor (N×FAILING ticks)         | score, reason, previous                                  |
| `health_update`      | Health monitor (every tick, per peer)    | score, status, latency_ms, handshake_age_s               |
| `scope_connected`    | `ScopeConnect` RPC                       | mesh_ip, netns, public_key, listen_port                  |
| `scope_disconnected` | `ScopeDisconnect` RPC                    | —                                                        |
| `relay_setup`        | `SetupRelay` / `AllocateWSTunnel` RPC    | relay / url, local_endpoint, kind ("udp" or "ws")        |
| `firewall_applied`   | `ApplyFirewall` on success               | applied, failed, errors, backend                         |
| `firewall_error`     | `ApplyFirewall` with any failed rule     | applied, failed, errors, backend                         |
| `nat_changed`        | (Phase 9) periodic NAT re-discovery      | old.{ip,port,type}, new.{ip,port,type}                   |
| `peer_method_change` | (Phase 9) strategy engine swap           | peer_id, from, to, reason                                |

### Subscription semantics

- **Filter**: `SubscribeEventsRequest.types` is a list of type strings.
  Empty list = subscribe to everything. Filter is exact-match on the
  `type` field.
- **Buffering**: each subscription has a 256-event channel. If the
  subscriber falls behind, newer events drop silently (counter
  incremented, logged once per burst of 100). This ensures the publisher
  is never blocked by a slow consumer.
- **Ordering**: events are emitted in publication order. A subscriber
  that starts mid-flight never sees events older than its start time.
- **Delivery guarantee**: at-most-once. No persistence, no replay.

### Wire format

```proto
message Event {
    int64  timestamp_unix_ms = 1;
    string type              = 2;
    string peer_id           = 3;  // "" when not peer-scoped
    string payload_json      = 4;  // per-type schema, see table above
}
```

### Client usage

Go:

```go
stream, _ := client.SubscribeEvents(ctx, &gmeshv1.SubscribeEventsRequest{
    Types: []string{"health_update", "peer_disconnected"},
})
for {
    ev, err := stream.Recv()
    if err != nil { break }
    handle(ev)
}
```

CLI:

```bash
gmeshctl events tail
gmeshctl events tail --type peer_connected,peer_disconnected
gmeshctl events tail --json | jq .
```

Sample output:

```
2026-04-19T06:49:17-04:00  scope_connected     peer=42  {"mesh_ip":"10.200.0.42","netns":"scope-42","public_key":"7Xhp..."}
2026-04-19T06:49:17-04:00  firewall_applied    peer=    {"applied":1,"backend":"memory","errors":[],"failed":0}
2026-04-19T06:49:32-04:00  health_update       peer=7   {"score":86,"status":"good","latency_ms":22,"handshake_age_s":41}
```

## Health monitor

Runs inside `Engine.Start`, ticks at `health.check_interval_seconds`
(default 30 s). On each tick it:

1. Calls `RefreshPeerStats` to pull fresh WG dump data (rx/tx, last
   handshake) into the peer registry.
2. For each peer, computes a 0 – 100 score via `health.Score` using:
   - 30 % handshake freshness (fresh <150 s / stale >600 s)
   - 30 % ping success + RTT bucket
   - 20 % traffic rate
   - 20 % connection-method quality (DIRECT=100, …, WS_TUNNEL=20)
3. Classifies into 5 status buckets (Excellent >90, Good >70,
   Degraded >50, Poor >30, Failing ≤30).
4. Emits `health_update` with the fresh score.
5. Tracks consecutive FAILING ticks; after
   `reconnect_failing_threshold` (default 3), emits
   `peer_disconnected`.
6. When a peer recovers from FAILING, emits `peer_connected`.

When **any** peer is below Good, the next tick runs at
`degraded_check_interval_seconds` (default 15 s) for faster recovery
detection. Otherwise it stays at the normal interval.

### Configuration

```yaml
health:
  check_interval_seconds: 30
  degraded_check_interval_seconds: 15
  max_concurrent_pings: 5              # reserved for Phase 9 ping engine
  reconnect_failing_threshold: 3
```

### Point-in-time snapshot

`gmeshctl health` calls the `HealthCheck` RPC which computes scores
synchronously (without waiting for the next tick):

```
$ gmeshctl health
PEER   STATUS     SCORE  LATENCY  HANDSHAKE_AGE  LOSS
100    good       78     22 ms    41 s           0.000
200    degraded   62     180 ms   220 s          0.002
```

The RPC scorer is intentionally simpler than the monitor's formula — it
weights method + latency + handshake age only, since rate integration
needs a window.

## Structured logs

`log/slog` with format picked by `log.format` (`text` or `json`). All
major lifecycle + error events log with structured key-value pairs:

```
time=2026-04-19T06:49:15.113-04:00 level=INFO msg="scope connected (stub)" id=42 mesh_ip=10.200.0.42
time=2026-04-19T06:49:16.228-04:00 level=INFO msg="firewall schedule re-applied" live=12
```

Configure per service via systemd drop-ins:

```
[Service]
Environment="GMESH_LOG_LEVEL=debug"
Environment="GMESH_LOG_FORMAT=json"
```

(Config file takes precedence; env vars override.)

## Tuning for low-overhead monitoring

- **Quiet subscription**: pass a tight type filter
  (`--type peer_disconnected,firewall_error`) — the bus short-circuits
  mismatched types before channel send.
- **Long tail of health_update**: if UIs only care about status
  transitions, filter to
  `peer_connected,peer_disconnected,peer_method_change` and drop
  `health_update` entirely. The monitor still evaluates every tick, the
  UI just doesn't see the noise.
- **Sampling**: Phase 9 adds an optional `health.sample_every_n` knob
  to skip `health_update` emission every Nth tick while keeping the
  rising/falling edge events.

## Integration with GritivaCore

The bridge in Phase 8 subscribes to every `gmesh.Event` and translates
relevant ones into WebSocket messages on the GritivaCore backend bus
so the frontend Mesh UI can render realtime state. See
[`migration-from-python.md`](migration-from-python.md#events) for the
mapping table.
