# gRPC Protocol Reference

Canonical source: [`api/proto/gmesh/v1/gmesh.proto`](../api/proto/gmesh/v1/gmesh.proto).
Generated Go code: [`gen/gmesh/v1/`](../gen/gmesh/v1/).

Transport: **gRPC over Unix socket** at `/run/gmesh.sock` (configurable).

## Service overview

```
service GMesh {
  // Lifecycle
  rpc Join, Leave, Status, Version

  // Peers
  rpc AddPeer, RemovePeer, UpdatePeer, ListPeers, GetPeerStats

  // NAT & traversal
  rpc DiscoverNAT, HolePunch

  // Relay / WS tunnel
  rpc SetupRelay, AllocateWSTunnel

  // Health
  rpc HealthCheck

  // Scope peers
  rpc ScopeConnect, ScopeDisconnect

  // Firewall
  rpc ApplyFirewall, ResetFirewall, GetFirewallStatus

  // Event stream (server-streaming)
  rpc SubscribeEvents
}
```

## Idempotency

| RPC             | Idempotent | Key                     |
|-----------------|-----------|-------------------------|
| Join            | Yes (NOP if already joined) | — |
| Leave           | Yes       | —                       |
| AddPeer         | Yes       | (peer_id, mesh_ip)      |
| UpdatePeer      | Yes       | peer_id                 |
| RemovePeer      | Yes       | peer_id                 |
| ScopeConnect    | Yes       | scope_id                |
| ScopeDisconnect | Yes       | scope_id                |
| ApplyFirewall   | Replace-all semantics | — |
| ResetFirewall   | Yes       | —                       |

## Event types (`SubscribeEvents` stream)

| `type`               | When emitted                                               | `payload_json` schema                                   |
|----------------------|------------------------------------------------------------|---------------------------------------------------------|
| `peer_connected`     | WG handshake verified with peer                            | `{peer_id, method, endpoint, latency_ms}`               |
| `peer_disconnected`  | Peer handshake stale AND ping fails                        | `{peer_id, reason}`                                     |
| `peer_method_change` | Live connection migrated to a different method             | `{peer_id, from, to, reason}`                           |
| `nat_changed`        | Re-discovery detected different external IP / port / type  | `{old, new}`                                            |
| `health_update`      | Periodic health snapshot (configurable interval)           | `{peer_id, score, status, latency_ms, packet_loss}`     |
| `firewall_applied`   | Apply completed                                            | `{applied, failed, errors[]}`                           |
| `firewall_error`     | Apply failed or rule rejected                              | `{rule_id, reason}`                                     |
| `scope_connected`    | Scope peer fully set up                                    | `{scope_id, scope_mesh_ip}`                             |
| `scope_disconnected` | Scope peer torn down                                       | `{scope_id}`                                            |
| `relay_setup`        | Relay session established                                  | `{peer_id, relay_endpoint, session_id}`                 |

## Error model

Standard gRPC status codes. In addition:

- `FAILED_PRECONDITION` — `Join` not called yet
- `ALREADY_EXISTS` — `Join` called twice
- `NOT_FOUND` — peer_id / scope_id unknown
- `INVALID_ARGUMENT` — malformed mesh_ip / endpoint / public_key
- `UNAVAILABLE` — WG backend unreachable (kernel module missing + wg-go failed)
- `INTERNAL` — bug / unexpected state; include stack trace in detail

## Versioning

The proto lives under `gmesh.v1`. Any breaking change goes to `v2` —
`v1` is preserved for the lifetime of the 1.x release branch.
