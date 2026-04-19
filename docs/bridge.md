# Python bridge (Phase 8)

The bridge is the cutover infrastructure between GritivaCore's Python
agent and gmeshd. Package source lives in [`python-bridge/`](../python-bridge/),
generated gRPC stubs live in [`gen/py/`](../gen/py/).

## Why a separate package

gmeshd is the only authoritative source for mesh state once we cut over.
The agent runs alongside it, translates backend WS messages into gmesh
gRPC calls, and forwards gmesh events back out. The bridge sits between
those two protocols — exactly the place the legacy
`agentNew/mesh/manager.py` occupied in the Python-mesh era.

Shipping it as a standalone Python package (not inline in GritivaCore)
means:

- We can version the gmesh protocol independently of the agent.
- We can test bridge behaviour without a full GritivaCore stack
  (the `tests/` directory spins up a real gmeshd subprocess).
- Migration-day wiring is a one-line import + one-line dispatcher swap.

## The three translation layers

### 1. Inbound: WS → gRPC (`translator.py`)

Backend sends, e.g.:

```json
{"type": "mesh_add_peer", "peer_id": 7, "mesh_ip": "10.200.0.7",
 "public_key": "pk...", "endpoint": "1.2.3.4:51820",
 "allowed_ips": ["10.200.0.7/32"]}
```

`Translator.handle` dispatches to `GmeshBridge.add_peer(...)` and shapes
the reply into the legacy response:

```json
{"type": "mesh_peer_connected", "success": true,
 "peer_id": 7, "mesh_ip": "10.200.0.7", "status": "connecting"}
```

Unknown types raise `UnknownMessageType` so the dispatcher can fall
through to the legacy Python path.

### 2. Outbound: gmesh events → WS (`events.py`)

`EventForwarder.stream()` is an async iterator over backend-shaped
messages. Every gmesh event is mapped (or filtered) per this table:

| gmesh event          | backend WS type              | Extra payload                |
|----------------------|------------------------------|------------------------------|
| `peer_connected`     | `mesh_peer_connected`        | peer_id, score, status       |
| `peer_disconnected`  | `mesh_peer_disconnected`     | peer_id, reason, score       |
| `peer_method_change` | `mesh_peer_method_change`    | peer_id, from, to, reason    |
| `health_update`      | `mesh_metrics`               | peer_id, latency_ms, score   |
| `scope_connected`    | `scope_mesh_connected`       | scope_id, mesh_ip, netns, …  |
| `scope_disconnected` | `scope_mesh_disconnected`    | scope_id                     |
| `firewall_applied`   | `mesh_firewall_applied`      | applied, failed, backend     |
| `firewall_error`     | `mesh_firewall_error`        | errors, backend              |
| `relay_setup` (udp)  | `mesh_relay_allocated`       | peer_id, relay, local_ep     |
| `relay_setup` (ws)   | `mesh_ws_tunnel_allocated`   | peer_id, url, local_ep       |
| `mesh_joined`        | `mesh_joined` (echo)         | full join payload            |
| `mesh_left`          | `mesh_left`                  | reason                       |
| `nat_changed`        | `mesh_nat_discovery`         | old, new                     |

### 3. Feature flag: `USE_GMESH` (`dispatcher.py`)

```python
from gmesh_bridge import choose_dispatcher

dispatch = choose_dispatcher(bridge=gmesh_bridge, legacy=legacy_dispatch)
async for ws_msg in incoming:
    await send_back(await dispatch(ws_msg))
```

Env-var behaviour:

| Env             | Behaviour                                                  |
|-----------------|------------------------------------------------------------|
| `USE_GMESH=0`   | Bridge is a no-op; every message goes to legacy.           |
| `USE_GMESH=1`   | Bridge primary; unknown types fall through to legacy.      |
| +`GMESH_SHADOW=1` | Primary returns gmesh result; legacy runs in parallel   |
|                 | and responses are diffed + logged. Use during cutover.    |

## Cutover procedure

### Pre-flight checklist

1. gmesh `.deb` installed on the agent (Phase 9 packaging).
2. `/run/gmesh.sock` exists and `gmeshctl status` responds.
3. `gmesh-bridge` installed in the agent venv + `gen/py/` on
   `PYTHONPATH`.
4. Legacy mesh code **still present** in `agentNew/` — we don't delete it
   until Phase 10.

### Day-0: shadow mode

```
systemctl set-environment USE_GMESH=1 GMESH_SHADOW=1
systemctl restart gritiva-agent
```

Watch the logs for "SHADOW DIFF" warnings. Every diff is an asymmetry
that needs investigation before flipping shadow off.

### Day-N: flip the switch

Once 72 hours go by with zero shadow diffs:

```
systemctl set-environment USE_GMESH=1 GMESH_SHADOW=0
systemctl restart gritiva-agent
```

### Rollback

```
systemctl set-environment USE_GMESH=0
systemctl restart gritiva-agent
```

Re-enters legacy path instantly. The gmeshd daemon stays running (harmless),
so rollback is <5s.

### Post-cutover (Phase 10)

Delete:

- `agentNew/mesh/` (22 files)
- `agentNew/handlers/mesh.py`
- `agentNew/handlers/mesh_firewall_handler.py`
- The `USE_GMESH` env var — gmesh becomes unconditional.
- `if USE_GMESH:` branches in `agentNew/handlers/__init__.py`.

## Observability during cutover

```
# Stream gmesh events (debugging)
gmeshctl events tail

# Only look at disconnects to spot flakiness
gmeshctl events tail --type peer_disconnected,peer_method_change

# Check a specific peer's live health
gmeshctl peer show --id 7
gmeshctl health --json | jq '.peers[] | select(.peer_id==7)'
```

## Open questions for day-of-migration

- **Config persistence**: gmeshd's `state.json` holds the private key.
  On first start with `USE_GMESH=1`, the agent still sends `mesh_join` —
  the bridge calls `Join`, gmeshd generates a fresh keypair, and the
  backend DB learns the new public key. This is a minor rotation event;
  backend will re-send `auto_connect_peers` afterward.
- **Signed relay tokens**: the current bridge passes the session ID as
  string; `SetupRelay` RPC signs with a placeholder. Before the first
  production relay use, wire cfg.Relay.Secret on both gmeshd and
  `gmesh-relay` to a shared secret sourced from the backend.
- **Firewall rule serialization**: GritivaCore stores rules with numeric
  enum values matching our proto; no conversion needed beyond what
  `GmeshBridge._rule_to_proto` already does.
