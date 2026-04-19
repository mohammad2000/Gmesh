# gmesh-bridge

Python package that lets the GritivaCore agent talk to `gmeshd` over
gRPC. Wraps the generated protobuf stubs (in `../gen/py/`) in an async
client plus translation layers for the existing mesh WebSocket protocol
and the gmesh event stream.

## Install

```bash
# Direct from the repo (editable):
pip install -e .

# Or vendor into the agent's venv:
cp -r gmesh_bridge /opt/gritiva-agent/lib/
PYTHONPATH=/opt/gritiva-agent/lib:/opt/gmesh/gen/py python3 -c "import gmesh_bridge"
```

## Usage

```python
import os, asyncio
from gmesh_bridge import GmeshBridge, Translator, EventForwarder, choose_dispatcher

async def main():
    bridge = await GmeshBridge.connect("/run/gmesh.sock")
    translator = Translator(bridge)

    # Dispatch an inbound backend WS message.
    resp = await translator.handle({
        "type": "mesh_add_peer",
        "peer_id": 7,
        "mesh_ip": "10.200.0.7",
        "public_key": "pk...",
        "endpoint": "1.2.3.4:51820",
        "allowed_ips": ["10.200.0.7/32"],
    })
    print(resp)  # {"type": "mesh_peer_connected", "success": True, ...}

    # Forward gmesh events back to the backend WS.
    async for ws_msg in EventForwarder(bridge).stream():
        await send_to_backend(ws_msg)  # your function

asyncio.run(main())
```

## Feature flag

```bash
export USE_GMESH=1            # route inbound WS through gmesh
export GMESH_SHADOW=1         # also run legacy path, log diffs
```

`choose_dispatcher(bridge=..., legacy=...)` returns a single callable that
honours both env vars and falls through to `legacy` for any message type
gmesh doesn't know about.

## Development

```bash
# Regenerate Python stubs from ../api/proto/*.
../scripts/gen-proto-py.sh

# Run integration tests (starts gmeshd as a subprocess).
pip install -e '.[dev]'
pytest
```

## What's in the package

| Module          | Purpose                                                             |
|-----------------|---------------------------------------------------------------------|
| `client.py`     | `GmeshBridge` — async wrapper over all gRPC methods.                |
| `translator.py` | Translate inbound backend WS messages → gmesh calls.                |
| `events.py`     | `EventForwarder` — translate gmesh events → outbound WS messages.   |
| `dispatcher.py` | `choose_dispatcher` — `USE_GMESH`/`GMESH_SHADOW` env-var routing.   |

## Coverage of backend protocol

`translator.known_message_types()` returns the 16 WS message types
currently wired through gmesh:

```
mesh_add_peer         mesh_firewall_apply    mesh_health_check
mesh_firewall_reset   mesh_firewall_status   mesh_hole_punch
mesh_join             mesh_leave             mesh_nat_discovery
mesh_remove_peer      mesh_setup_relay       mesh_status
mesh_update_peer      mesh_ws_tunnel_allocated
scope_mesh_connect    scope_mesh_disconnect
```

Any other message type raises `UnknownMessageType`; `choose_dispatcher`
catches that and falls through to the legacy Python mesh handler.

## Compatibility matrix

| gmeshd | gmesh-bridge | gRPC wire   | Notes                       |
|--------|--------------|-------------|-----------------------------|
| 0.1.x  | 0.1.x        | gmesh.v1    | Phase 0 – Phase 8 baseline  |

Breaking proto changes bump to `gmesh.v2` per
[docs/protocol.md](../docs/protocol.md#versioning); bridge version will
track accordingly.
