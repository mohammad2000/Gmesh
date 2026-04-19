"""Python bridge between the GritivaCore agent and the gmeshd daemon.

This package wraps the gmesh gRPC API as an async-friendly Python client,
translates GritivaCore's WebSocket mesh protocol into gmesh RPC calls,
and translates gmesh event streams back into WebSocket messages that the
backend already understands.

Typical use from inside ``agentNew/``:

    from gmesh_bridge import GmeshBridge, Translator, EventForwarder

    bridge = await GmeshBridge.connect(socket_path="/run/gmesh.sock")
    translator = Translator(bridge)

    async for ws_msg in incoming_from_backend():
        await translator.handle(ws_msg)

    async def forward_events():
        async for ws_msg in EventForwarder(bridge).stream():
            await send_to_backend(ws_msg)
"""

from .client import GmeshBridge  # noqa: F401
from .translator import Translator  # noqa: F401
from .events import EventForwarder  # noqa: F401
from .dispatcher import USE_GMESH, choose_dispatcher  # noqa: F401

__all__ = [
    "GmeshBridge",
    "Translator",
    "EventForwarder",
    "USE_GMESH",
    "choose_dispatcher",
]
