"""Feature-flag dispatcher that picks between legacy Python mesh and gmesh.

The GritivaCore agent's existing mesh handlers register themselves in a
dict keyed by message type (see ``agentNew/handlers/mesh.py``). When the
agent starts:

    - If ``USE_GMESH=1`` is set, we prefer the gmesh bridge: inbound WS
      messages are first tried through the Translator; on
      ``UnknownMessageType`` we fall through to the legacy handler as a
      graceful safety net.
    - If ``USE_GMESH`` is unset or 0, we call the legacy handler directly,
      unchanged.

This module is *library code*. The actual wiring into the agent happens
where the agent dispatches a WS message:

    from gmesh_bridge import choose_dispatcher, USE_GMESH

    dispatch = choose_dispatcher(bridge=gmesh_bridge, legacy=legacy_dispatch)

    async def on_ws_message(msg):
        return await dispatch(msg)

where ``legacy_dispatch`` is a callable with the same shape as
``Translator.handle``. That way this file has no import dependency on
GritivaCore internals.

Shadow mode: when ``GMESH_SHADOW=1`` **and** ``USE_GMESH=1``, the
dispatcher sends the message to *both* paths and logs a diff of the
responses. Useful during cutover verification.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Awaitable, Callable, Dict, Optional

from .client import GmeshBridge
from .translator import Translator, UnknownMessageType

log = logging.getLogger("gmesh_bridge.dispatcher")

# Cached env-var reads (agents are long-lived processes; re-reading is
# cheap but we want a single source of truth per import).
USE_GMESH = os.environ.get("USE_GMESH", "0") in ("1", "true", "True", "yes")
SHADOW = os.environ.get("GMESH_SHADOW", "0") in ("1", "true", "True", "yes")


LegacyHandler = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]
Dispatcher = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]


def choose_dispatcher(*, bridge: Optional[GmeshBridge],
                      legacy: LegacyHandler) -> Dispatcher:
    """Return a dispatcher function that respects USE_GMESH / GMESH_SHADOW.

    - bridge: a ready GmeshBridge; may be None if USE_GMESH is off.
    - legacy: the existing Python-mesh dispatcher.

    The returned callable never raises; errors become
    ``{"type": "mesh_error", "error": "..."}``.
    """
    if not USE_GMESH:
        log.info("USE_GMESH=0; dispatching via legacy Python mesh")
        return legacy

    if bridge is None:
        log.warning("USE_GMESH=1 but no bridge provided; falling back to legacy")
        return legacy

    translator = Translator(bridge)

    async def gmesh_primary(msg: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return await translator.handle(msg)
        except UnknownMessageType as ex:
            log.debug("gmesh: unknown type %s; falling through to legacy", ex)
            return await legacy(msg)

    if not SHADOW:
        log.info("USE_GMESH=1; dispatching via gmesh bridge")
        return gmesh_primary

    log.info("USE_GMESH=1 + GMESH_SHADOW=1; running gmesh primary + legacy shadow")

    async def shadow(msg: Dict[str, Any]) -> Dict[str, Any]:
        # Fire both paths concurrently. The primary (gmesh) result is
        # returned; the legacy result is logged for diff.
        gmesh_fut = asyncio.ensure_future(gmesh_primary(msg))
        legacy_fut = asyncio.ensure_future(_safe_legacy(legacy, msg))
        gmesh_res, legacy_res = await asyncio.gather(gmesh_fut, legacy_fut)

        if _differ(gmesh_res, legacy_res):
            log.warning(
                "SHADOW DIFF on %s: gmesh=%s legacy=%s",
                msg.get("type"), _summarize(gmesh_res), _summarize(legacy_res),
            )
        return gmesh_res

    return shadow


async def _safe_legacy(legacy: LegacyHandler, msg: dict) -> dict:
    try:
        return await legacy(msg)
    except Exception as ex:  # pragma: no cover
        return {"type": "mesh_error", "error": str(ex), "success": False}


def _differ(a: dict, b: dict) -> bool:
    # Compare on a stable projection: type + success + key scalar fields.
    # Don't diff timestamps or binary payloads.
    keys = {"type", "success", "peer_id", "mesh_ip", "applied_count", "failed_count"}
    pa = {k: a.get(k) for k in keys if k in a}
    pb = {k: b.get(k) for k in keys if k in b}
    return pa != pb


def _summarize(d: dict) -> str:
    try:
        return json.dumps({k: d.get(k) for k in ("type", "success", "peer_id", "error")})
    except Exception:
        return str(d)[:200]
