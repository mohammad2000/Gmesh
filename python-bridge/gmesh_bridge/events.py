"""Translate gmesh event stream into GritivaCore backend WS messages.

EventForwarder subscribes to ``SubscribeEvents`` and yields dicts ready
to be sent verbatim to the GritivaCore backend. The backend's existing
``handlers/mesh.py`` already knows how to route these messages (most
were in use in the legacy Python mesh — we just re-emit them with the
payload fields the backend expects).

Mapping table (see docs/bridge.md for the full schema):

    peer_connected      → {"type": "mesh_peer_connected", "peer_id": N, ...}
    peer_disconnected   → {"type": "mesh_peer_disconnected", "peer_id": N, ...}
    health_update       → {"type": "mesh_metrics", "peer_id": N, ...}
    nat_changed         → {"type": "mesh_nat_discovery", ...}
    firewall_applied    → {"type": "mesh_firewall_applied", ...}
    firewall_error      → {"type": "mesh_firewall_error", ...}
    scope_connected     → {"type": "scope_mesh_connected", ...}
    scope_disconnected  → {"type": "scope_mesh_disconnected", ...}
    mesh_joined         → {"type": "mesh_joined", ...}  (echo for backends
                                                         that didn't
                                                         originate the
                                                         join)
    mesh_left           → {"type": "mesh_left", ...}
    relay_setup         → {"type": "mesh_relay_allocated", ...} with
                          kind=udp | "mesh_ws_tunnel_allocated" with kind=ws
"""

from __future__ import annotations

import json
import logging
from typing import AsyncIterator, Dict, List, Optional

from .client import GmeshBridge

log = logging.getLogger("gmesh_bridge.events")


# Default filter: the subset of events the backend cares about today.
# Client can override to include health_update for realtime dashboards.
DEFAULT_TYPES = [
    "peer_connected",
    "peer_disconnected",
    "peer_method_change",
    "scope_connected",
    "scope_disconnected",
    "firewall_applied",
    "firewall_error",
    "relay_setup",
    "mesh_joined",
    "mesh_left",
    "nat_changed",
]


class EventForwarder:
    """Subscribe to gmeshd's event bus; yield backend-shaped messages."""

    def __init__(self, bridge: GmeshBridge, types: Optional[List[str]] = None):
        self.bridge = bridge
        self.types = types if types is not None else list(DEFAULT_TYPES)

    async def stream(self) -> AsyncIterator[Dict]:
        async for ev in self.bridge.subscribe_events(self.types):
            out = _translate_event(ev)
            if out is not None:
                yield out


def _translate_event(ev: Dict) -> Optional[Dict]:
    t = ev.get("type", "")
    payload = _parse_json(ev.get("payload_json", ""))
    peer_id = _parse_int(ev.get("peer_id", ""))

    if t == "peer_connected":
        return {
            "type": "mesh_peer_connected",
            "peer_id": peer_id,
            "score": payload.get("score"),
            "status": payload.get("status"),
        }
    if t == "peer_disconnected":
        return {
            "type": "mesh_peer_disconnected",
            "peer_id": peer_id,
            "reason": payload.get("reason", ""),
            "score": payload.get("score"),
        }
    if t == "peer_method_change":
        return {
            "type": "mesh_peer_method_change",
            "peer_id": peer_id,
            **payload,
        }
    if t == "health_update":
        return {
            "type": "mesh_metrics",
            "peer_id": peer_id,
            "latency_ms": payload.get("latency_ms"),
            "score": payload.get("score"),
            "status": payload.get("status"),
            "handshake_age_s": payload.get("handshake_age_s"),
        }
    if t == "scope_connected":
        return {
            "type": "scope_mesh_connected",
            "scope_id": peer_id,
            **{k: v for k, v in payload.items() if k in
               ("mesh_ip", "netns", "public_key", "listen_port")},
        }
    if t == "scope_disconnected":
        return {"type": "scope_mesh_disconnected", "scope_id": peer_id}
    if t == "firewall_applied":
        return {
            "type": "mesh_firewall_applied",
            "applied": payload.get("applied", 0),
            "failed": payload.get("failed", 0),
            "backend": payload.get("backend", ""),
        }
    if t == "firewall_error":
        return {
            "type": "mesh_firewall_error",
            "errors": payload.get("errors", []),
            "backend": payload.get("backend", ""),
        }
    if t == "relay_setup":
        kind = payload.get("kind", "udp")
        if kind == "ws":
            return {
                "type": "mesh_ws_tunnel_allocated",
                "peer_id": peer_id,
                "url": payload.get("url", ""),
                "local_endpoint": payload.get("local_endpoint", ""),
            }
        return {
            "type": "mesh_relay_allocated",
            "peer_id": peer_id,
            "relay": payload.get("relay", ""),
            "local_endpoint": payload.get("local_endpoint", ""),
        }
    if t == "mesh_joined":
        return {"type": "mesh_joined", **payload}
    if t == "mesh_left":
        return {"type": "mesh_left", **payload}
    if t == "nat_changed":
        return {"type": "mesh_nat_discovery", **payload}

    log.debug("no mapping for event type %s", t)
    return None


def _parse_json(s: str) -> dict:
    if not s:
        return {}
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def _parse_int(s: str) -> int:
    if not s:
        return 0
    try:
        return int(s)
    except ValueError:
        return 0
