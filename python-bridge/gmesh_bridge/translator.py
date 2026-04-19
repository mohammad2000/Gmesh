"""Translate GritivaCore backend WebSocket messages into gmesh gRPC calls.

The GritivaCore backend sends agent-bound messages like:

    {"type": "mesh_join", "mesh_ip": "10.200.0.7", "listen_port": 51820, ...}
    {"type": "mesh_add_peer", "peer_id": 42, "mesh_ip": "10.200.0.8", ...}
    {"type": "scope_mesh_connect", "scope_id": 12, ...}

The Translator class here receives those dicts, dispatches to the right
GmeshBridge method, and returns a response dict that mimics what the
legacy Python mesh would have produced — so the backend handler code
doesn't need to know whether the agent is running the Python mesh or
the Go daemon.

Unknown message types raise ``UnknownMessageType``. The dispatcher above
us catches that and falls through to the legacy Python mesh.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from .client import GmeshBridge

log = logging.getLogger("gmesh_bridge.translator")


class UnknownMessageType(Exception):
    """Raised when the inbound message type has no gmesh mapping."""


class Translator:
    """Dispatches backend WS messages to gmeshd."""

    def __init__(self, bridge: GmeshBridge):
        self.bridge = bridge

    async def handle(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Execute one inbound message, returning a response dict.

        The response mirrors the legacy mesh protocol so the backend's
        existing parsers (handlers/mesh.py in GritivaCore) keep working.
        """
        t = msg.get("type", "")
        handler = _HANDLERS.get(t)
        if handler is None:
            raise UnknownMessageType(t)
        try:
            return await handler(self, msg)
        except Exception as ex:  # pragma: no cover — defensive logging
            log.exception("bridge handler %s failed", t)
            return {"type": _error_type_for(t), "error": str(ex), "success": False}


# ── Individual handlers ────────────────────────────────────────────────

async def _handle_mesh_join(self: Translator, msg: dict) -> dict:
    res = await self.bridge.join(
        mesh_ip=msg["mesh_ip"],
        listen_port=int(msg.get("listen_port", 51820)),
        interface_name=msg.get("interface_name", "wg-gritiva"),
        network_cidr=msg.get("network_cidr", "10.200.0.0/16"),
        node_id=msg.get("node_id", ""),
    )
    return {
        "type": "mesh_joined",
        "success": True,
        "mesh_ip": msg["mesh_ip"],
        "public_key": res["public_key"],
        "private_key_encrypted": res["private_key_encrypted"],
        "endpoint": res["endpoint"],
    }


async def _handle_mesh_leave(self: Translator, msg: dict) -> dict:
    await self.bridge.leave(reason=msg.get("reason", "backend requested"))
    return {"type": "mesh_left", "success": True}


async def _handle_mesh_add_peer(self: Translator, msg: dict) -> dict:
    peer = await self.bridge.add_peer(
        peer_id=int(msg["peer_id"]),
        mesh_ip=msg["mesh_ip"],
        public_key=msg["public_key"],
        endpoint=msg.get("endpoint", ""),
        allowed_ips=msg.get("allowed_ips"),
        keepalive=int(msg.get("keepalive", 25)),
    )
    return {
        "type": "mesh_peer_connected",
        "success": True,
        "peer_id": peer.id,
        "mesh_ip": peer.mesh_ip,
        "status": peer.status,
    }


async def _handle_mesh_remove_peer(self: Translator, msg: dict) -> dict:
    await self.bridge.remove_peer(int(msg["peer_id"]))
    return {"type": "mesh_peer_removed", "success": True, "peer_id": int(msg["peer_id"])}


async def _handle_mesh_update_peer(self: Translator, msg: dict) -> dict:
    peer = await self.bridge.update_peer(
        peer_id=int(msg["peer_id"]),
        endpoint=msg.get("endpoint", ""),
        allowed_ips=msg.get("allowed_ips"),
        keepalive=int(msg.get("keepalive", 0)),
    )
    return {"type": "mesh_peer_updated", "success": True, "peer_id": peer.id}


async def _handle_mesh_hole_punch(self: Translator, msg: dict) -> dict:
    res = await self.bridge.hole_punch(
        peer_id=int(msg.get("peer_id", 0)),
        remote_endpoint=msg.get("remote_endpoint", ""),
        fire_at_unix_ms=int(msg.get("fire_at_unix_ms", 0)),
    )
    return {
        "type": "mesh_hole_punch_result",
        "success": res["success"],
        "method_used": res["method_used"],
        "latency_ms": res["latency_ms"],
        "error": res["error"],
    }


async def _handle_mesh_nat_discovery(self: Translator, msg: dict) -> dict:
    nat = await self.bridge.discover_nat(force=bool(msg.get("force", False)))
    return {
        "type": "mesh_nat_discovery",
        "success": True,
        "external_ip": nat["external_ip"],
        "external_port": nat["external_port"],
        "supports_hole_punching": nat["supports_hole_punch"],
        "is_relay_capable": nat["is_relay_capable"],
    }


async def _handle_mesh_status(self: Translator, msg: dict) -> dict:
    st = await self.bridge.status()
    st.update({"type": "mesh_status", "success": True})
    return st


async def _handle_mesh_setup_relay(self: Translator, msg: dict) -> dict:
    res = await self.bridge.setup_relay(
        peer_id=int(msg["peer_id"]),
        relay_endpoint=msg["relay_endpoint"],
        relay_session_id=msg["relay_session_id"],
    )
    return {"type": "mesh_relay_allocated", "success": res["ok"], "error": res["error"]}


async def _handle_mesh_ws_tunnel_allocated(self: Translator, msg: dict) -> dict:
    res = await self.bridge.allocate_ws_tunnel(
        peer_id=int(msg["peer_id"]),
        backend_ws_url=msg["backend_ws_url"],
    )
    return {"type": "mesh_ws_tunnel_allocated", "success": res["ok"], "error": res["error"]}


async def _handle_scope_mesh_connect(self: Translator, msg: dict) -> dict:
    p = await self.bridge.scope_connect(
        scope_id=int(msg["scope_id"]),
        scope_mesh_ip=msg.get("scope_mesh_ip") or msg.get("mesh_ip", ""),
        scope_netns=msg.get("namespace") or msg.get("scope_netns", ""),
        veth_cidr=msg.get("veth_cidr", ""),
        vm_veth_ip=msg.get("vm_veth_ip", ""),
        scope_ip=msg.get("scope_ip", ""),
        gateway_mesh_ip=msg.get("gateway_ip") or msg.get("gateway_mesh_ip", ""),
        listen_port=int(msg.get("listen_port", 0)),
    )
    return {
        "type": "scope_mesh_connected",
        "success": True,
        "scope_id": int(msg["scope_id"]),
        "public_key": p["public_key"],
        "mesh_ip": p["mesh_ip"],
    }


async def _handle_scope_mesh_disconnect(self: Translator, msg: dict) -> dict:
    await self.bridge.scope_disconnect(int(msg["scope_id"]))
    return {"type": "scope_mesh_disconnected", "success": True,
            "scope_id": int(msg["scope_id"])}


async def _handle_mesh_firewall_apply(self: Translator, msg: dict) -> dict:
    res = await self.bridge.apply_firewall(
        rules=msg.get("rules", []),
        default_policy=msg.get("default_policy", "accept"),
        force_reset=bool(msg.get("force_reset", False)),
    )
    return {
        "type": "mesh_firewall_applied",
        "success": res["failed"] == 0,
        "applied_count": res["applied"],
        "failed_count": res["failed"],
        "errors": res["errors"],
    }


async def _handle_mesh_firewall_reset(self: Translator, msg: dict) -> dict:
    await self.bridge.reset_firewall()
    return {"type": "mesh_firewall_reset", "success": True}


async def _handle_mesh_firewall_status(self: Translator, msg: dict) -> dict:
    st = await self.bridge.firewall_status()
    st.update({"type": "mesh_firewall_status", "success": True})
    return st


async def _handle_mesh_health_check(self: Translator, msg: dict) -> dict:
    peers = await self.bridge.health_check(peer_id=int(msg.get("peer_id", 0)))
    return {"type": "mesh_health_check", "success": True, "peers": peers}


# ── Dispatch table ────────────────────────────────────────────────────

_HANDLERS = {
    "mesh_join": _handle_mesh_join,
    "mesh_leave": _handle_mesh_leave,
    "mesh_add_peer": _handle_mesh_add_peer,
    "mesh_remove_peer": _handle_mesh_remove_peer,
    "mesh_update_peer": _handle_mesh_update_peer,
    "mesh_hole_punch": _handle_mesh_hole_punch,
    "mesh_nat_discovery": _handle_mesh_nat_discovery,
    "mesh_status": _handle_mesh_status,
    "mesh_setup_relay": _handle_mesh_setup_relay,
    "mesh_ws_tunnel_allocated": _handle_mesh_ws_tunnel_allocated,
    "scope_mesh_connect": _handle_scope_mesh_connect,
    "scope_mesh_disconnect": _handle_scope_mesh_disconnect,
    "mesh_firewall_apply": _handle_mesh_firewall_apply,
    "mesh_firewall_reset": _handle_mesh_firewall_reset,
    "mesh_firewall_status": _handle_mesh_firewall_status,
    "mesh_health_check": _handle_mesh_health_check,
}


def _error_type_for(inbound_type: str) -> str:
    if inbound_type.startswith("scope_"):
        return "scope_mesh_error"
    if inbound_type.startswith("mesh_firewall_"):
        return "mesh_firewall_error"
    return "mesh_error"


def known_message_types() -> list:
    """Return the sorted list of WS message types this Translator handles."""
    return sorted(_HANDLERS.keys())
