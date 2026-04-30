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

import ipaddress
import logging
import socket
from typing import Any, Dict, List

import grpc

from .client import GmeshBridge

log = logging.getLogger("gmesh_bridge.translator")


# LAN candidate networks we'll advertise as reachable over an "lan"
# endpoint. Mirrors gmesh's internal/nat/lan.go isPrivateV4 set:
# RFC1918, link-local, and CGNAT.
_LAN_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]


def _enumerate_lan_endpoints(port: int) -> List[Dict[str, Any]]:
    """Return every private IPv4 on a non-tunnel interface as an
    {address, kind, priority} dict keyed to the given UDP port.

    Used by the mesh_join re-entry path: when gmeshd returns
    ALREADY_EXISTS (agent reconnected without the daemon restarting)
    the fresh-join LAN list isn't returned, so we enumerate here so
    the backend still sees up-to-date LAN candidates on every
    reconnect — a phone that switches Wi-Fi networks, for example.
    """
    try:
        import psutil  # lazy — agent has it, standalone tools may not
    except ImportError:
        return []

    out: List[Dict[str, Any]] = []
    try:
        addrs_by_iface = psutil.net_if_addrs()
    except Exception:
        return []
    for iface, addrs in addrs_by_iface.items():
        if _is_tunnel_iface(iface):
            continue
        for a in addrs:
            if a.family != socket.AF_INET:
                continue
            try:
                ip = ipaddress.ip_address(a.address)
            except ValueError:
                continue
            if any(ip in net for net in _LAN_NETS):
                out.append({
                    "address": f"{ip}:{port}",
                    "kind": "lan",
                    "priority": 10,
                })
    return out


def _same_mesh_prefix(a: str, b: str) -> bool:
    """Return True when two mesh IPs share the same top-two octets
    (≈ /16). Used to tolerate primary+alias setups like 10.250.0.1 +
    10.200.0.1 on the same gmesh node — those are intentionally stacked
    on one wg-gmesh interface via MeshPeerAddress aliases.
    """
    try:
        pa = a.split(".")
        pb = b.split(".")
        return len(pa) >= 2 and len(pb) >= 2 and pa[0] == pb[0]
    except Exception:
        return False


def _is_tunnel_iface(name: str) -> bool:
    # Skip tunnel interfaces AND container/CNI virtual bridges. Their IPs
    # (docker0 → 172.17.0.1, br-* → 172.18.0.1, etc.) live entirely
    # inside this host and advertising them as LAN candidates poisons
    # the remote peer's endpoint list. Mirrors internal/nat/lan.go.
    n = name.lower()
    prefixes = (
        "utun", "wg", "tun", "tap", "gpd", "zt", "tailscale",
        "docker", "br-", "veth", "cni", "cali", "flannel",
        "weave", "cilium", "podman", "virbr", "vnet", "kube",
    )
    return any(n.startswith(p) for p in prefixes)


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

        Accepts every shape the backend emits, so individual clients
        (Mac, Linux) don't each need their own _flatten. Shapes seen in
        the wild:
          {"type": "mesh_join", ...flat fields...}
          {"action": "mesh_join", "data": {...fields...}, "peer_id": N}
          {"action": "mesh_add_peer", "peer_id": N, "remote_peer": {...}}
        """
        msg = _normalize(msg)
        t = msg.get("type", "")
        handler = _HANDLERS.get(t)
        if handler is None:
            raise UnknownMessageType(t)
        try:
            return await handler(self, msg)
        except Exception as ex:  # pragma: no cover — defensive logging
            log.exception("bridge handler %s failed", t)
            return {"type": _error_type_for(t), "error": str(ex), "success": False}


def _normalize(msg: Dict[str, Any]) -> Dict[str, Any]:
    """Fold every wrapper shape into a flat dict handlers can read
    directly. Handlers should only reference top-level keys after this.
    Leaves the input untouched; returns a fresh dict.
    """
    out: Dict[str, Any] = {}
    # "type" wins if present; fall back to "action" (backend cmd side).
    out["type"] = msg.get("type") or msg.get("action") or ""
    for wrapper in ("data", "remote_peer"):
        inner = msg.get(wrapper)
        if isinstance(inner, dict):
            for k, v in inner.items():
                if k not in out:
                    out[k] = v
    for k, v in msg.items():
        if k in ("type", "action", "data", "remote_peer"):
            continue
        if k not in out:
            out[k] = v
    return out


# ── Individual handlers ────────────────────────────────────────────────

async def _handle_mesh_join(self: Translator, msg: dict) -> dict:
    try:
        res = await self.bridge.join(
            mesh_ip=msg["mesh_ip"],
            listen_port=int(msg.get("listen_port", 51820)),
            interface_name=msg.get("interface_name", "wg-gmesh"),
            network_cidr=msg.get("network_cidr", "10.200.0.0/16"),
            node_id=msg.get("node_id", ""),
        )
        public_key = res["public_key"]
        private_key_encrypted = res.get("private_key_encrypted", "")
        endpoint = res.get("endpoint", "")
        # JoinResponse.endpoints now carries the LAN IPs gmeshd
        # enumerated via internal/nat.LocalEndpoints (plus any reflexive
        # candidate). Forward them unchanged to the backend so
        # mesh_peer_endpoints can race LAN before WAN for same-subnet
        # peers. List of {address, kind, priority}.
        join_endpoints = res.get("endpoints") or []
        # Always snapshot Status so we can return the *actual* port and
        # interface the daemon is running with (config file, existing
        # wg-quick setup, or a concurrent mesh_leave+rejoin might make
        # these diverge from what the backend requested).
        try:
            st_now = await self.bridge.status()
        except Exception:
            st_now = {}
    except grpc.aio.AioRpcError as ex:
        # gmeshd refuses duplicate joins with ALREADY_EXISTS. This is
        # NOT an error from the backend's point of view — the backend
        # just wants the agent to be in that mesh, and it already is.
        # Fall through to Status so we can return the same response
        # shape (public_key, endpoint) the backend parser expects.
        if ex.code() != grpc.StatusCode.ALREADY_EXISTS:
            raise
        log.info("mesh_join already in place; returning current state")
        st_now = await self.bridge.status()
        st = st_now
        # Status exposes the local node's actual public_key + interface
        # + whatever listen_port gmeshd ended up using. The backend
        # trusts these values over what it itself sent in the mesh_join
        # command — which may differ from the daemon's runtime state
        # (different config file, port collision, OS-rename like macOS
        # utunN, etc.). Returning the truth here is what keeps the DB
        # consistent without manual psql updates.
        public_key = st.get("public_key", "")
        private_key_encrypted = ""
        endpoint = ""
        # gmeshd only returns the LAN candidate list on a fresh Join;
        # for already-joined re-entries we enumerate the same set in
        # Python here so the backend still gets current interface state
        # every time the agent re-connects. Matches internal/nat/lan.go
        # in the Go daemon (RFC1918 + link-local + CGNAT ranges, skip
        # tunnel interfaces).
        port = int(st.get("listen_port") or msg.get("listen_port") or 51820)
        join_endpoints = _enumerate_lan_endpoints(port)
        # The daemon can hold multiple mesh IPs on one WireGuard
        # interface (primary + secondary aliases — see MeshPeerAddress
        # in app/models/mesh_advanced.py). A node with primary
        # 10.250.0.1 also serving 10.200.0.1 is perfectly legal and
        # hitting mesh_join with either IP should succeed. Only raise
        # the conflict error when the requested IP is in a completely
        # different /16 — that's when the caller really is confused.
        st_mesh = st.get("mesh_ip")
        req_mesh = msg["mesh_ip"]
        if st_mesh and st_mesh != req_mesh and not _same_mesh_prefix(st_mesh, req_mesh):
            return {
                "type": "mesh_error",
                "success": False,
                "error": (
                    f"gmeshd is already joined to a DIFFERENT mesh "
                    f"({st_mesh} vs requested {req_mesh}). "
                    f"Call mesh_leave first, or use the existing mesh."
                ),
                "error_type": "already_joined_conflict",
                "action": "mesh_join",
            }
    # Report the *actual* listen port + interface the daemon ended up
    # using (vs whatever the backend asked for in the mesh_join cmd).
    # Backend's handle_mesh_joined uses these to keep the DB aligned
    # with reality — otherwise peer-sync hands siblings a stale port
    # and WireGuard handshakes silently time out.
    runtime_listen_port = (st_now.get("listen_port") if isinstance(st_now, dict) else None)
    runtime_iface = (st_now.get("interface") if isinstance(st_now, dict) else None)
    out = {
        "type": "mesh_joined",
        "success": True,
        # Echo peer_id back so the backend's handle_mesh_joined can
        # look up the right MeshPeer row and update its fields
        # (status, public_key, endpoint). Without this echo the
        # handler saw peer_id=None and bailed early with
        # "MeshPeer not found", leaving public_key stuck at the
        # "placeholder_public_key::..." sentinel forever.
        "peer_id": msg.get("peer_id"),
        "mesh_ip": msg["mesh_ip"],
        "public_key": public_key,
        "private_key_encrypted": private_key_encrypted,
        "endpoint": endpoint,
    }
    if runtime_listen_port:
        out["listen_port"] = runtime_listen_port
    if runtime_iface:
        out["interface_name"] = runtime_iface
    if join_endpoints:
        out["endpoints"] = join_endpoints
    return out


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
        endpoints=msg.get("endpoints") or [],
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
        endpoints=msg.get("endpoints") or [],
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




# ── Ingress profile bridge handlers ───────────────────────────────────
# Backend → agent → bridge → gmeshd. The agent emits mesh.ingress.created
# / mesh.ingress.removed / mesh.ingress.error to the backend after the
# RPC returns; the backend uses those acks to flip
# mesh_ingress_profiles.status.

def _ingress_payload_from_msg(msg: dict) -> dict:
    """Backend may send the IngressProfile fields either at top level or
    nested under `data`. Normalise both shapes into a flat dict the
    client.ingress_to_proto helper understands."""
    p = dict(msg.get("data") or {})
    for k in (
        "id", "name", "enabled",
        "backend_peer_id", "backend_scope_id", "backend_ip", "backend_port",
        "edge_peer_id", "edge_port", "protocol",
        "allowed_source_cidrs", "require_mtls",
    ):
        if k in msg and k not in p:
            p[k] = msg[k]
    return p


async def _handle_mesh_ingress_create(self: Translator, msg: dict) -> dict:
    profile = _ingress_payload_from_msg(msg)
    try:
        result = await self.bridge.ingress_create(profile)
        return {
            "type":     "mesh.ingress.created",
            "success":  True,
            "id":       result.get("id"),
            "profile_id": result.get("id"),
            "profile":  result,
        }
    except Exception as ex:
        return {
            "type":     "mesh.ingress.error",
            "success":  False,
            "id":       profile.get("id"),
            "profile_id": profile.get("id"),
            "error":    str(ex),
            "operation": "create",
        }


async def _handle_mesh_ingress_update(self: Translator, msg: dict) -> dict:
    profile = _ingress_payload_from_msg(msg)
    try:
        result = await self.bridge.ingress_update(profile)
        return {
            "type":     "mesh.ingress.created",
            "success":  True,
            "id":       result.get("id"),
            "profile_id": result.get("id"),
            "profile":  result,
        }
    except Exception as ex:
        return {
            "type":     "mesh.ingress.error",
            "success":  False,
            "id":       profile.get("id"),
            "profile_id": profile.get("id"),
            "error":    str(ex),
            "operation": "update",
        }


async def _handle_mesh_ingress_delete(self: Translator, msg: dict) -> dict:
    p = msg.get("data") or {}
    pid = int(msg.get("id") or p.get("id") or msg.get("profile_id") or 0)
    if pid <= 0:
        return {
            "type":     "mesh.ingress.error",
            "success":  False,
            "error":    "missing profile id",
            "operation": "delete",
        }
    try:
        await self.bridge.ingress_delete(pid)
        return {
            "type":     "mesh.ingress.removed",
            "success":  True,
            "id":       pid,
            "profile_id": pid,
        }
    except Exception as ex:
        return {
            "type":     "mesh.ingress.error",
            "success":  False,
            "id":       pid,
            "profile_id": pid,
            "error":    str(ex),
            "operation": "delete",
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

# Late registration: handler defs live below the _HANDLERS
# dict literal, so we splice them in here after both exist.
_HANDLERS["mesh_ingress_create"] = _handle_mesh_ingress_create
_HANDLERS["mesh_ingress_update"] = _handle_mesh_ingress_update
_HANDLERS["mesh_ingress_delete"] = _handle_mesh_ingress_delete
