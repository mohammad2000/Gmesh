"""Thin async wrapper around the gmesh gRPC client."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, AsyncIterator, Iterable, List, Optional

# Allow imports of the generated stubs when running out of the repo tree
# (i.e. before the bridge is pip-installed). In production we rely on the
# stubs being in site-packages.
_HERE = os.path.dirname(os.path.abspath(__file__))
_GEN_PY = os.path.normpath(os.path.join(_HERE, "..", "..", "gen", "py"))
if os.path.isdir(_GEN_PY) and _GEN_PY not in sys.path:
    sys.path.insert(0, _GEN_PY)

import grpc  # noqa: E402

from gmesh.v1 import gmesh_pb2, gmesh_pb2_grpc  # noqa: E402  type: ignore

log = logging.getLogger("gmesh_bridge.client")


@dataclass
class PeerView:
    """Read-only projection of a gmesh.v1.Peer."""

    id: int
    type: str
    mesh_ip: str
    endpoint: str
    public_key: str
    status: str
    method: str
    rx_bytes: int
    tx_bytes: int
    latency_ms: int
    last_handshake_unix: int


def _peer_view(p: Any) -> PeerView:
    type_map = {
        gmesh_pb2.PEER_TYPE_VM: "vm",
        gmesh_pb2.PEER_TYPE_SCOPE: "scope",
    }
    status_map = {
        gmesh_pb2.PEER_STATUS_CONNECTING: "connecting",
        gmesh_pb2.PEER_STATUS_CONNECTED: "connected",
        gmesh_pb2.PEER_STATUS_DISCONNECTED: "disconnected",
        gmesh_pb2.PEER_STATUS_ERROR: "error",
        gmesh_pb2.PEER_STATUS_ESTABLISHING: "establishing",
    }
    method_map = {
        gmesh_pb2.CONN_METHOD_DIRECT: "direct",
        gmesh_pb2.CONN_METHOD_UPNP_PORT_MAP: "upnp_port_map",
        gmesh_pb2.CONN_METHOD_STUN_HOLE_PUNCH: "stun_hole_punch",
        gmesh_pb2.CONN_METHOD_SIMULTANEOUS_OPEN: "simultaneous_open",
        gmesh_pb2.CONN_METHOD_BIRTHDAY_PUNCH: "birthday_punch",
        gmesh_pb2.CONN_METHOD_RELAY: "relay",
        gmesh_pb2.CONN_METHOD_RELAY_TCP: "relay_tcp",
        gmesh_pb2.CONN_METHOD_WS_TUNNEL: "ws_tunnel",
    }
    return PeerView(
        id=p.id,
        type=type_map.get(p.type, "unspecified"),
        mesh_ip=p.mesh_ip,
        endpoint=p.endpoint,
        public_key=p.public_key,
        status=status_map.get(p.status, "unspecified"),
        method=method_map.get(p.method, "unspecified"),
        rx_bytes=p.rx_bytes,
        tx_bytes=p.tx_bytes,
        latency_ms=p.latency_ms,
        last_handshake_unix=p.last_handshake_unix,
    )


class GmeshBridge:
    """Async client for gmeshd."""

    def __init__(self, channel: grpc.aio.Channel) -> None:
        self._chan = channel
        self._stub = gmesh_pb2_grpc.GMeshStub(channel)

    @classmethod
    async def connect(cls, socket_path: str = "/run/gmesh.sock") -> "GmeshBridge":
        channel = grpc.aio.insecure_channel(
            f"unix:{socket_path}",
            options=[
                ("grpc.keepalive_time_ms", 30_000),
                ("grpc.keepalive_timeout_ms", 10_000),
                ("grpc.max_receive_message_length", 4 * 1024 * 1024),
            ],
        )
        # Eagerly check the connection by calling Version — raises on failure.
        stub = gmesh_pb2_grpc.GMeshStub(channel)
        try:
            resp = await stub.Version(gmesh_pb2.VersionRequest(), timeout=3.0)
            log.info("connected to gmeshd %s (%s)", resp.version, resp.commit)
        except Exception:
            await channel.close()
            raise
        return cls(channel)

    async def close(self) -> None:
        await self._chan.close()

    # ── Lifecycle ──────────────────────────────────────────────────────

    async def join(self, *, mesh_ip: str, listen_port: int, interface_name: str = "wg-gritiva",
                   network_cidr: str = "10.200.0.0/16", node_id: str = "") -> dict:
        resp = await self._stub.Join(gmesh_pb2.JoinRequest(
            mesh_ip=mesh_ip, listen_port=listen_port, interface_name=interface_name,
            network_cidr=network_cidr, node_id=node_id,
        ))
        return {
            "public_key": resp.public_key,
            "private_key_encrypted": resp.private_key_encrypted,
            "endpoint": resp.endpoint,
        }

    async def leave(self, reason: str = "") -> None:
        await self._stub.Leave(gmesh_pb2.LeaveRequest(reason=reason))

    async def status(self) -> dict:
        resp = await self._stub.Status(gmesh_pb2.StatusRequest())
        return {
            "joined": resp.joined,
            "mesh_ip": resp.mesh_ip,
            "interface": resp.interface,
            "public_key": resp.public_key,
            "peer_count": resp.peer_count,
            "active_peers": resp.active_peers,
            "peers": [_peer_view(p).__dict__ for p in resp.peers],
        }

    async def version(self) -> dict:
        resp = await self._stub.Version(gmesh_pb2.VersionRequest())
        return {"version": resp.version, "commit": resp.commit, "build_date": resp.build_date}

    # ── Peers ──────────────────────────────────────────────────────────

    async def add_peer(self, *, peer_id: int, mesh_ip: str, public_key: str,
                        endpoint: str = "", allowed_ips: Optional[Iterable[str]] = None,
                        keepalive: int = 25) -> PeerView:
        resp = await self._stub.AddPeer(gmesh_pb2.AddPeerRequest(
            peer_id=peer_id, mesh_ip=mesh_ip, public_key=public_key,
            endpoint=endpoint, allowed_ips=list(allowed_ips or []), keepalive=keepalive,
        ))
        return _peer_view(resp.peer)

    async def remove_peer(self, peer_id: int) -> None:
        await self._stub.RemovePeer(gmesh_pb2.RemovePeerRequest(peer_id=peer_id))

    async def update_peer(self, peer_id: int, *, endpoint: str = "",
                           allowed_ips: Optional[Iterable[str]] = None,
                           keepalive: int = 0) -> PeerView:
        resp = await self._stub.UpdatePeer(gmesh_pb2.UpdatePeerRequest(
            peer_id=peer_id, endpoint=endpoint,
            allowed_ips=list(allowed_ips or []), keepalive=keepalive,
        ))
        return _peer_view(resp.peer)

    async def list_peers(self) -> List[PeerView]:
        resp = await self._stub.ListPeers(gmesh_pb2.ListPeersRequest())
        return [_peer_view(p) for p in resp.peers]

    # ── NAT + hole-punch ──────────────────────────────────────────────

    async def discover_nat(self, force: bool = False) -> dict:
        resp = await self._stub.DiscoverNAT(gmesh_pb2.DiscoverNATRequest(force_refresh=force))
        return {
            "external_ip": resp.nat.external_ip,
            "external_port": resp.nat.external_port,
            "supports_hole_punch": resp.nat.supports_hole_punch,
            "is_relay_capable": resp.nat.is_relay_capable,
        }

    async def hole_punch(self, *, peer_id: int, remote_endpoint: str,
                          fire_at_unix_ms: int = 0) -> dict:
        resp = await self._stub.HolePunch(gmesh_pb2.HolePunchRequest(
            peer_id=peer_id, remote_endpoint=remote_endpoint,
            fire_at_unix_ms=fire_at_unix_ms,
        ))
        return {
            "success": resp.success,
            "method_used": resp.method_used,
            "latency_ms": resp.latency_ms,
            "error": resp.error,
        }

    # ── Relay ─────────────────────────────────────────────────────────

    async def setup_relay(self, *, peer_id: int, relay_endpoint: str,
                           relay_session_id: str) -> dict:
        resp = await self._stub.SetupRelay(gmesh_pb2.SetupRelayRequest(
            peer_id=peer_id, relay_endpoint=relay_endpoint,
            relay_session_id=relay_session_id,
        ))
        return {"ok": resp.ok, "error": resp.error}

    async def allocate_ws_tunnel(self, *, peer_id: int, backend_ws_url: str) -> dict:
        resp = await self._stub.AllocateWSTunnel(gmesh_pb2.AllocateWSTunnelRequest(
            peer_id=peer_id, backend_ws_url=backend_ws_url,
        ))
        return {"ok": resp.ok, "error": resp.error}

    # ── Scope ─────────────────────────────────────────────────────────

    async def scope_connect(self, *, scope_id: int, scope_mesh_ip: str,
                             veth_cidr: str = "", vm_veth_ip: str = "",
                             scope_ip: str = "", gateway_mesh_ip: str = "",
                             scope_netns: str = "", listen_port: int = 0) -> dict:
        resp = await self._stub.ScopeConnect(gmesh_pb2.ScopeConnectRequest(
            scope_id=scope_id, scope_mesh_ip=scope_mesh_ip,
            scope_netns=scope_netns, veth_cidr=veth_cidr,
            vm_veth_ip=vm_veth_ip, scope_ip=scope_ip,
            gateway_mesh_ip=gateway_mesh_ip, listen_port=listen_port,
        ))
        return _peer_view(resp.peer).__dict__

    async def scope_disconnect(self, scope_id: int) -> None:
        await self._stub.ScopeDisconnect(gmesh_pb2.ScopeDisconnectRequest(scope_id=scope_id))

    # ── Firewall ──────────────────────────────────────────────────────

    async def apply_firewall(self, rules: list, *, default_policy: str = "accept",
                              force_reset: bool = False) -> dict:
        proto_rules = [self._rule_to_proto(r) for r in rules]
        resp = await self._stub.ApplyFirewall(gmesh_pb2.ApplyFirewallRequest(
            rules=proto_rules, force_reset=force_reset, default_policy=default_policy,
        ))
        return {
            "applied": resp.applied_count,
            "failed": resp.failed_count,
            "errors": list(resp.errors),
        }

    async def reset_firewall(self) -> None:
        await self._stub.ResetFirewall(gmesh_pb2.ResetFirewallRequest())

    async def firewall_status(self) -> dict:
        resp = await self._stub.GetFirewallStatus(gmesh_pb2.GetFirewallStatusRequest())
        return {
            "backend": resp.backend,
            "active_rules": resp.active_rules,
            "hit_counts": dict(resp.hit_counts),
        }

    @staticmethod
    def _rule_to_proto(r: dict) -> Any:
        # r is a dict with keys matching gmesh.v1.FirewallRule fields.
        return gmesh_pb2.FirewallRule(
            id=r.get("id", 0),
            name=r.get("name", ""),
            enabled=bool(r.get("enabled", True)),
            priority=r.get("priority", 0),
            action=r.get("action", gmesh_pb2.FW_ACTION_ALLOW),
            protocol=r.get("protocol", gmesh_pb2.FW_PROTO_ANY),
            source=r.get("source", ""),
            destination=r.get("destination", ""),
            port_range=r.get("port_range", ""),
            direction=r.get("direction", "inbound"),
            tcp_flags=r.get("tcp_flags", ""),
            conn_state=r.get("conn_state", ""),
            rate_limit=r.get("rate_limit", ""),
            rate_burst=r.get("rate_burst", 0),
            schedule=r.get("schedule", ""),
            expires_at=r.get("expires_at", 0),
            tags=r.get("tags", []),
        )

    # ── Health + events ───────────────────────────────────────────────

    async def health_check(self, peer_id: int = 0) -> list:
        resp = await self._stub.HealthCheck(gmesh_pb2.HealthCheckRequest(peer_id=peer_id))
        status_name = {
            gmesh_pb2.HEALTH_EXCELLENT: "excellent",
            gmesh_pb2.HEALTH_GOOD: "good",
            gmesh_pb2.HEALTH_DEGRADED: "degraded",
            gmesh_pb2.HEALTH_POOR: "poor",
            gmesh_pb2.HEALTH_FAILING: "failing",
        }
        return [{
            "peer_id": p.peer_id,
            "status": status_name.get(p.status, "unknown"),
            "score": p.score,
            "latency_ms": p.latency_ms,
            "packet_loss": p.packet_loss,
            "handshake_age_s": p.handshake_age_s,
        } for p in resp.peers]

    async def subscribe_events(self, types: Optional[List[str]] = None) -> AsyncIterator[dict]:
        """Yield one dict per event until the server closes the stream."""
        req = gmesh_pb2.SubscribeEventsRequest(types=list(types or []))
        with contextlib.suppress(asyncio.CancelledError):
            async for ev in self._stub.SubscribeEvents(req):
                yield {
                    "timestamp_unix_ms": ev.timestamp_unix_ms,
                    "type": ev.type,
                    "peer_id": ev.peer_id,
                    "payload_json": ev.payload_json,
                }
