# Migration from Python mesh

This document describes the cutover from GritivaCore's Python mesh
(`agentNew/mesh/*`) to gmeshd.

## Compatibility contract

The **GritivaCore backend protocol is unchanged.** The backend still sends
`mesh_join`, `mesh_add_peer`, `mesh_hole_punch_result`, `scope_mesh_connect`,
`mesh_firewall_apply`, etc. as WebSocket messages to the agent. The backend
does not know — and should not care — whether the agent handles these with
Python code or by forwarding to gmeshd.

This means migration is purely an agent-side change. No backend migrations,
no database schema changes, no frontend changes.

## The bridge

`agentNew/mesh_bridge.py` (lands in Phase 8) is a thin gRPC client that:

1. Subscribes to `gmeshd.SubscribeEvents` stream.
2. Translates inbound WS messages → gRPC calls:
   - `mesh_join`       → `GMesh.Join`
   - `mesh_add_peer`   → `GMesh.AddPeer`
   - `mesh_hole_punch` → `GMesh.HolePunch`
   - `scope_mesh_connect`  → `GMesh.ScopeConnect`
   - `mesh_firewall_apply` → `GMesh.ApplyFirewall`
   - …
3. Translates gRPC Events → outbound WS messages:
   - `Event{type:"peer_connected"}` → `{"type":"mesh_peer_connected", ...}`
   - `Event{type:"nat_changed"}`    → `{"type":"mesh_nat_discovery", ...}`
   - …

## Feature flag

A single env var flips behavior:

```
USE_GMESH=1
```

When unset or `0`, the agent runs the legacy Python mesh. When `1`, the agent
dispatches to the bridge. Both implementations can coexist in the binary
during the transition.

## Rollout phases

### 1. Per-agent canary

Install gmesh on one agent server (e.g., `100.76.29.64`) alongside Python
mesh. Set `USE_GMESH=1` in its systemd env only:

```bash
sudo systemctl edit gritiva-agent
# [Service]
# Environment=USE_GMESH=1
sudo systemctl restart gritiva-agent
```

Compare metrics with other agents for 72h.

### 2. Shadow mode (optional)

Run **both** implementations simultaneously — Python mesh owns the live
WG interface, gmeshd runs read-only alongside, executing every command in a
dummy namespace. Diff their responses. Any divergence → bug.

### 3. Fleet-wide cutover

Push `USE_GMESH=1` to all agents via OTA config update. Watch the dashboard
for 24h — mesh peer counts, connection method breakdown, latency histograms
should match pre-cutover baselines.

### 4. Cleanup

After a 72h soak with no regressions, delete:
- `agentNew/mesh/` (22 files)
- `agentNew/handlers/mesh.py` (replaced by bridge dispatch)
- `agentNew/handlers/mesh_firewall_handler.py`
- Related requirements (stun-client, pywgtools, etc.) from `agentNew/requirements.txt`
- The `USE_GMESH` flag itself — gmesh becomes unconditional

## Rollback

If Phase 3 fails:

```bash
# Fleet-wide rollback
ansible gritiva-agents -m systemd -a "name=gritiva-agent state=restarted" \
  --extra-vars "env=USE_GMESH=0"

# On a single server
sudo systemctl edit gritiva-agent   # remove Environment=USE_GMESH=1
sudo systemctl restart gritiva-agent
```

Python mesh code is preserved in the binary. Switching flags takes <5s per agent.

## State migration

gmeshd's `/var/lib/gmesh/state.json` starts empty on first run. The backend
re-issues `mesh_add_peer` for every existing peer during `auto_connect_peers`,
so no state transfer from Python mesh is needed. Peers reconnect within ~30s
of agent restart with `USE_GMESH=1`.

## Known behavioral differences

| Area                    | Python mesh                              | gmesh                                       |
|-------------------------|------------------------------------------|---------------------------------------------|
| Scope peer model        | Shared WG config on parent VM            | Own WG interface in scope netns             |
| Firewall backend        | iptables (`GRITIVA_MESH` chain)          | nftables (`gmesh` table)                    |
| Schedule rules          | Not implemented (`app/models/mesh.py:610`) | Fully implemented (Phase 5)               |
| Method switching        | TODO (`quality_monitor.py:555`)          | Supported via `peer_method_change` event    |
| Real-time frontend      | Polling (10-15s)                         | WebSocket subscription to backend event bus |

The first row is the most significant change. See
[architecture.md](architecture.md#scope-support) for the scope model rationale.
