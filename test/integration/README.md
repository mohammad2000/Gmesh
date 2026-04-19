# Integration tests

This harness spins up multiple gmeshd instances in Docker, simulates NAT
between them, then asserts high-level mesh behavior.

## Not yet functional

The `docker-compose.yml` is a skeleton. Actual test scenarios land in
Phase 2 (NAT discovery) and Phase 3 (hole punching). See
[../../docs/roadmap.md](../../docs/roadmap.md).

## Planned scenarios

- **direct-full-mesh** — 3 nodes, all public. Assert every pair connects via `DIRECT`.
- **nat-full-cone** — 2 nodes behind full-cone NAT (MASQUERADE). Assert hole-punch succeeds.
- **nat-symmetric** — 1 node behind symmetric NAT. Assert fallback to `RELAY`.
- **udp-blocked** — UDP egress dropped on one node. Assert fallback to `WS_TUNNEL`.
- **scope-mesh** — 2 VMs × 2 scopes each. Assert scope-to-scope reachable.
- **firewall-apply** — 1000-rule apply completes in <1s and matches kernel state.
- **agent-restart** — restart gmeshd mid-session. Assert peers recover in <30s.

## Run

```bash
cd test/integration
docker compose up --abort-on-container-exit --exit-code-from runner
```
