# Hardening

Phase 9 wires observability + audit + a load-test harness around the
core built in Phase 0 – 8. The goal is operators can answer three
questions at any hour of any day:

1. What is gmeshd doing right now? → **Prometheus `/metrics`**.
2. Who called which RPC, when, and did it succeed? → **audit log**.
3. Will it hold up under fleet-scale load? → **benchmarks + latency tests**.

## Prometheus metrics

Exposed over a dedicated Unix socket (`/run/gmesh-metrics.sock` by
default, configurable via `metrics.socket_path`).

```bash
curl --unix-socket /run/gmesh-metrics.sock http://localhost/metrics
curl --unix-socket /run/gmesh-metrics.sock http://localhost/healthz
```

### Exposed series

| Metric                                     | Type        | Labels                     |
|--------------------------------------------|-------------|----------------------------|
| `gmesh_rpc_requests_total`                 | Counter     | `method`, `code`           |
| `gmesh_rpc_latency_seconds`                | Histogram   | `method`                   |
| `gmesh_peers_total`                        | Gauge       | —                          |
| `gmesh_scopes_total`                       | Gauge       | —                          |
| `gmesh_traversal_holepunch_attempts_total` | Counter     | `method`, `outcome`        |
| `gmesh_firewall_applies_total`             | Counter     | `outcome`                  |
| `gmesh_firewall_rules_active`              | Gauge       | —                          |
| `gmesh_relay_bytes_forwarded_total`        | Counter     | —                          |
| `gmesh_wstunnel_bytes_total`               | Counter     | —                          |
| `gmesh_events_published_total`             | Counter     | `type`                     |
| `gmesh_events_dropped_total`               | Counter     | —                          |
| `gmesh_health_score`                       | Histogram   | —                          |
| `gmesh_nat_discovery_total`                | Counter     | `outcome`, `nat_type`      |
| `gmesh_build_info`                         | Gauge       | `version`, `commit`, `build_date` |

Plus the default Go runtime collectors (`go_gc_*`, `go_goroutines`,
`process_*`).

### Sample Prom scrape

```
# HELP gmesh_rpc_requests_total Number of gRPC requests handled.
# TYPE gmesh_rpc_requests_total counter
gmesh_rpc_requests_total{method="Status",code="OK"} 14
gmesh_rpc_requests_total{method="Version",code="OK"} 2
gmesh_rpc_requests_total{method="ScopeConnect",code="OK"} 3
gmesh_rpc_latency_seconds_bucket{method="Status",le="0.001"} 12
gmesh_rpc_latency_seconds_bucket{method="Status",le="0.0025"} 14
gmesh_rpc_latency_seconds_sum{method="Status"} 0.00421
```

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: gmeshd
    scrape_interval: 15s
    static_configs:
      - targets: ['unused']    # target is the socket below
    metrics_path: /metrics
    # node_exporter's textfile collector trick — or use socket_exporter
    # to scrape Unix sockets. Alternatively run a tiny socat bridge:
    #   socat TCP-LISTEN:9464,fork UNIX-CONNECT:/run/gmesh-metrics.sock
```

## Audit log

Every gRPC unary call is recorded as one JSON line in
`/var/log/gmesh/audit.log` (path configurable). Entries:

```json
{"ts":"2026-04-19T15:05:15.447Z","actor":"","method":"ScopeConnect",
 "code":"OK","latency_ms":9,"scope_id":42,
 "params":{"listen_port":51842,"scope_mesh_ip":"10.200.0.42"}}
```

Fields:

- `ts` — RFC3339Nano UTC.
- `actor` — placeholder; future work will fill this with the Unix
  peer credentials (uid/pid) pulled off the socket.
- `method` — unqualified RPC name (`AddPeer`, not `/gmesh.v1.GMesh/AddPeer`).
- `code` — gRPC status string (`OK`, `NotFound`, `Internal`, …).
- `latency_ms` — wall time from handler entry to handler return.
- `peer_id`, `scope_id` — extracted reflection-free from the request
  via optional getter interfaces.
- `params` — opt-in subset of request fields known to be non-sensitive
  (mesh_ip, endpoint, interface, listen_port, default_policy). **Private
  keys, HMAC tokens, and relay secrets are never logged.**
- `error` — populated when `code != OK`.

Rotation: when the file exceeds `max_bytes` (default 10 MiB), it's
renamed with a UTC timestamp (`audit.log.20260419-150515`) and a fresh
file is opened. No built-in compression; pair with `logrotate` for
long-term retention.

## Load characterization

Run the test suite to reproduce:

```bash
go test -run "TestApplyFirewall1000Latency|TestAddPeer1000Latency" \
    ./internal/engine -v
```

Results on an M-series Mac, stub backends (no kernel ops):

| Operation                         | Result                        |
|-----------------------------------|-------------------------------|
| Apply 1000 firewall rules         | **~1 ms** (~500 rules/ms)     |
| Add 1000 peers (with persist)     | ~11 s (~90 peers/s)           |
| 1000-peer registry snapshot       | < 100 µs                      |

**Note on AddPeer:** each peer add fsyncs state.json. At 1000 peers the
cost is dominated by syscall overhead + filesystem commit latency. A
batched / debounced persist landing in a follow-up will bring this to
sub-second without changing the public API.

## Go benchmarks

```bash
go test -bench=. -benchmem -run=^$ ./internal/engine
```

```
BenchmarkAddPeer1000-10          N ops     op/ns    B/op    allocs/op
BenchmarkApplyFirewall1000-10    …
BenchmarkStatus1000Peers-10      …
```

## Chaos scenarios

The gmesh source tree doesn't ship a dedicated chaos runner in Phase 9 —
the building blocks for chaos tests live in the existing integration
harness ([test/integration/](../test/integration/)). The recipes we
validate by hand on Linux test beds:

| Scenario                        | Expected                                   |
|---------------------------------|--------------------------------------------|
| `systemctl restart gmeshd`      | Peers rehydrate from state.json; WG up <3s |
| Kill `gmesh-relay`              | Sessions drain; `peer_disconnected` events |
| Drop UDP egress via iptables    | Health drops to FAILING; WS tunnel kicks in|
| Swap public IP (NAT re-lease)   | `nat_changed` event; handshakes re-established via new endpoint |
| Delete /run/gmesh.sock          | Daemon detects on next accept, recreates   |

A Go chaos harness (fault-injecting mesh-relay-proxy + randomized
kill/restart loop) is on the Phase 9.5 backlog.

## Operating-guide quickies

**Check recent error RPCs**

```bash
jq -c 'select(.code != "OK")' /var/log/gmesh/audit.log | tail -20
```

**Top 10 slowest RPCs in the last hour**

```bash
tail -n +1 /var/log/gmesh/audit.log \
    | jq -s 'sort_by(-.latency_ms) | .[:10]'
```

**Live RPC rate**

```bash
watch -n 1 'curl -s --unix-socket /run/gmesh-metrics.sock \
    http://localhost/metrics | grep gmesh_rpc_requests_total'
```

**Prometheus alert recipe**

```yaml
- alert: GmeshRPCErrors
  expr: rate(gmesh_rpc_requests_total{code!="OK"}[5m]) > 0.1
  for: 5m
  labels: {severity: warning}

- alert: GmeshEventsBacklog
  expr: rate(gmesh_events_dropped_total[5m]) > 0
  for: 5m
  labels: {severity: warning}
  annotations:
    summary: "gmesh event subscriber is slow"
```
