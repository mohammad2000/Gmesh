# Path Monitor (Phase 14)

`internal/pathmon` actively probes each mesh peer (ICMP ping on Linux,
stubbed elsewhere) and tracks RTT, packet loss and up/down status with
hysteresis. Transitions emit `path_up` / `path_down` events on the
engine's event bus — the same bus that carries `peer_connected`,
`quota_warning`, and `health_update`.

## Why a separate monitor

`internal/health` already gives each peer a 0..100 score. That score
is fine for humans and dashboards but it's:

- **Slow** — one sample per interval, averaged over several factors.
- **Latched softly** — a transient spike in RTT is smoothed out.
- **Output-coupled** — its purpose is a UI badge, not a switch.

Path Monitor answers a different question: **right now, can I still
send traffic to this peer, or should I switch?** That signal needs to
be fast, binary, and edge-triggered. Hysteresis prevents a single
dropped ICMP packet from causing flap — by default, 3 consecutive
misses trip `path_down` and 2 consecutive successes restore `path_up`.

## Configuration

The engine constructs the monitor with `pathmon.Config{}`
(all-defaults):

| Field          | Default | Meaning                                                 |
|----------------|---------|---------------------------------------------------------|
| Interval       | 5s      | How often one probe fires per target                    |
| Timeout        | 1s      | Per-probe timeout                                       |
| WindowSize     | 10      | Rolling history used for LossPct                        |
| UpThreshold    | 2       | Consecutive successes to transition Down → Up           |
| DownThreshold  | 3       | Consecutive failures to transition Up → Down            |

Targets auto-sync from the peer registry every 30 s; peers added
between ticks begin probing within one cycle.

## Events

| Type         | Payload fields                                   |
|--------------|--------------------------------------------------|
| `path_up`    | `mesh_ip`, `rtt_ms`, `loss_pct`, `at_unix`       |
| `path_down`  | `mesh_ip`, `rtt_ms`, `loss_pct`, `at_unix`       |

Downstream consumers (egress switcher, dashboard, alerting) subscribe
to the event bus with `gmeshctl events watch` or programmatically via
`Events.Subscribe`.

## CLI

```
gmeshctl path list
PEER  MESH_IP       STATUS  RTT_MS  LOSS%  OK  FAIL  SAMPLES
1     10.250.0.1    up      0.18    0.0    8   0     8
3     10.250.0.20   up      105.22  0.0    8   0     8
42    10.250.0.42   unknown 0.00    0.0    0   0     0
```

## gRPC

`ListPathStates` returns the same snapshot as the CLI. No streaming RPC
today — subscribe to `EventsStream` with `--types path_up,path_down`
for live transitions.

## Prober implementations

- `LinuxPingProber` — shells out to `ping -n -c 1 -W 1 <mesh_ip>`.
  Requires `iputils-ping` and either CAP_NET_RAW or ping's setuid bit.
- `StubProber` — scripted results for tests.

`NewPlatformProber()` picks automatically: Linux with `ping` in PATH →
real prober, otherwise stub. The stub keeps `go test` green on
Darwin / CI images without ping capabilities.

## Current use

The engine wires `path_down` onto the event bus; external automation
can act on it (e.g. flip an egress profile, alert oncall). A future
phase will add an in-engine Listener that automatically invokes the
quota Switcher on `path_down` for critical profiles, and a kill-switch
that installs a DROP rule when no path remains.
