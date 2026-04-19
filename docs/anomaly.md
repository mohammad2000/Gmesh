# Anomaly Detection (Phase 21)

`internal/anomaly` is a lightweight stat-based anomaly detector. It
watches per-peer traffic + liveness signals and emits `anomaly_alert`
events on the bus when values fall outside a rolling baseline.

## What's detected

| Detector           | What it watches                          | Typical cause                              |
|--------------------|------------------------------------------|---------------------------------------------|
| `bandwidth_z`      | bytes/sec per peer, rolling 5-min window | exfil spike, idle peer, backup job         |
| `handshake_storm`  | new WG handshakes per peer, 60-s window  | key-churn bug, retry loop, misconfig       |
| `peer_flap`        | path_up/path_down transitions per peer   | flaky underlay, ISP brown-out              |

Scope is deliberately small: three detectors, stdlib-only, no ML. The
goal is "operator-meaningful signals a SRE can reason about", not
state-of-the-art detection. Tune-via-config is expected; defaults are
conservative.

## Output

Every alert carries:

```json
{
  "detector": "bandwidth_z",
  "peer_id": 3,
  "severity": "warn",    // info | warn | critical
  "message": "bandwidth z=5.2 (value=42 MB/s, baseline mean=2 MB/s σ=0.3 MB/s)",
  "metrics": {
    "bytes_per_s": 44040192,
    "mean": 2097152,
    "stddev": 314572,
    "z": 5.2
  },
  "observed_unix": 1760000000
}
```

Transport:
- **Event bus**: `anomaly_alert`. Anything subscribing to the bus
  (`gmeshctl events watch`, the GritivaCore backend, external
  automation) sees it in real time.
- **ListAnomalies RPC**: point-in-time snapshot of the last ~200
  alerts. Used by `gmeshctl anomaly list` and the dashboard.

## CLI

```
gmeshctl anomaly list [--peer-id N] [--limit K]
```

Example:

```
OBSERVED              DETECTOR         SEVERITY  PEER  MESSAGE
2026-04-20T01:12:33Z  bandwidth_z      critical  3     bandwidth z=12.4 (value=1.8 GB/s, baseline mean=2 MB/s σ=0.3 MB/s)
2026-04-20T01:08:17Z  handshake_storm  warn      3     15 handshakes in 1m0s (threshold=10)
2026-04-20T01:04:02Z  peer_flap        warn      4     5 up/down transitions in 5m0s (threshold=4)
```

## How the detectors work

### bandwidth_z

Per peer, maintains a rolling window (default 30 samples × 10s =
5 min) of bytes/sec. Each new sample is compared against the CURRENT
window's mean + stddev BEFORE being added to the window (so a new
sample can't hide itself in its own comparison). If
|value − mean| / stddev > threshold (default 4.0), alert. Severity is
`warn` by default and `critical` when z > threshold × 1.5.

Cold-start: skips alerting until the window has at least MinSamples
observations (default 6), so a single startup blip doesn't fire.

Zero-variance edge case: if a peer's stddev is exactly 0 (e.g. it's
been sitting at 0 B/s the whole window), z is undefined and no alert
fires. In production, real jitter means stddev > 0 almost immediately;
synthetic tests can inject tiny noise.

### handshake_storm

Counts handshake observations per peer inside a sliding time window
(default 60s). When the count exceeds Threshold (default 10), alert.
Useful for detecting:

- Key-churn bugs (wg rapidly renegotiating).
- Retry storms from a buggy peer.
- A compromised peer hammering the local daemon.

Window is exact (not a histogram bucket) — old timestamps are pruned
on every observe, so the count is always an accurate last-N-seconds
figure.

### peer_flap

Counts path_up/path_down transitions per peer inside a window (default
5 min). Threshold default 4 — i.e. two full up-down cycles in five
minutes is "flapping". Severity bumps to `critical` at 2× threshold.

## Cooldown

Every detector enters a per-peer cooldown after firing (60s / 120s /
5m respectively). Additional observations during the cooldown are
silently counted but don't emit duplicate alerts. This keeps a
sustained incident from spamming the bus.

## Wiring

The engine constructs one `anomaly.Monitor` per gmeshd and feeds:

- Bandwidth: `RefreshPeerStats` every 10s → delta vs previous tick →
  `bandwidth_z.Observe`.
- Handshake storm: peer-stats tick → if `LastHandshake` is newer than
  last tick → `handshake_storm.Observe`.
- Peer flap: pathmon's `path_up`/`path_down` listener → `peer_flap.Observe`.

No user config is required for the detectors to start working — the
defaults are chosen to be quiet during normal operation and loud
enough to matter during real incidents.

## Config

Future work: expose the per-detector thresholds in `gmesh.yaml`.
Today they live in defaults inside `Config.defaults()`. Operators who
need to tune can rebuild gmeshd with a custom config struct.

## Interaction with policy engine (Phase 17)

Anomaly events land on the bus as `anomaly_alert`. The policy engine
does not listen to this type today (its trigger whitelist is just
path/quota events) but an operator can write a simple shell hook:

```
gmeshctl events watch --types anomaly_alert | \
    jq -r 'select(.severity=="critical") | "[\(.at_unix)] \(.message)"' | \
    xargs -I{} sh -c 'curl -X POST -d "{}" https://alerting.corp/anomaly'
```

A Phase 21.5 could extend the policy engine's trigger list to
`anomaly_alert` so an operator can write `when: anomaly_alert of
bandwidth_z severity=critical → disable_profile N`.

## What's NOT in Phase 21

- ML / sequence models. Everything is rolling-mean + z-score.
- Per-direction (rx vs tx) splits — we treat combined bandwidth as one
  signal. A future phase can add a direction-aware detector if exfil
  asymmetry matters.
- Destination-aware anomalies (e.g. "this peer suddenly talks to a
  country it's never reached before"). Needs GeoIP integration and a
  wider data model.
- Config surface — thresholds are hardcoded defaults today. A
  `anomaly.*` YAML stanza will expose them in a follow-up.
