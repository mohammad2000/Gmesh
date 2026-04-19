# Policy Engine (Phase 17)

`internal/policy` is a small event-driven rule engine. Operators drop
YAML files in a directory; the engine subscribes to the event bus and
fires actions when a policy's condition matches.

## Why a rule engine

Phases 11–14 ship with several automatic behaviours (quota shift,
pathmon failover). They each answer one specific question. Operators
occasionally want to answer a slightly different one — "swap profile
10 if peer 3 flaps three times in a minute" — that doesn't fit the
built-in paths.

Rather than hardcoding each new variant into the daemon, Phase 17
introduces a thin policy layer that composes existing engine verbs.
It's a **skeleton**: enough to solve the cases on the roadmap today,
extensible as more come up.

## File format

One policy per YAML file in `policies.dir`.

```yaml
version: 1                      # only 1 is accepted today
name: failover_on_high_loss

when:
  event: path_down              # path_up | path_down | quota_warning | quota_shift | quota_stop
  peer_id: 3                    # optional filter
  profile_id: 10                # optional (for quota_* events)
  debounce_seconds: 30          # 0 = fire on every match
  min_count: 3                  # fire only if N matches land in the window

do:
  action: swap_exit_peer        # swap_exit_peer | enable_profile | disable_profile | reset_quota
  profile_id: 10
  to_peer_id: 5
```

Unknown YAML fields are rejected at load time — typos fail loudly
instead of being silently ignored.

## Debounce semantics

With `debounce_seconds > 0` and `min_count > 1`:

- The first match starts a window.
- Matches within the window increment a counter.
- When the counter hits `min_count`, the action fires once and the
  policy enters a cooldown equal to `debounce_seconds`.
- Further matches during cooldown are ignored.
- After the cooldown expires, the next match starts a new window.

With `debounce_seconds == 0` every match fires immediately.

## Actions

| Action            | Fields required                  | Effect                                                 |
|-------------------|----------------------------------|--------------------------------------------------------|
| `swap_exit_peer`  | `profile_id`, `to_peer_id`       | Update the egress profile's `exit_peer_id`             |
| `enable_profile`  | `profile_id`                     | Set `enabled=true` on the egress profile               |
| `disable_profile` | `profile_id`                     | Set `enabled=false`                                    |
| `reset_quota`     | `quota_id`                       | Zero counters + clear latches + rollback if enabled    |

## Config

```yaml
policies:
  dir: /etc/gmesh/policies.d
```

Leave `dir` empty to disable loading. An empty or missing directory is
not an error — gmeshd just runs without any policies.

## CLI

```
gmeshctl policy list
gmeshctl policy reload
```

`reload` re-reads the directory atomically; partial load errors are
reported but don't replace the live set with garbage.

## What's out of scope (for now)

- Boolean composition (`when: A and B`).
- Time-windowed predicates beyond single-policy debounce
  (e.g. "average RTT > 200ms over 1m").
- Action chaining ("do X, then do Y").
- Subscribing to arbitrary event types — the whitelist keeps the
  surface area small.

These land when a concrete use case arrives. The file format carries a
`version` key specifically so future extensions can add new shapes
without breaking old policies.
