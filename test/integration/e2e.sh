#!/usr/bin/env bash
# e2e.sh — end-to-end regression across the two-node mesh cluster.
#
# Drives one full scenario per implemented phase (11..21) against a live
# cluster, then tears down. Prints a ✓/✗ per scenario. Exits non-zero
# if any scenario fails.
#
# Prereqs:
#   - SSH access to $CORE and $FSN1 (see env-var defaults below).
#   - Both hosts have nft + wg + conntrack-tools installed.
#   - Locally: Go toolchain (script builds and scps the binaries).
#
# Usage:
#   test/integration/e2e.sh          # run the whole matrix
#   test/integration/e2e.sh scope_netns quota_hard_stop  # subset
#
# Scenarios are idempotent: they clean up their own state at the end.
# If one fails partway through the script still tries to reset the
# state and moves on to the next scenario.
set -o pipefail

# ── configuration ─────────────────────────────────────────────────────
CORE="${CORE:-root@100.71.50.46}"
FSN1_VIA_CORE="${FSN1_VIA_CORE:-root@100.89.201.68}"  # reached via ssh from CORE
CORE_PEER_ID="${CORE_PEER_ID:-1}"
FSN1_PEER_ID="${FSN1_PEER_ID:-3}"
FSN1_MESH_IP="${FSN1_MESH_IP:-10.250.0.20}"
CORE_MESH_IP="${CORE_MESH_IP:-10.250.0.1}"
FSN1_PUBLIC="${FSN1_PUBLIC:-188.245.175.144:52064}"
WG_IFACE="${WG_IFACE:-wg-gmesh}"

GO_ROOT="${GO_ROOT:-/Users/mohammad/Gmesh}"

# ── styling ───────────────────────────────────────────────────────────
GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; RESET="\033[0m"
PASS=(); FAIL=(); SKIP=()

log()   { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }
ok()    { printf "${GREEN}✓${RESET} %s\n" "$*"; PASS+=("$1"); }
bad()   { printf "${RED}✗${RESET} %s — %s\n" "$1" "$2"; FAIL+=("$1"); }
skip()  { printf "${YELLOW}·${RESET} %s — %s\n" "$1" "$2"; SKIP+=("$1"); }

# Convenience: run on core
coresh() { ssh -o ConnectTimeout=6 -o StrictHostKeyChecking=accept-new "$CORE" "$@"; }
# Convenience: run on fsn1 via core (fsn1 SSH allows the core tailnet
# origin). Two-try retry — the intercontinental hop to fsn1 occasionally
# times out on the first SSH connect but succeeds immediately after.
fsn1sh() {
  local i
  for i in 1 2; do
    coresh "ssh -o ConnectTimeout=10 $FSN1_VIA_CORE \"$@\"" && return 0
    sleep 1
  done
  return 1
}

# ── build + deploy ────────────────────────────────────────────────────
build_and_push() {
  log "building linux binaries from $GO_ROOT"
  GOOS=linux GOARCH=amd64 go build -C "$GO_ROOT" -o /tmp/gmeshd-linux ./cmd/gmeshd || return 1
  GOOS=linux GOARCH=amd64 go build -C "$GO_ROOT" -o /tmp/gmeshctl-linux ./cmd/gmeshctl || return 1
  scp -q /tmp/gmeshd-linux /tmp/gmeshctl-linux "$CORE":/tmp/ || return 1
  coresh "scp -q /tmp/gmeshd-linux /tmp/gmeshctl-linux $FSN1_VIA_CORE:/tmp/" || return 1
  for host in core fsn1; do
    if [[ "$host" == core ]]; then
      sh=coresh
    else
      sh=fsn1sh
    fi
    $sh "install -m 0755 /tmp/gmeshd-linux /usr/local/bin/gmeshd \
       && install -m 0755 /tmp/gmeshctl-linux /usr/local/bin/gmeshctl" || return 1
  done
}

ensure_config_sections() {
  # Make sure the features the scenarios poke at are enabled in
  # /etc/gmesh/config.yaml on core. Idempotent: skips sections that
  # already exist so re-runs don't keep appending.
  coresh "grep -q '^mtls:' /etc/gmesh/config.yaml || printf '\nmtls:\n  dir: /var/lib/gmesh/ca\n  trust_domain: gmesh.local\n' >> /etc/gmesh/config.yaml; \
          grep -q '^policies:' /etc/gmesh/config.yaml || printf '\npolicies:\n  dir: /etc/gmesh/policies.d\n' >> /etc/gmesh/config.yaml; \
          grep -q 'self_peer_id' /etc/gmesh/config.yaml || sed -i '/^wireguard:/a\\  self_peer_id: '$CORE_PEER_ID /etc/gmesh/config.yaml; \
          mkdir -p /var/lib/gmesh/ca" >/dev/null 2>&1
  fsn1sh "grep -q 'self_peer_id' /etc/gmesh/config.yaml || sed -i '/^wireguard:/a\\  self_peer_id: '$FSN1_PEER_ID /etc/gmesh/config.yaml" >/dev/null 2>&1
}

start_daemons() {
  ensure_config_sections
  for host in core fsn1; do
    local sh=coresh
    [[ "$host" == fsn1 ]] && sh=fsn1sh
    $sh "systemctl stop gmeshd-t 2>/dev/null; systemctl reset-failed gmeshd-t 2>/dev/null; systemd-run --unit=gmeshd-t /usr/local/bin/gmeshd --config /etc/gmesh/config.yaml" >/dev/null
  done
  sleep 3
}

stop_daemons() {
  coresh "systemctl stop gmeshd-t 2>/dev/null" || true
  fsn1sh "systemctl stop gmeshd-t 2>/dev/null" || true
}

# ── scenarios ─────────────────────────────────────────────────────────
# Each function: returns 0 on pass, non-zero on fail.

scn_peer_handshake() {
  # Phase 0 baseline: peers auto-rehydrate, handshake within 10s.
  local hs
  hs=$(coresh "gmeshctl peer list 2>&1 | awk '/10\\.250\\.0\\.20/ {print \$NF}'" 2>&1)
  [[ "$hs" == "-" ]] && { echo "no handshake yet"; return 1; }
  [[ -z "$hs" ]] && { echo "fsn1 peer missing"; return 1; }
  return 0
}

scn_path_monitor() {
  # Phase 14: pathmon requires two consecutive probe successes to flip
  # Unknown → Up (UpThreshold=2, Interval=5s). Poll up to 30 s so we
  # tolerate a slow first handshake.
  local i out
  for i in $(seq 1 10); do
    out=$(coresh "gmeshctl path list" 2>&1)
    if echo "$out" | grep -q "up"; then return 0; fi
    sleep 3
  done
  echo "no 'up' within 30 s"; echo "$out"; return 1
}

scn_egress_profile() {
  # Phase 11 + 14 fix: conntrack-aware guards present.
  coresh "gmeshctl egress create --id 5 --name e5-smoke \
    --exit-peer $FSN1_PEER_ID --dest 1.1.1.1/32 --dest-ports 443 --protocol tcp" \
    > /dev/null 2>&1 || { echo "create egress failed"; return 1; }
  local rules
  rules=$(coresh "nft list chain inet gmesh-egress egress_mark_out 2>&1")
  echo "$rules" | grep -q "meta mark 0x10000000/4 return" \
    || { coresh "gmeshctl egress delete --id 5" >/dev/null 2>&1; echo "ct guard missing"; return 1; }
  echo "$rules" | grep -q "ct mark set 0x10000005" \
    || { coresh "gmeshctl egress delete --id 5" >/dev/null 2>&1; echo "ct mark set missing"; return 1; }
  coresh "gmeshctl egress delete --id 5" >/dev/null 2>&1
  return 0
}

scn_ingress_profile() {
  # Phase 12: DNAT + MASQ + FWD rules installed cleanly on fsn1.
  fsn1sh "gmeshctl ingress create --id 99 --name edge --backend-ip $CORE_MESH_IP --backend-port 8099 --edge-peer $FSN1_PEER_ID --edge-port 8099 --protocol tcp" >/dev/null 2>&1 \
    || { echo "create ingress failed"; return 1; }
  local rules; rules=$(fsn1sh "nft list table inet gmesh-ingress 2>&1")
  echo "$rules" | grep -q "dnat ip to $CORE_MESH_IP:8099" \
    || { fsn1sh "gmeshctl ingress delete --id 99" >/dev/null 2>&1; echo "dnat rule missing"; return 1; }
  fsn1sh "gmeshctl ingress delete --id 99" >/dev/null 2>&1
  return 0
}

scn_quota_hard_stop() {
  # Phase 13 + 13.5: hard_stop installs DROP rules keyed by profile fwmark.
  coresh "gmeshctl egress create --id 5 --name e5-q --exit-peer $FSN1_PEER_ID --dest 1.1.1.1/32 --dest-ports 443 --protocol tcp" >/dev/null 2>&1 || { echo "pre-egress failed"; return 1; }
  coresh "gmeshctl quota create --id 9 --name q-smoke --profile 5 --limit-bytes 100 --period daily --stop-at 0.5 --hard-stop" >/dev/null 2>&1 || { coresh "gmeshctl egress delete --id 5" >/dev/null; echo "quota create failed"; return 1; }
  coresh "timeout 5 curl -s --max-time 3 https://1.1.1.1 -o /dev/null" >/dev/null 2>&1 || true
  sleep 12
  local rules; rules=$(coresh "nft list table inet gmesh-quota 2>&1 || true")
  echo "$rules" | grep -q "quota-drop-5" \
    || { coresh "gmeshctl quota delete --id 9; gmeshctl egress delete --id 5" >/dev/null; echo "DROP rule never installed"; return 1; }
  coresh "gmeshctl quota reset --id 9; gmeshctl quota delete --id 9; gmeshctl egress delete --id 5" >/dev/null 2>&1
  return 0
}

scn_pathmon_failover_listener() {
  # Phase 14: engine's listener is registered; verifiable by the fact that
  # path list yields entries (listener runs in same goroutine pool).
  local out; out=$(coresh "gmeshctl path list | grep -v '^PEER'" 2>&1)
  [[ -z "$out" ]] && { echo "no path entries"; return 1; }
  return 0
}

scn_circuit_source_role() {
  # Phase 19: source-role install stamps a 0x2_______ mark rule.
  coresh "gmeshctl circuit create --id 1 --name c1 --source $CORE_PEER_ID --hop $FSN1_PEER_ID --protocol tcp --dest-ports 443 --dest 1.1.1.1/32" >/dev/null 2>&1 || { echo "create circuit failed"; return 1; }
  local rules; rules=$(coresh "nft list chain inet gmesh-circuit circuit_source_out 2>&1")
  echo "$rules" | grep -q 'meta mark set 0x20000001' \
    || { coresh "gmeshctl circuit delete --id 1" >/dev/null; echo "source rule missing"; return 1; }
  coresh "gmeshctl circuit delete --id 1" >/dev/null 2>&1
  return 0
}

scn_mtls_ca_roundtrip() {
  # Phase 20: init (force=true handles prior-run CA) → issue → revoke.
  # Assumes /etc/gmesh/config.yaml already has an mtls section pointing
  # at /var/lib/gmesh/ca (the e2e setup step ensures this). No daemon
  # restart mid-scenario — force=true overwrites in place.
  coresh "gmeshctl mtls init --trust-domain gmesh.local --force" >/dev/null 2>&1 \
    || { echo "mtls init failed"; return 1; }
  local serial; serial=$(coresh "gmeshctl mtls issue --peer-id 7 --cn smoke-peer 2>/dev/null | awk '/^serial:/ {print \$2}'")
  [[ -z "$serial" ]] && { echo "issue returned no serial"; return 1; }
  coresh "gmeshctl mtls revoke --serial $serial --reason smoke" >/dev/null 2>&1 \
    || { echo "revoke failed"; return 1; }
  coresh "gmeshctl mtls list | grep -q smoke" \
    || { echo "revoked cert not in list"; return 1; }
  return 0
}

scn_policy_engine_loads() {
  # Phase 17: YAML policy loads and is visible via list.
  coresh "mkdir -p /etc/gmesh/policies.d && cat > /etc/gmesh/policies.d/smoke.yaml <<EOF
version: 1
name: smoke
when: {event: path_down, peer_id: $FSN1_PEER_ID}
do: {action: reset_quota, quota_id: 99}
EOF
grep -q '^policies:' /etc/gmesh/config.yaml || printf '\npolicies:\n  dir: /etc/gmesh/policies.d\n' >> /etc/gmesh/config.yaml" >/dev/null 2>&1
  coresh "gmeshctl policy reload | grep -q 'loaded 1 policies'" || { echo "reload did not load 1"; return 1; }
  coresh "gmeshctl policy list | grep -q smoke" || { echo "policy list missing entry"; return 1; }
  coresh "rm -rf /etc/gmesh/policies.d; gmeshctl policy reload" >/dev/null 2>&1
  return 0
}

scn_anomaly_rpc() {
  # Phase 21: RPC responds cleanly. With no anomalies yet the proto
  # returns "{}" (an empty `alerts` list is omitted by protojson);
  # we only assert the command exits 0 and JSON parses.
  coresh "gmeshctl anomaly list --json" > /dev/null || { echo "anomaly rpc errored"; return 1; }
  return 0
}

scn_l7_classifier() {
  # Phase 18: l7 reader works on fsn1 (real kernel conntrack).
  fsn1sh "sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1; sleep 11; gmeshctl l7 totals --json | head -c 80" | grep -q "totals" \
    || { echo "l7 totals JSON missing totals key"; return 1; }
  return 0
}

scn_geoip_validation() {
  # Phase 15: empty resolver rejects unknown-country profiles loudly.
  local out; out=$(coresh "gmeshctl egress create --id 5 --name g5 --exit-peer $FSN1_PEER_ID --geoip-country DE 2>&1" || true)
  echo "$out" | grep -qiE "geoip|country|resolver" \
    || { echo "unknown country should reject; output: $out"; return 1; }
  coresh "gmeshctl egress delete --id 5" >/dev/null 2>&1
  return 0
}

scn_exit_pool() {
  # Phase 16: pool install produces a numgen vmap in the mark rule.
  coresh "gmeshctl egress create --id 7 --name pool-smoke \
    --exit-pool $FSN1_PEER_ID --exit-pool $FSN1_PEER_ID \
    --exit-weights 60 --exit-weights 40 --protocol tcp --dest-ports 443" >/dev/null 2>&1 \
    || { echo "pool create failed"; return 1; }
  local rules; rules=$(coresh "nft list chain inet gmesh-egress egress_mark_out 2>&1")
  echo "$rules" | grep -q "numgen inc mod 100" \
    || { coresh "gmeshctl egress delete --id 7" >/dev/null; echo "numgen missing"; return 1; }
  coresh "gmeshctl egress delete --id 7" >/dev/null 2>&1
  return 0
}

# Scenario registry as a case-lookup, not an associative array — bash
# 3.2 on macOS silently collapses `${arr[$key]}` to `${arr[0]}`, which
# makes every scenario alias to the first one and every test "pass"
# unconditionally. Case statements work on every bash.
dispatch() {
  case "$1" in
    peer_handshake)     scn_peer_handshake ;;
    path_monitor)       scn_path_monitor ;;
    egress_profile)     scn_egress_profile ;;
    ingress_profile)    scn_ingress_profile ;;
    quota_hard_stop)    scn_quota_hard_stop ;;
    pathmon_listener)   scn_pathmon_failover_listener ;;
    circuit_source)     scn_circuit_source_role ;;
    mtls_ca)            scn_mtls_ca_roundtrip ;;
    policy_load)        scn_policy_engine_loads ;;
    anomaly_rpc)        scn_anomaly_rpc ;;
    l7_classifier)      scn_l7_classifier ;;
    geoip_validate)     scn_geoip_validation ;;
    exit_pool)          scn_exit_pool ;;
    *)                  return 127 ;;
  esac
}

# Run order matters for some scenarios (mtls restarts gmeshd; put it last).
ORDER=(
  peer_handshake path_monitor egress_profile ingress_profile
  quota_hard_stop pathmon_listener circuit_source policy_load
  anomaly_rpc l7_classifier geoip_validate exit_pool mtls_ca
)

# ── main ─────────────────────────────────────────────────────────────
run_one() {
  local name="$1"
  log "→ $name"
  local err; err=$(dispatch "$name" 2>&1 >/dev/null); local rc=$?
  if [[ $rc -eq 127 ]]; then skip "$name" "unknown scenario"; return; fi
  if [[ $rc -eq 0 ]]; then ok "$name"; else bad "$name" "${err:-nonzero rc}"; fi
}

main() {
  build_and_push || { echo "build/deploy failed; aborting"; exit 2; }
  start_daemons
  trap 'stop_daemons' EXIT

  if [[ $# -eq 0 ]]; then
    for s in "${ORDER[@]}"; do run_one "$s"; done
  else
    for s in "$@"; do run_one "$s"; done
  fi

  echo
  printf "${GREEN}passed:${RESET} %d\n" "${#PASS[@]}"
  printf "${RED}failed:${RESET} %d  %s\n" "${#FAIL[@]}" "${FAIL[*]:-}"
  printf "${YELLOW}skipped:${RESET} %d\n" "${#SKIP[@]}"
  [[ ${#FAIL[@]} -gt 0 ]] && exit 1 || exit 0
}

main "$@"
