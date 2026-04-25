#!/usr/bin/env bash
# run_tests.sh — Integration test runner for rfed.
#
# Scenarios:
#   1  live_fanout     — Subscribe → publish → verify blob received via live fanout
#   2  deferred        — Subscribe offline → publish → come online → verify flushed to delivery
#   3  pull            — Subscribe offline → publish → pull → verify blobs returned
#   4  notify          — Register notify relay → publish offline → relay receives wake packet
#   5  sync            — Two nodes: publish on A, subscribe on B, verify sync delivers via PULL
#   7  prop_notify     — Register via rfed.notify → send LXMF propagation batch → relay woken
#
# Usage:
#   ./run_tests.sh [1|2|3|4|5|6|7|8|all] [--mode live|deterministic|remote-sim]
#   ./run_tests.sh [scenarios] [--mode ...] [--profile clean|wan|bad-wan|flaky]
#
# Modes:
#   live          Uses external uplink (default; current behavior)
#   deterministic Uses local isolated rnsd backbone only
#   remote-sim    Uses local isolated backbone via deterministic netem proxy

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../.." && pwd)"
PYTHON="${PYTHON:-$(command -v python3 || command -v python)}"
mkdir -p "$HOME/tmp"
if [ -n "${RFED_TEST_RUN_DIR:-}" ]; then
  RUN_BASE="$RFED_TEST_RUN_DIR"
else
  RUN_BASE="$(mktemp -d "$HOME/tmp/rfed-tests.XXXXXX")"
fi
RUN_ID="$(basename "$RUN_BASE")"
export RFED_TEST_RUN_DIR="$RUN_BASE"
LOG_DIR="$RUN_BASE/logs"
DATA_DIR="$RUN_BASE/rfed_data"

pass=0; fail=0
TEST_MODE="${RFED_TEST_MODE:-live}"
NET_PROFILE="${RFED_NET_PROFILE:-wan}"
ARTIFACT_DIR="$RUN_BASE/artifacts"

# ── Utilities ─────────────────────────────────────────────────────────────────

green() { echo -e "\033[32m$*\033[0m"; }
red()   { echo -e "\033[31m$*\033[0m"; }

set_namespace() {
  export RFED_TEST_NAMESPACE="$1"
  # Reset per-scenario client storage so stale paths/identities cannot leak
  # across scenarios while keeping intra-scenario persistence intact.
  find "$RUN_BASE" -maxdepth 1 -type d -name "*_${RFED_TEST_NAMESPACE}" -exec rm -rf {}/storage \; 2>/dev/null || true
}

scenario_channel() {
  echo "public.$1.$RUN_ID"
}

ensure_namespaced_config() {
  local template="$1"
  local target="$RUN_BASE/${template}_${RFED_TEST_NAMESPACE}"
  if [ ! -d "$target" ]; then
     cp -R "$TEST_DIR/$template" "$target"
     # Patch hardcoded test ports with per-run dynamic ports.  Without this, a
     # bash-copied config would still reference 4244/4245/4246/4247 even after
     # setup.sh allocated fresh ports — causing the client to connect to a stale
     # rfed from a previous run.
     local config_file="$target/config"
     if [ -f "$config_file" ] && [ -n "${RFED_TEST_HOST:-}" ]; then
      sed -i '' \
        -e "s/\(target_port = \)4244/\1${RFED_UPLINK_PORT}/g" \
        -e "s/\(target_port = \)4245/\1${RFED_PORT_B}/g" \
        -e "s/\(target_port = \)4246/\1${RFED_PORT_BP}/g" \
        -e "s/\(target_port = \)4247/\1${RFED_PORT_BN}/g" \
          -e "s/\(target_host = \)127\.0\.0\.1/\1${RFED_TEST_HOST}/g" \
          -e "s/\(target_host = \)localhost/\1${RFED_TEST_HOST}/g" \
          -e "s/\(listen_ip = \)127\.0\.0\.1/\10.0.0.0/g" \
        "$config_file"
     fi
  fi
  echo "$target"
}

run_py() {
  local label="$1"; shift
  local logfile="$LOG_DIR/$label.log"
  echo "[test] running: $*" | tee "$logfile"
  "$PYTHON" "$@" 2>&1 | tee -a "$logfile"
  return "${PIPESTATUS[0]}"
}

assert_log() {
  local logfile="$1"
  local pattern="$2"
  if grep -q "$pattern" "$logfile" 2>/dev/null; then
    return 0
  else
    return 1
  fi
}

report() {
  local name="$1" ok="$2"
  if [ "$ok" = "0" ]; then
    green "  PASS  $name"
    ((pass++)) || true
  else
    red   "  FAIL  $name"
    ((fail++)) || true
  fi
  collect_artifacts "$name" "$ok"
}

collect_artifacts() {
  local name="$1"
  local ok="$2"
  local status="FAIL"
  [ "$ok" = "0" ] && status="PASS"

  mkdir -p "$ARTIFACT_DIR"
  local stamp
  stamp="$(date +%Y%m%d-%H%M%S)"
  local out="$ARTIFACT_DIR/${RFED_TEST_NAMESPACE}_${name}_${status}_${stamp}"
  mkdir -p "$out"

  {
    echo "scenario=$name"
    echo "status=$status"
    echo "mode=$TEST_MODE"
    echo "profile=$NET_PROFILE"
    echo "namespace=${RFED_TEST_NAMESPACE:-unknown}"
    echo "run_base=$RUN_BASE"
    date
  } > "$out/meta.txt"

  cp "$DATA_DIR/hashes.env" "$out/hashes.env" 2>/dev/null || true
  cp "$DATA_DIR/ports.env" "$out/ports.env" 2>/dev/null || true

  if [ -f "$LOG_DIR/rfed.log" ]; then
    tail -n 400 "$LOG_DIR/rfed.log" > "$out/rfed.tail.log" || true
    grep -E "Path request|no path known|timed out|ERROR|WARN|announce|PASS|FAIL" "$out/rfed.tail.log" > "$out/rfed.signals.log" 2>/dev/null || true
  fi

  mkdir -p "$out/logs"
  cp "$LOG_DIR"/*.log "$out/logs" 2>/dev/null || true
}

apply_net_profile() {
  case "$NET_PROFILE" in
    clean)
      export NETEM_LATENCY_MS="0"
      export NETEM_JITTER_MS="0"
      export NETEM_DROP_PERCENT="0"
      ;;
    wan)
      export NETEM_LATENCY_MS="35"
      export NETEM_JITTER_MS="8"
      export NETEM_DROP_PERCENT="0"
      ;;
    bad-wan)
      export NETEM_LATENCY_MS="120"
      export NETEM_JITTER_MS="40"
      export NETEM_DROP_PERCENT="2"
      ;;
    flaky)
      export NETEM_LATENCY_MS="250"
      export NETEM_JITTER_MS="120"
      export NETEM_DROP_PERCENT="8"
      ;;
    *)
      echo "[test] ERROR: invalid profile '$NET_PROFILE'"
      echo "[test] valid profiles: clean, wan, bad-wan, flaky"
      exit 1
      ;;
  esac
  export RFED_NET_PROFILE="$NET_PROFILE"
}

assert_pid_running() {
  local pidfile="$1"
  local label="$2"
  if [ ! -f "$pidfile" ]; then
    echo "[test] ERROR: missing pidfile for $label ($pidfile)"
    return 1
  fi
  local pid
  pid=$(cat "$pidfile")
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "[test] ERROR: process not running for $label (pid $pid)"
    return 1
  fi
  return 0
}

# ── Load node hash ─────────────────────────────────────────────────────────────

load_hashes() {
  if [ ! -f "$DATA_DIR/hashes.env" ]; then
    echo "[test] hashes.env not found — run setup.sh first"
    exit 1
  fi
  # shellcheck disable=SC1090
  source "$DATA_DIR/hashes.env"
}

load_ports() {
  local PORTS_ENV="$DATA_DIR/ports.env"
  if [ ! -f "$PORTS_ENV" ]; then
    echo "[test] ports.env not found — run setup.sh first"
    exit 1
  fi
  # shellcheck disable=SC1090
  source "$PORTS_ENV"
  export RFED_TEST_PORT="$RFED_PORT"
  export RFED_TEST_PORT_B="$RFED_PORT_B"
  export RFED_TEST_PORT_BP="$RFED_PORT_BP"
  export RFED_TEST_PORT_BN="$RFED_PORT_BN"
  export RFED_TEST_HOST
  export RFED_UPLINK_PORT
}

# ── Scenario helpers ──────────────────────────────────────────────────────────

restart_rfed() {
  # Restart rfed without wiping the data directory (keeps subscriptions etc.)
  local PID_DIR="$RUN_BASE/.pids"
  local RFED_BIN="$ROOT_DIR/RFed-rust/target/debug/rfed"
  if [ -f "$PID_DIR/rfed.pid" ]; then
    kill "$(cat "$PID_DIR/rfed.pid")" 2>/dev/null || true
    rm -f "$PID_DIR/rfed.pid"
    sleep 1
  fi
  PYTHONUNBUFFERED=1 \
  "$RFED_BIN" \
    --config    "$DATA_DIR" \
    >> "$LOG_DIR/rfed.log" 2>&1 &
  echo $! > "$PID_DIR/rfed.pid"
  sleep 3  # allow rfed to announce
}

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 1: Live fanout
#   Subscriber comes online, publisher sends, subscriber should receive via
#   direct rfed.delivery packet fanout.
# ──────────────────────────────────────────────────────────────────────────────

test_live_fanout() {
  echo
  echo "=== Scenario 1: live fanout ==="
  set_namespace s1
  load_hashes
  local channel="$(scenario_channel live_fanout)"

  # Subscribe first (background, timeout 40s).
  run_py sub1 "$TEST_DIR/rfed_subscriber.py" "$RFED_NODE_HASH" \
      "$channel" "--timeout" "40" &
  SUB_PID=$!
  sleep 8  # let subscriber announce rfed.delivery to the network

  # Publish.
  run_py pub1 "$TEST_DIR/rfed_publisher.py" "$RFED_NODE_HASH" \
      "$channel" "live fanout message"

  # Wait for subscriber to finish.
  wait $SUB_PID || true

  # Evaluate.
  local ok=1
  assert_log "$LOG_DIR/sub1.log" "LIVE DELIVERY"      && ok=0
  assert_log "$LOG_DIR/sub1.log" "live fanout message" && ok=0 || true
  report "live_fanout" $ok
}

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 2: Deferred delivery
#   Subscriber registers but is NOT announcing (no live path), so rfed defers.
#   When subscriber comes back online (announces rfed.delivery), rfed flushes.
# ──────────────────────────────────────────────────────────────────────────────

test_deferred() {
  echo
  echo "=== Scenario 2: deferred delivery ==="
  set_namespace s2
  load_hashes
  local channel="$(scenario_channel deferred)"

  # Phase A — subscribe but stay offline (pull-only = no announce).
  run_py sub2a "$TEST_DIR/rfed_subscriber.py" "$RFED_NODE_HASH" \
      "$channel" "--pull-only"

  sleep 2

  # Phase B — publish (subscriber is offline, rfed will defer).
  run_py pub2 "$TEST_DIR/rfed_publisher.py" "$RFED_NODE_HASH" \
      "$channel" "deferred message"

  sleep 2

  # Phase C — subscriber comes back online; announces rfed.delivery.
  # rfed's announce handler detects this and flushes deferred blobs.
  run_py sub2b "$TEST_DIR/rfed_subscriber.py" "$RFED_NODE_HASH" \
      "$channel" "--timeout" "20" &
  SUB2B_PID=$!
  wait $SUB2B_PID || true

  # Evaluate: look for live delivery OR pull blobs from deferred flush.
  local ok=1
  assert_log "$LOG_DIR/sub2b.log" "LIVE DELIVERY"    && ok=0
  assert_log "$LOG_DIR/sub2b.log" "deferred message" && ok=0 || true
  # If neither live nor pull, check pull returned blobs returned.
  assert_log "$LOG_DIR/sub2b.log" "blob\[0\]"        && ok=0 || true
  report "deferred_delivery" $ok
}

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 3: Explicit pull
#   Subscriber registers offline, publisher sends, subscriber pulls.
# ──────────────────────────────────────────────────────────────────────────────

test_pull() {
  echo
  echo "=== Scenario 3: explicit pull ==="
  set_namespace s3
  load_hashes
  local channel="$(scenario_channel pull)"

  # Subscribe offline.
  run_py sub3a "$TEST_DIR/rfed_subscriber.py" "$RFED_NODE_HASH" \
      "$channel" "--pull-only"

  sleep 2

  # Publish (subscriber offline → stored in deferred queue).
  run_py pub3 "$TEST_DIR/rfed_publisher.py" "$RFED_NODE_HASH" \
      "$channel" "pull test message"

  sleep 2

  # Pull — pass --pull-only so it subscribes at top, then pulls at end.
  run_py sub3b "$TEST_DIR/rfed_subscriber.py" "$RFED_NODE_HASH" \
      "$channel" "--pull-only"

  # Evaluate: PULL section at the end of the log should report blobs.
  local ok=1
  assert_log "$LOG_DIR/sub3b.log" "PULL returned [1-9]"  && ok=0
  assert_log "$LOG_DIR/sub3b.log" "pull\[0\]"            && ok=0 || true
  report "explicit_pull" $ok
}

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 4: Notify wake-up
#   Relay registers; publisher sends while subscriber is offline; rfed fires
#   notify wake-up to relay; relay prints and exits 0.
# ──────────────────────────────────────────────────────────────────────────────

test_notify() {
  echo
  echo "=== Scenario 4: notify wake-up ==="
  set_namespace s4
  load_hashes
  local channel="$(scenario_channel notify)"

  # Start relay (background — waits up to 60s for a wake-up packet).
  run_py relay4 "$TEST_DIR/rfed_notify_relay.py" "$RFED_NODE_HASH" &
  RELAY_PID=$!
  sleep 5  # let relay announce and save its hash

  # Register the relay with rfed.
  if [ ! -f "$DATA_DIR/notify_relay_hash.txt" ]; then
    red "[test] relay hash file not found — rfed_notify_relay.py may not have started in time"
    wait $RELAY_PID || true
    report "notify_wakeup" 1
    return
  fi

  run_py reg4 "$TEST_DIR/rfed_notify_register.py" "$RFED_NODE_HASH" "auto"

  sleep 2

  # Subscribe offline so rfed has a subscription but can't deliver live.
  run_py sub4 "$TEST_DIR/rfed_subscriber.py" "$RFED_NODE_HASH" \
      "$channel" "--pull-only"

  sleep 1

  # Publish — delivery will fail (subscriber offline) → rfed fires notify.
  run_py pub4 "$TEST_DIR/rfed_publisher.py" "$RFED_NODE_HASH" \
      "$channel" "notify trigger message"

  # Wait for relay to receive the wake packet (timeout handled inside script).
  wait $RELAY_PID
  RELAY_EXIT=$?

  # Require relay to exit 0 AND print PASS line.
  local ok=1
  if [ "$RELAY_EXIT" = "0" ] && assert_log "$LOG_DIR/relay4.log" "PASS"; then
    ok=0
  fi
  report "notify_wakeup" $ok
}

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 5: Internode sync
#   Two rfed nodes connected on the same local mesh.  Publisher sends to Node A.
#   Node B is configured with Node A as a static peer so sync fires immediately.
#   Subscriber on Node B pulls after sync completes and should receive the blob.
# ──────────────────────────────────────────────────────────────────────────────

test_internode_sync() {
  echo
  echo "=== Scenario 5: internode sync ==="
  set_namespace s5
  load_hashes  # loads Node A hashes
  local channel="$(scenario_channel sync)"

  # Start Node B (requires Node A to be up).
  bash "$TEST_DIR/teardown_node_b.sh" 2>/dev/null || true
  bash "$TEST_DIR/setup_node_b.sh"
  NODE_B_HASH=$(cat "$RUN_BASE/rfed_data_b/node_hash.txt" 2>/dev/null || echo "")
  if [ -z "$NODE_B_HASH" ]; then
    red "[test] Node B failed to start"
    bash "$TEST_DIR/teardown_node_b.sh" 2>/dev/null || true
    report "internode_sync" 1
    return
  fi

  # Subscribe on Node B (pull-only — no live path yet, blob arrives via sync).
  run_py sub5 "$TEST_DIR/rfed_sync_subscriber.py" \
      "$NODE_B_HASH" "$channel" "sync test blob" "--timeout" "60" &
  SUB5_PID=$!

  # Wait until subscriber has actually registered its subscription on Node B
  # (look for the "subscribe response" line in the log).
  echo "[test] waiting for Node B subscriber to register..."
  for i in $(seq 1 30); do
    if grep -q "subscribe response" "$LOG_DIR/sub5.log" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  sleep 2  # brief extra margin

  # Publish to Node A.
  run_py pub5 "$TEST_DIR/rfed_publisher.py" "$RFED_NODE_HASH" \
      "$channel" "sync test blob"

  # Wait for subscriber (it does: subscribe → wait 30s for sync → PULL).
  wait $SUB5_PID
  SUB5_EXIT=$?

  bash "$TEST_DIR/teardown_node_b.sh" 2>/dev/null || true

  local ok=1
  if [ "$SUB5_EXIT" = "0" ] && assert_log "$LOG_DIR/sub5.log" "PASS"; then
    ok=0
  fi
  report "internode_sync" $ok
}

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 6: Backup subscription failover
#   Primary rfed node has a primary_node configured.  Subscriber registers on
#   primary (pull-only, no live path).  Primary pushes subscription entry to
#   backup node.  Publisher sends blob to primary.  Primary syncs blob to backup.
#   Primary is then killed.  After owner_offline_secs (12s) elapses, backup
#   node's backup_delivery_tick fires and moves the blob into deferred_queue for
#   the subscriber.  Subscriber then PULLs from backup node and receives blob.
# ──────────────────────────────────────────────────────────────────────────────

test_backup_failover() {
  echo
  echo "=== Scenario 6: backup subscription failover ==="
  set_namespace s6
  local channel="$(scenario_channel backup)"
  local publisher_config_dir="$(ensure_namespaced_config rns_publisher)"

  # Clear publisher's stale known_destinations so it discovers the backup
  # primary's identity fresh via announce/path-response.
  rm -rf "$publisher_config_dir/storage/known_destinations" 2>/dev/null || true
  rm -rf "$publisher_config_dir/storage/destination_table" 2>/dev/null || true

  # Clear register-phase subscriber's stale RNS state.
  rm -rf "$RUN_BASE/rns_backup_subscriber_register_${RFED_TEST_NAMESPACE}/storage" 2>/dev/null || true

  # Start fresh backup pair.
  bash "$TEST_DIR/teardown_backup_nodes.sh" 2>/dev/null || true
  bash "$TEST_DIR/setup_backup_nodes.sh"

  # Give RNS announce propagation a few extra seconds so subscriber can discover
  # primary's channel destination when it boots fresh.
  sleep 5

  PRIMARY_HASH=$(cat "$RUN_BASE/rfed_data_backup_primary/node_hash.txt" 2>/dev/null || echo "")
  BACKUP_HASH=$(cat  "$RUN_BASE/rfed_data_backup_node/node_hash.txt"    2>/dev/null || echo "")

  if [ -z "$PRIMARY_HASH" ] || [ -z "$BACKUP_HASH" ]; then
    red "[test] backup nodes failed to start"
    report "backup_failover" 1
    return
  fi

  # Phase 1 — Register subscription on primary (pull-only).
  # The subscriber identity is saved to rns_backup_subscriber/sub_identity so the
  # same identity is reused in the pull phase.
  run_py sub6reg "$TEST_DIR/rfed_backup_subscriber.py" \
      "$PRIMARY_HASH" "$BACKUP_HASH" "$channel" "backup failover message" \
      "--phase" "register"

  # Wait for the primary's backup push tick (30s hardcoded) to push the
  # subscription to the backup node.
  echo "[test] waiting 65s for backup push tick..."
  sleep 65

  # Save the main node hashes so we can restore after this scenario.
  cp "$RUN_BASE/rfed_data/hashes.env" "$RUN_BASE/rfed_data/hashes.env.bak" 2>/dev/null || true

  # Point the publisher's hashes.env at the backup primary's hashes so it finds
  # the correct rfed.channel hash instead of the one from scenarios 1-5.
  cp "$RUN_BASE/rfed_data_backup_primary/hashes.env" "$RUN_BASE/rfed_data/hashes.env" 2>/dev/null || true

  # Publisher already targets the fixed upstream endpoint (RFED_TEST_HOST:RFED_UPLINK_PORT).

  # Publish the blob to the primary.
  run_py pub6 "$TEST_DIR/rfed_publisher.py" "$PRIMARY_HASH" \
      "$channel" "backup failover message"

  # Wait long enough for the post-publish backup push tick (30s) and sync
  # backoff windows so the new blob is replicated before primary shutdown.
  echo "[test] waiting 65s for post-publish backup push + sync..."
  sleep 65

  # Kill the primary.
  echo "[test] killing primary node..."
  if [ -f "$RUN_BASE/.pids/rfed_backup_primary.pid" ]; then
    kill "$(cat "$RUN_BASE/.pids/rfed_backup_primary.pid")" 2>/dev/null || true
    rm -f "$RUN_BASE/.pids/rfed_backup_primary.pid"
  fi

  # Also stop the main Node A rfed so the backup node does not keep refreshing
  # owner liveness through stale transport paths while we're testing failover.
  if [ -f "$RUN_BASE/.pids/rfed.pid" ]; then
    kill "$(cat "$RUN_BASE/.pids/rfed.pid")" 2>/dev/null || true
    rm -f "$RUN_BASE/.pids/rfed.pid"
  fi

  # Wait for owner_offline_secs (12s) to elapse plus one backup delivery tick (30s).
  echo "[test] waiting 50s for owner_offline_secs + backup_delivery_tick..."
  sleep 50

  # Phase 2 — Pull from backup node.
  run_py sub6pull "$TEST_DIR/rfed_backup_subscriber.py" \
      "$PRIMARY_HASH" "$BACKUP_HASH" "$channel" "backup failover message" \
      "--phase" "pull" \
      "--timeout" "30"
  SUB6_EXIT=$?

  bash "$TEST_DIR/teardown_backup_nodes.sh" 2>/dev/null || true

  # No per-scenario publisher target_port rewrite needed with fixed upstream endpoint.

  # Restore main node hashes.env.
  if [ -f "$RUN_BASE/rfed_data/hashes.env.bak" ]; then
    mv "$RUN_BASE/rfed_data/hashes.env.bak" "$RUN_BASE/rfed_data/hashes.env"
  fi

  local ok=1
  if [ "$SUB6_EXIT" = "0" ] && assert_log "$LOG_DIR/sub6pull.log" "PASS"; then
    ok=0
  fi
  report "backup_failover" $ok
}

# ── Ensure rfed node is running for scenarios 1-5, 7 ─────────────────────────

# ── Ensure rfed node is running for scenarios 1-5, 7 ─────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 8: LXMF propagation store-and-forward
#   Pure LXMF store-and-forward through rfed's lxmf.propagation node.
#   Phase 1 (announce): receiver creates a persistent identity, announces to
#   rfed so rfed knows its public key, writes delivery hash and prop node hash
#   to rfed_data/ for the sender.
#   Phase 2 (send): sender uses the real Python LXMRouter with PROPAGATED
#   delivery method; rfed stores the encrypted message.
#   Phase 3 (sync): receiver syncs from rfed's lxmf.propagation node via
#   request_messages_from_propagation_node, decrypts the message, and verifies
#   the content matches.
# ──────────────────────────────────────────────────────────────────────────────

test_lxmf_prop_store_forward() {
  echo
  echo "=== Scenario 8: LXMF propagation store-and-forward ==="
  set_namespace s8
  load_hashes

  # Clean stale receiver identity and hash files so each run starts fresh.
  rm -f "$RUN_BASE/rfed_data/lxmf_receiver_hash.txt"
  rm -f "$RUN_BASE/rfed_data/prop_node_hash.txt"
  rm -f "$RUN_BASE/rfed_data/e2e_receiver_identity"
  rm -rf "$RUN_BASE/lxmf_storage/e2e_sender"
  rm -rf "$RUN_BASE/lxmf_storage/e2e_receiver"

  # Phase 1 — announce: receiver registers its identity with rfed.
  run_py prop8_recv_announce "$TEST_DIR/lxmf_e2e_receiver.py" "--announce" \
      "--timeout" "30"
  ANNOUNCE_EXIT=$?
  if [ "$ANNOUNCE_EXIT" != "0" ] || \
     [ ! -f "$RUN_BASE/rfed_data/lxmf_receiver_hash.txt" ] || \
     [ ! -f "$RUN_BASE/rfed_data/prop_node_hash.txt" ]; then
    red "[test] receiver announce phase failed"
    report "lxmf_prop_store_forward" 1
    return
  fi

  sleep 3  # let announce propagate through rfed

  # Phase 2 — send: sender pushes an encrypted LXMF message via PROPAGATED.
  run_py prop8_send "$TEST_DIR/lxmf_e2e_sender.py" "--timeout" "60"
  SEND_EXIT=$?
  if [ "$SEND_EXIT" != "0" ]; then
    red "[test] sender failed to store message on prop node"
    report "lxmf_prop_store_forward" 1
    return
  fi

  sleep 2  # brief margin before sync

  # Phase 3 — sync: receiver pulls messages from rfed's prop node and verifies.
  run_py prop8_recv_sync "$TEST_DIR/lxmf_e2e_receiver.py" "--sync" \
      "--timeout" "60"
  SYNC_EXIT=$?

  local ok=1
  if [ "$SYNC_EXIT" = "0" ] && assert_log "$LOG_DIR/prop8_recv_sync.log" "PASS"; then
    ok=0
  fi
  report "lxmf_prop_store_forward" $ok
}

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 7: LXMF propagation notify
#   A dedicated receiver registers itself with rfed.notify (subscriber=self,
#   relay=self).  A sender pushes a minimal LXMF propagation batch to rfed's
#   lxmf.propagation destination with the receiver's identity hash as recipient.
#   rfed extracts the recipient hash, looks it up in the notify registry, and
#   fires a wake-up packet to the receiver's rfed.notify destination.
# ──────────────────────────────────────────────────────────────────────────────

test_prop_notify() {
  echo
  echo "=== Scenario 7: LXMF propagation notify ==="
  set_namespace s7
  load_hashes

  # Clean up stale state from a previous run so we get a fresh receiver hash.
  rm -f "$DATA_DIR/prop_receiver_hash.txt"

  # Start receiver (background) — registers with rfed, then waits for wake.
  run_py prop_recv "$TEST_DIR/rfed_prop_receiver.py" "$RFED_NODE_HASH" \
      "--timeout" "60" &
  RECV_PID=$!

  # Wait until receiver prints "REGISTERED" (registration confirmed by rfed).
  echo "[test] waiting for prop_receiver to register..."
  local waited=0
  while [ $waited -lt 60 ]; do
    if grep -q "REGISTERED" "$LOG_DIR/prop_recv.log" 2>/dev/null; then
      break
    fi
    sleep 1
    ((waited++)) || true
  done

  if ! grep -q "REGISTERED" "$LOG_DIR/prop_recv.log" 2>/dev/null; then
    red "[test] prop_receiver did not register in time"
    wait $RECV_PID || true
    report "prop_notify" 1
    return
  fi

  sleep 2  # brief margin for rfed to persist registration before the send

  # Send LXMF propagation batch — reads subscriber hash from prop_receiver_hash.txt.
  run_py prop_send "$TEST_DIR/rfed_prop_sender.py" "$RFED_NODE_HASH"

  # Wait for receiver to get the wake packet (it exits 0 on success).
  wait $RECV_PID
  RECV_EXIT=$?

  local ok=1
  if [ "$RECV_EXIT" = "0" ] && assert_log "$LOG_DIR/prop_recv.log" "PASS"; then
    ok=0
  fi
  report "prop_notify" $ok
}

ensure_rfed() {
  local PID_DIR="$RUN_BASE/.pids"
  if [ -f "$PID_DIR/rfed.pid" ] && kill -0 "$(cat "$PID_DIR/rfed.pid")" 2>/dev/null; then
    load_ports  # rfed already running — load dynamic ports for child processes
    if [ "$TEST_MODE" = "deterministic" ]; then
      assert_pid_running "$PID_DIR/rnsd_backbone.pid" "local backbone" || return 1
    elif [ "$TEST_MODE" = "remote-sim" ]; then
      assert_pid_running "$PID_DIR/rnsd_backbone.pid" "local backbone" || return 1
      assert_pid_running "$PID_DIR/netem_proxy.pid" "netem proxy" || return 1
    fi
    return
  fi
  echo "[test] rfed not running — starting via setup.sh..."
  export RFED_TEST_MODE="$TEST_MODE"
  apply_net_profile
  bash "$TEST_DIR/setup.sh"
  load_ports
  if [ "$TEST_MODE" = "deterministic" ]; then
    assert_pid_running "$PID_DIR/rnsd_backbone.pid" "local backbone" || return 1
  elif [ "$TEST_MODE" = "remote-sim" ]; then
    assert_pid_running "$PID_DIR/rnsd_backbone.pid" "local backbone" || return 1
    assert_pid_running "$PID_DIR/netem_proxy.pid" "netem proxy" || return 1
  fi
}

stop_rfed() {
  local PID_DIR="$RUN_BASE/.pids"
  if [ -f "$PID_DIR/rfed.pid" ]; then
    kill "$(cat "$PID_DIR/rfed.pid")" 2>/dev/null || true
    rm -f "$PID_DIR/rfed.pid"
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

SCENARIOS="all"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode)
      if [ "$#" -lt 2 ]; then
        echo "[test] ERROR: --mode requires a value"
        exit 1
      fi
      TEST_MODE="$2"
      shift 2
      ;;
    --profile)
      if [ "$#" -lt 2 ]; then
        echo "[test] ERROR: --profile requires a value"
        exit 1
      fi
      NET_PROFILE="$2"
      shift 2
      ;;
    1|2|3|4|5|6|7|8|all|live_fanout|deferred|pull|notify|sync|backup|prop_notify|lxmf_prop)
      SCENARIOS="$1"
      shift
      ;;
    *)
      echo "Usage: $0 [1|2|3|4|5|6|7|8|all] [--mode live|deterministic|remote-sim]"
      exit 1
      ;;
  esac
done

case "$TEST_MODE" in
  live|deterministic|remote-sim) ;;
  *)
    echo "[test] ERROR: invalid mode '$TEST_MODE'"
    echo "[test] valid modes: live, deterministic, remote-sim"
    exit 1
    ;;
esac

export RFED_TEST_MODE="$TEST_MODE"
apply_net_profile

# Fresh logs.
mkdir -p "$LOG_DIR"
echo "[test] sandbox: $RUN_BASE"
echo "[test] mode: $TEST_MODE"
echo "[test] profile: $NET_PROFILE"

case "$SCENARIOS" in
  1|live_fanout)       ensure_rfed; test_live_fanout ;;
  2|deferred)          ensure_rfed; test_deferred ;;
  3|pull)              ensure_rfed; test_pull ;;
  4|notify)            ensure_rfed; test_notify ;;
  5|sync)              ensure_rfed; test_internode_sync ;;
  6|backup)
    ensure_rfed   # backup primary needs Node A running as backbone
    test_backup_failover ;;
  7|prop_notify)       ensure_rfed; test_prop_notify ;;
  8|lxmf_prop)        ensure_rfed; test_lxmf_prop_store_forward ;;
  all)
    ensure_rfed
    test_live_fanout
    test_deferred
    test_pull
    test_notify
    test_internode_sync
    test_lxmf_prop_store_forward
    test_prop_notify
    test_backup_failover   # needs Node A running as backbone for backup primary
    stop_rfed
    ;;
  *)
    echo "Usage: $0 [1|2|3|4|5|6|7|8|all] [--mode live|deterministic|remote-sim]"
    exit 1
    ;;
esac

echo
echo "══════════════════════════════════════"
echo "  Results:  $pass passed,  $fail failed"
echo "══════════════════════════════════════"
[ "$fail" = "0" ] && green "ALL TESTS PASSED" || red "SOME TESTS FAILED"
echo

[ "$fail" = "0" ]
