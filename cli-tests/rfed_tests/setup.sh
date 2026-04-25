#!/usr/bin/env bash
# setup.sh — Start rfed node for integration tests.
#             rfed now acts as its own RNS router (TCP server on port 4244).
#             All test clients connect directly to rfed on port 4244.
#
# Outputs: rfed_data/node_hash.txt  — rfed.node destination hash
#          rfed_data/hashes.env     — all 4 destination hashes

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../.." && pwd)"
RUN_BASE="${RFED_TEST_RUN_DIR:-$TEST_DIR}"
LOG_DIR="$RUN_BASE/logs"
PID_DIR="$RUN_BASE/.pids"
DATA_DIR="$RUN_BASE/rfed_data"
RFED_BIN="$ROOT_DIR/RFed-rust/target/debug/rfed"
RFED_TEST_MODE="${RFED_TEST_MODE:-live}"
NETEM_LATENCY_MS="${NETEM_LATENCY_MS:-35}"
NETEM_JITTER_MS="${NETEM_JITTER_MS:-8}"
NETEM_DROP_PERCENT="${NETEM_DROP_PERCENT:-0}"
NETEM_SEED="${NETEM_SEED:-1337}"
BACKBONE_DIR="$RUN_BASE/rnsd_backbone"

mkdir -p "$LOG_DIR" "$PID_DIR" "$DATA_DIR"

if [ ! -f "$DATA_DIR/config" ]; then
  cp "$TEST_DIR/rfed_data/config" "$DATA_DIR/config"
fi

# ── Allocate free ports for this run (no hardcoded ports → no stale conflicts) ─
# Each run gets its own unique TCP ports so concurrent or sequential runs never
# fight over the same socket.  All client configs are patched at sandbox-copy
# time via ensure_config_dir() / ensure_namespaced_config().

_free_port() {
  python3 -c "import socket; s=socket.socket(); s.bind(('0.0.0.0',0)); p=s.getsockname()[1]; s.close(); print(p)"
}

RFED_PORT=$(_free_port)
RFED_PORT_B=$(_free_port)
RFED_PORT_BP=$(_free_port)
RFED_PORT_BN=$(_free_port)
BACKBONE_PORT=$(_free_port)
NETEM_PROXY_PORT=$(_free_port)

stop_pid_if_running() {
  local pidfile="$1"
  if [ -f "$pidfile" ]; then
    local pid
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 0.5
      kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
}

start_local_backbone() {
  mkdir -p "$BACKBONE_DIR"
  cat > "$BACKBONE_DIR/config" <<EOF
[reticulum]
  share_instance = No
  enable_transport = Yes
  panic_on_interface_error = No

[logging]
  loglevel = 4

[interfaces]

  [[Backbone TCP Server]]
    type = TCPServerInterface
    enabled = Yes
    listen_ip = 127.0.0.1
    listen_port = $BACKBONE_PORT
EOF

  : > "$LOG_DIR/rnsd_backbone.log"
  PYTHONPATH="$ROOT_DIR/Reticulum-master" \
    python3 "$ROOT_DIR/Reticulum-master/RNS/Utilities/rnsd.py" \
      --config "$BACKBONE_DIR" \
      > "$LOG_DIR/rnsd_backbone.log" 2>&1 &
  echo $! > "$PID_DIR/rnsd_backbone.pid"

  for i in $(seq 1 20); do
    if grep -q "System interfaces are ready\|Bringing up system interfaces" "$LOG_DIR/rnsd_backbone.log" 2>/dev/null; then
      break
    fi
    sleep 0.5
  done
}

start_netem_proxy() {
  : > "$LOG_DIR/netem_proxy.log"
  python3 "$TEST_DIR/netem_proxy.py" \
    --listen-host 127.0.0.1 \
    --listen-port "$NETEM_PROXY_PORT" \
    --target-host 127.0.0.1 \
    --target-port "$BACKBONE_PORT" \
    --latency-ms "$NETEM_LATENCY_MS" \
    --jitter-ms "$NETEM_JITTER_MS" \
    --drop-percent "$NETEM_DROP_PERCENT" \
    --seed "$NETEM_SEED" \
    > "$LOG_DIR/netem_proxy.log" 2>&1 &
  echo $! > "$PID_DIR/netem_proxy.pid"

  for i in $(seq 1 20); do
    if grep -q "\[netem-proxy\] listening" "$LOG_DIR/netem_proxy.log" 2>/dev/null; then
      break
    fi
    sleep 0.3
  done
}

# rfed's own backbone uplink (what rfed itself connects to for network reachability).
# In live mode this is the NAS; in isolated modes it's the local rnsd backbone.
RFED_BACKBONE_HOST="${RFED_BACKBONE_HOST:-192.168.2.107}"
RFED_BACKBONE_PORT="${RFED_BACKBONE_PORT:-4242}"

if [ "$RFED_TEST_MODE" = "deterministic" ] || [ "$RFED_TEST_MODE" = "remote-sim" ]; then
  RFED_BACKBONE_HOST="127.0.0.1"
  RFED_BACKBONE_PORT="$BACKBONE_PORT"
  stop_pid_if_running "$PID_DIR/netem_proxy.pid"
  stop_pid_if_running "$PID_DIR/rnsd_backbone.pid"
  start_local_backbone

  if [ "$RFED_TEST_MODE" = "remote-sim" ]; then
    start_netem_proxy
    RFED_BACKBONE_PORT="$NETEM_PROXY_PORT"
  fi
fi

# Test clients ALWAYS connect directly to the local rfed's TCP server, regardless of mode.
# This eliminates NAS routing-table expiry races and avoids interference from other rfed
# nodes on the public backbone.
RFED_TEST_HOST="127.0.0.1"
RFED_UPLINK_PORT="$RFED_PORT"

{
  echo "RFED_TEST_MODE=$RFED_TEST_MODE"
  echo "RFED_PORT=$RFED_PORT"
  echo "RFED_PORT_B=$RFED_PORT_B"
  echo "RFED_PORT_BP=$RFED_PORT_BP"
  echo "RFED_PORT_BN=$RFED_PORT_BN"
  echo "RFED_TEST_HOST=$RFED_TEST_HOST"
  echo "RFED_UPLINK_PORT=$RFED_UPLINK_PORT"
  echo "RFED_BACKBONE_HOST=$RFED_BACKBONE_HOST"
  echo "RFED_BACKBONE_PORT=$RFED_BACKBONE_PORT"
  echo "BACKBONE_PORT=$BACKBONE_PORT"
  echo "NETEM_PROXY_PORT=$NETEM_PROXY_PORT"
  echo "NETEM_LATENCY_MS=$NETEM_LATENCY_MS"
  echo "NETEM_JITTER_MS=$NETEM_JITTER_MS"
  echo "NETEM_DROP_PERCENT=$NETEM_DROP_PERCENT"
  echo "NETEM_SEED=$NETEM_SEED"
} > "$DATA_DIR/ports.env"

export RFED_TEST_MODE
export RFED_TEST_PORT="$RFED_PORT"
export RFED_TEST_PORT_B="$RFED_PORT_B"
export RFED_TEST_PORT_BP="$RFED_PORT_BP"
export RFED_TEST_PORT_BN="$RFED_PORT_BN"
export RFED_TEST_HOST
export RFED_UPLINK_PORT
export RFED_BACKBONE_HOST
export RFED_BACKBONE_PORT

# ── Generate isolated rfed RNS config for this run ───────────────────────────
# Completely isolated: TCP server on dynamic port only, no rnsd/external peers.

cat > "$DATA_DIR/config" <<EOF
[reticulum]
  share_instance = No
  enable_transport = Yes
  panic_on_interface_error = No

[interfaces]

  [[Test TCP Server]]
    type = TCPServerInterface
    enabled = Yes
    listen_ip = 0.0.0.0
    listen_port = $RFED_PORT

  [[Uplink to backbone]]
    type = TCPClientInterface
    enabled = Yes
    target_host = $RFED_BACKBONE_HOST
    target_port = $RFED_BACKBONE_PORT

[node]
  name                      = rfed-e2e-test
  announce_interval_minutes = 1
  announce_at_start         = yes
  lxmf_propagation          = yes

[storage]

[peering]

[policy.default]
  stamp_cost = 0

[policy.vip]
  stamp_cost = 0
EOF

# ── Kill any stale processes ──────────────────────────────────────────────────

pkill -f "rfed.*$DATA_DIR" 2>/dev/null || true
rm -f "$PID_DIR/rfed.pid"
sleep 0.5

# ── Clear stale rfed state (keep identity for stable hashes across runs) ──────

# Copy test TOML into the data directory where rfed expects it.
cp "$TEST_DIR/rfed.toml" "$DATA_DIR/rfed.toml"

rm -f "$DATA_DIR/subscriptions.rmp" \
      "$DATA_DIR/deferred_queue.rmp" \
      "$DATA_DIR/notify_registrations.rmp" \
      "$DATA_DIR/peer_state.rmp" \
      "$DATA_DIR/hashes.env" \
      "$DATA_DIR/node_hash.txt" \
      "$DATA_DIR/notify_relay_hash.txt"
rm -rf "$DATA_DIR/blobs"

: > "$LOG_DIR/rfed.log"

# ── Build rfed if needed ──────────────────────────────────────────────────────

if [ ! -f "$RFED_BIN" ]; then
  echo "[setup] building rfed..."
  (cd "$ROOT_DIR/RFed-rust" && cargo build --bin rfed 2>&1)
fi

# ── Start rfed ────────────────────────────────────────────────────────────────

echo "[setup] starting rfed..."
"$RFED_BIN" \
  --config   "$DATA_DIR" \
  > "$LOG_DIR/rfed.log" 2>&1 &
echo $! > "$PID_DIR/rfed.pid"

# Wait for rfed to bind TCP port 4244 and announce its destinations.
echo "[setup] waiting for rfed to announce..."
for i in $(seq 1 30); do
  if grep -q "rfed\.node" "$LOG_DIR/rfed.log" 2>/dev/null; then
    break
  fi
  sleep 1
done

if ! grep -q "rfed\.node" "$LOG_DIR/rfed.log" 2>/dev/null; then
  echo "[setup] ERROR: rfed did not start in time. See $LOG_DIR/rfed.log"
  cat "$LOG_DIR/rfed.log"
  exit 1
fi

# Brief extra settle time so rfed's RNS destinations are fully registered
# and path requests are answered immediately when tests start.
sleep 2
# ── Extract destination hashes from rfed log ──────────────────────────────────

extract_hash() {
  grep "rfed\.$1" "$LOG_DIR/rfed.log" | grep -oE '[0-9a-f]{32}' | tail -1
}

NODE_HASH=$(extract_hash node)
DELIVERY_HASH=$(extract_hash delivery)
CHANNEL_HASH=$(extract_hash channel)
NOTIFY_HASH=$(extract_hash notify)

if [ -z "$NODE_HASH" ]; then
  echo "[setup] ERROR: could not parse rfed destination hashes from log"
  cat "$LOG_DIR/rfed.log"
  exit 1
fi

# Write for test scripts to consume.
echo "$NODE_HASH" > "$DATA_DIR/node_hash.txt"
{
  echo "RFED_NODE_HASH=$NODE_HASH"
  echo "RFED_CHANNEL_HASH=$CHANNEL_HASH"
  echo "RFED_DELIVERY_HASH=$DELIVERY_HASH"
  echo "RFED_NOTIFY_HASH=$NOTIFY_HASH"
} > "$DATA_DIR/hashes.env"

echo ""
echo "[setup] rfed running"
echo "  rfed.node     : $NODE_HASH"
echo "  rfed.channel  : $CHANNEL_HASH"
echo "  rfed.delivery : $DELIVERY_HASH"
echo "  rfed.notify   : $NOTIFY_HASH"
echo ""
echo "[setup] ready. Log:"
echo "  rfed : $LOG_DIR/rfed.log"
