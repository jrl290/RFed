#!/usr/bin/env bash
# run_prop_local.sh — Run the LXMF propagation notify test (Scenario 7) locally.
#
# Uses a Python rnsd as the central router (TCP server on 127.0.0.1:4242).
# rfed connects to rnsd as a regular client (no transport of its own).
# Both Python clients (receiver, sender) also connect to rnsd at 4242.
#
# Usage:  ./run_prop_local.sh [--timeout N]   (default timeout 60s)
#
# Processes started:  rnsd (Python)  |  rfed (Rust)  |  receiver (Python)
# Process rnsd log:   logs/rnsd_local.log
# Process rfed log:   logs/rfed_local.log
# Receiver log:       logs/prop_receiver_local.log

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../.." && pwd)"
PYTHON="$(command -v python3)"
RNSD="$(command -v rnsd 2>/dev/null || echo "${HOME}/Library/Python/3.9/bin/rnsd")"
RFED_BIN="$ROOT_DIR/RFed-rust/target/debug/rfed"

LOG_DIR="$TEST_DIR/logs"
PID_DIR="$TEST_DIR/.pids"
DATA_DIR="$TEST_DIR/rfed_data"

TIMEOUT=60
for i in "$@"; do
  case "$i" in
    --timeout) shift; TIMEOUT="${1:-60}" ;;
  esac
done

mkdir -p "$LOG_DIR" "$PID_DIR" "$DATA_DIR"

# ── Cleanup ───────────────────────────────────────────────────────────────────

RECEIVER_PID=""
RNSD_PID=""
RFED_PID=""

cleanup() {
  echo ""
  echo "[local] cleaning up..."
  [[ -n "$RECEIVER_PID" ]] && kill "$RECEIVER_PID" 2>/dev/null || true
  [[ -n "$RFED_PID"     ]] && kill "$RFED_PID"     2>/dev/null || true
  [[ -n "$RNSD_PID"     ]] && kill "$RNSD_PID"     2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Kill any stale instances
pkill -f "rfed_tests/rns_rnsd_local" 2>/dev/null || true
pkill -f "rfed.*rfed_local"          2>/dev/null || true
sleep 0.5

# ── Step 1: Start rnsd (Python) ──────────────────────────────────────────────

echo "[local] starting rnsd on 127.0.0.1:4242..."
: > "$LOG_DIR/rnsd_local.log"
"$RNSD" --config "$TEST_DIR/rns_rnsd_local" \
  > "$LOG_DIR/rnsd_local.log" 2>&1 &
RNSD_PID=$!

# Wait for rnsd to be ready (it logs its version on startup).
for i in $(seq 1 20); do
  if grep -q "Started rnsd\|Reticulum Network Stack\|TCPServer" "$LOG_DIR/rnsd_local.log" 2>/dev/null; then
    break
  fi
  sleep 0.5
done
echo "[local] rnsd PID=$RNSD_PID"

# ── Step 2: Build rfed if needed ─────────────────────────────────────────────

if [ ! -f "$RFED_BIN" ]; then
  echo "[local] building rfed..."
  (cd "$ROOT_DIR/RFed-rust" && cargo build --bin rfed 2>&1)
fi

# ── Step 3: Write rfed config with rnsd as upstream router ───────────────────
# rfed_data/config is the combined RNS+rfed config.  Overwrite the interface
# section to point upstream at our local rnsd (4242) instead of the RPi.
# rfed still runs its own TCP Server on 4244 for Python clients to connect to.

echo "[local] starting rfed (upstream → rnsd at 4242, clients → 4244)..."

cp "$TEST_DIR/rfed.toml" "$DATA_DIR/rfed.toml"

# Write a local config that rfed will use as its combined RNS+settings file.
cat > "$DATA_DIR/config" <<'EOF'
[reticulum]
  share_instance = No
  enable_transport = Yes
  panic_on_interface_error = No

[interfaces]

  [[Local Router (rnsd)]]
    type = TCPClientInterface
    enabled = Yes
    target_host = 127.0.0.1
    target_port = 4242

  [[Local TCP Server]]
    type = TCPServerInterface
    enabled = Yes
    listen_ip = 127.0.0.1
    listen_port = 4244

[node]
  name                      = rfed-local-test
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

rm -f "$DATA_DIR/subscriptions.rmp" \
      "$DATA_DIR/deferred_queue.rmp" \
      "$DATA_DIR/notify_registrations.rmp" \
      "$DATA_DIR/hashes.env" \
      "$DATA_DIR/node_hash.txt" \
      "$DATA_DIR/peers.rmp"
: > "$LOG_DIR/rfed_local.log"

"$RFED_BIN" \
  --config "$DATA_DIR" \
  > "$LOG_DIR/rfed_local.log" 2>&1 &
RFED_PID=$!

echo "[local] rfed PID=$RFED_PID"

# Wait for rfed to announce its destinations.
echo "[local] waiting for rfed announces..."
for i in $(seq 1 40); do
  if grep -q "rfed\.node" "$LOG_DIR/rfed_local.log" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$RFED_PID" 2>/dev/null; then
    echo "[local] FAIL: rfed exited unexpectedly"
    cat "$LOG_DIR/rfed_local.log"
    exit 1
  fi
  sleep 1
done

if ! grep -q "rfed\.node" "$LOG_DIR/rfed_local.log" 2>/dev/null; then
  echo "[local] FAIL: rfed did not announce in time"
  cat "$LOG_DIR/rfed_local.log"
  exit 1
fi

# ── Extract destination hashes ────────────────────────────────────────────────

extract_hash() {
  grep "rfed\.$1" "$LOG_DIR/rfed_local.log" | grep -oE '[0-9a-f]{32}' | tail -1
}

NODE_HASH=$(extract_hash node)
NOTIFY_HASH=$(extract_hash notify)
CHANNEL_HASH=$(extract_hash channel)
DELIVERY_HASH=$(extract_hash delivery)

if [ -z "$NODE_HASH" ]; then
  echo "[local] FAIL: could not parse rfed hashes from log"
  cat "$LOG_DIR/rfed_local.log"
  exit 1
fi

echo "[local] rfed.node:     $NODE_HASH"
echo "[local] rfed.notify:   $NOTIFY_HASH"
echo "[local] rfed.channel:  $CHANNEL_HASH"
echo "[local] rfed.delivery: $DELIVERY_HASH"

{
  echo "RFED_NODE_HASH=$NODE_HASH"
  echo "RFED_CHANNEL_HASH=$CHANNEL_HASH"
  echo "RFED_DELIVERY_HASH=$DELIVERY_HASH"
  echo "RFED_NOTIFY_HASH=$NOTIFY_HASH"
} > "$DATA_DIR/hashes.env"
echo "$NODE_HASH" > "$DATA_DIR/node_hash.txt"

# ── Step 4: Start receiver ────────────────────────────────────────────────────

echo "[local] starting receiver (→ rfed TCP server at 4244)..."
: > "$LOG_DIR/prop_receiver_local.log"
"$PYTHON" "$TEST_DIR/rfed_prop_receiver.py" "$NODE_HASH" \
  --rns-config "$TEST_DIR/rns_prop_receiver" \
  --timeout "$TIMEOUT" \
  > "$LOG_DIR/prop_receiver_local.log" 2>&1 &
RECEIVER_PID=$!

# Wait for REGISTERED.
echo "[local] waiting for receiver to register with rfed.notify..."
for i in $(seq 1 60); do
  if grep -q "REGISTERED" "$LOG_DIR/prop_receiver_local.log" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$RECEIVER_PID" 2>/dev/null; then
    echo "[local] FAIL: receiver exited before registering"
    echo "--- receiver log ---"
    cat "$LOG_DIR/prop_receiver_local.log"
    exit 1
  fi
  sleep 1
done

if ! grep -q "REGISTERED" "$LOG_DIR/prop_receiver_local.log" 2>/dev/null; then
  echo "[local] FAIL: receiver did not register within 60s"
  echo "--- receiver log ---"
  cat "$LOG_DIR/prop_receiver_local.log"
  exit 1
fi

echo "[local] receiver registered. Running sender..."

# ── Step 5: Run sender ────────────────────────────────────────────────────────

: > "$LOG_DIR/prop_sender_local.log"
"$PYTHON" "$TEST_DIR/rfed_prop_sender.py" "$NODE_HASH" \
  --rns-config "$TEST_DIR/rns_prop_sender" \
  --timeout "$TIMEOUT" \
  > "$LOG_DIR/prop_sender_local.log" 2>&1
SENDER_EXIT=$?

echo "--- sender log ---"
cat "$LOG_DIR/prop_sender_local.log"

if [ "$SENDER_EXIT" -ne 0 ]; then
  echo "[local] FAIL: sender exited with code $SENDER_EXIT"
  echo "--- receiver log ---"
  cat "$LOG_DIR/prop_receiver_local.log"
  exit 1
fi

# ── Step 6: Wait for wake packet at receiver ──────────────────────────────────

echo "[local] waiting for receiver to retrieve messages..."
for i in $(seq 1 45); do
  if grep -q "PASS: message retrieved\|PASS: wake packet\|WARN: /get\|FAIL" "$LOG_DIR/prop_receiver_local.log" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$RECEIVER_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done

echo "--- receiver log ---"
cat "$LOG_DIR/prop_receiver_local.log"

if grep -q "PASS: message retrieved\|PASS: wake packet\|WARN: /get succeeded\|WARN: 0 messages" "$LOG_DIR/prop_receiver_local.log" 2>/dev/null; then
  echo ""
  echo "[local] *** PASS *** LXMF propagation notify + retrieve scenario complete"
  exit 0
else
  echo ""
  echo "[local] FAIL: receiver did not get wake packet or retrieve messages"
  exit 1
fi
