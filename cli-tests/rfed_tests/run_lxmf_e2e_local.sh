#!/usr/bin/env bash
# run_lxmf_e2e_local.sh — End-to-end LXMF store-and-forward test via rfed.
#
# Tests the standard LXMF propagation store-and-forward:
#   1. Python rnsd acts as the central transport router (TCP server :4242)
#   2. rfed connects upstream to rnsd; provides lxmf.propagation on TCP :4244
#   3. Receiver (Python LXMRouter) announces its identity, writes delivery hash
#   4. Sender (Python LXMRouter) sends a real encrypted LXMF message via PROPAGATED
#   5. Receiver syncs from rfed's lxmf.propagation, decrypts and prints message
#
# Usage:  ./run_lxmf_e2e_local.sh [--timeout N]   (default 90s)

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../.." && pwd)"
PYTHON="$(command -v python3)"
RNSD="$(command -v rnsd 2>/dev/null || echo "${HOME}/Library/Python/3.9/bin/rnsd")"
RFED_BIN="$ROOT_DIR/RFed-rust/target/debug/rfed"

LOG_DIR="$TEST_DIR/logs"
PID_DIR="$TEST_DIR/.pids"
DATA_DIR="$TEST_DIR/rfed_data"

TIMEOUT=90
for i in "$@"; do
  case "$i" in
    --timeout) shift; TIMEOUT="${1:-90}" ;;
  esac
done

mkdir -p "$LOG_DIR" "$PID_DIR" "$DATA_DIR"

# ── Cleanup ───────────────────────────────────────────────────────────────────

RFED_PID=""
RNSD_PID=""

cleanup() {
  echo ""
  echo "[e2e] cleaning up..."
  [[ -n "$RFED_PID" ]] && kill "$RFED_PID" 2>/dev/null || true
  [[ -n "$RNSD_PID" ]] && kill "$RNSD_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  # Ensure port 4244 is released for future runs
  pkill -f "RFed-rust.*rfed" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Kill stale instances (rfed or rnsd may be lingering from a previous run)
pkill -f "RFed-rust.*rfed" 2>/dev/null || true
pkill -f "rfed_tests/rns_rnsd_local" 2>/dev/null || true
# Wait for port 4244 to be released
for i in $(seq 1 20); do
  if ! lsof -i :4244 >/dev/null 2>&1; then break; fi
  sleep 0.5
done
sleep 0.5

# ── Step 1: Start rnsd ───────────────────────────────────────────────────────

echo "[e2e] starting rnsd on 127.0.0.1:4242..."
: > "$LOG_DIR/rnsd_e2e.log"
"$RNSD" --config "$TEST_DIR/rns_rnsd_local" \
  > "$LOG_DIR/rnsd_e2e.log" 2>&1 &
RNSD_PID=$!

for i in $(seq 1 20); do
  if grep -q "Started rnsd\|Reticulum Network Stack\|TCPServer" "$LOG_DIR/rnsd_e2e.log" 2>/dev/null; then
    break
  fi
  sleep 0.5
done
echo "[e2e] rnsd PID=$RNSD_PID"

# ── Step 2: Build rfed if needed ─────────────────────────────────────────────

if [ ! -f "$RFED_BIN" ]; then
  echo "[e2e] building rfed..."
  (cd "$ROOT_DIR/RFed-rust" && cargo build --bin rfed 2>&1)
fi

# ── Step 3: Write rfed config and start rfed ─────────────────────────────────

echo "[e2e] starting rfed (upstream → rnsd :4242, clients → :4244)..."

cp "$TEST_DIR/rfed.toml" "$DATA_DIR/rfed.toml"

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

rm -f "$DATA_DIR/subscriptions.rmp" \
      "$DATA_DIR/deferred_queue.rmp" \
      "$DATA_DIR/notify_registrations.rmp" \
      "$DATA_DIR/hashes.env" \
      "$DATA_DIR/node_hash.txt" \
      "$DATA_DIR/peers.rmp" \
      "$DATA_DIR/lxmf_receiver_hash.txt" \
      "$DATA_DIR/prop_node_hash.txt" \
      "$DATA_DIR/e2e_receiver_identity"

: > "$LOG_DIR/rfed_e2e.log"

"$RFED_BIN" \
  --config "$DATA_DIR" \
  > "$LOG_DIR/rfed_e2e.log" 2>&1 &
RFED_PID=$!

echo "[e2e] rfed PID=$RFED_PID"

echo "[e2e] waiting for rfed to announce..."
for i in $(seq 1 40); do
  if grep -q "rfed\.node" "$LOG_DIR/rfed_e2e.log" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$RFED_PID" 2>/dev/null; then
    echo "[e2e] FAIL: rfed exited unexpectedly"
    cat "$LOG_DIR/rfed_e2e.log"
    exit 1
  fi
  sleep 1
done

if ! grep -q "rfed\.node" "$LOG_DIR/rfed_e2e.log" 2>/dev/null; then
  echo "[e2e] FAIL: rfed did not announce in time"
  cat "$LOG_DIR/rfed_e2e.log"
  exit 1
fi

NODE_HASH=$(grep "rfed\.node" "$LOG_DIR/rfed_e2e.log" | grep -oE '[0-9a-f]{32}' | tail -1)
echo "[e2e] rfed node hash: $NODE_HASH"
echo "$NODE_HASH" > "$DATA_DIR/node_hash.txt"

# ── Step 4: Run receiver (announce phase) ────────────────────────────────────
# Receiver creates its identity, announces, writes delivery hash + prop node hash
# to rfed_data/*.txt files, then exits.

echo "[e2e] running receiver in announce phase..."
: > "$LOG_DIR/e2e_receiver_announce.log"
"$PYTHON" "$TEST_DIR/lxmf_e2e_receiver.py" --announce \
  > "$LOG_DIR/e2e_receiver_announce.log" 2>&1
ANNOUNCE_EXIT=$?

echo "--- receiver (announce) log ---"
cat "$LOG_DIR/e2e_receiver_announce.log"

if [ "$ANNOUNCE_EXIT" -ne 0 ]; then
  echo "[e2e] FAIL: receiver announce phase exited with code $ANNOUNCE_EXIT"
  exit 1
fi

if [ ! -f "$DATA_DIR/lxmf_receiver_hash.txt" ]; then
  echo "[e2e] FAIL: receiver did not write lxmf_receiver_hash.txt"
  exit 1
fi
RECEIVER_HASH=$(cat "$DATA_DIR/lxmf_receiver_hash.txt")
echo "[e2e] receiver delivery hash: $RECEIVER_HASH"

# Brief pause so rfed can clean up the receiver's connection before sender connects
sleep 2

# ── Step 5: Run sender ───────────────────────────────────────────────────────

echo "[e2e] running sender (real LXMF PROPAGATED message)..."
: > "$LOG_DIR/e2e_sender.log"
"$PYTHON" "$TEST_DIR/lxmf_e2e_sender.py" --timeout "$TIMEOUT" \
  > "$LOG_DIR/e2e_sender.log" 2>&1
SENDER_EXIT=$?

echo "--- sender log ---"
cat "$LOG_DIR/e2e_sender.log"

if [ "$SENDER_EXIT" -ne 0 ]; then
  echo "[e2e] FAIL: sender exited with code $SENDER_EXIT"
  echo "--- rfed log ---"
  tail -40 "$LOG_DIR/rfed_e2e.log"
  exit 1
fi

# ── Step 6: Run receiver (sync phase) ────────────────────────────────────────

echo "[e2e] running receiver in sync phase (request_messages_from_propagation_node)..."
: > "$LOG_DIR/e2e_receiver_sync.log"
"$PYTHON" "$TEST_DIR/lxmf_e2e_receiver.py" --sync --timeout "$TIMEOUT" \
  > "$LOG_DIR/e2e_receiver_sync.log" 2>&1
SYNC_EXIT=$?

echo "--- receiver (sync) log ---"
cat "$LOG_DIR/e2e_receiver_sync.log"

if [ "$SYNC_EXIT" -eq 0 ] && grep -q "PASS" "$LOG_DIR/e2e_receiver_sync.log" 2>/dev/null; then
  echo ""
  echo "[e2e] *** PASS *** Standard LXMF store-and-forward via rfed complete ✓"
  echo "[e2e]   - Real LXMRouter sender → rfed lxmf.propagation → Real LXMRouter receiver"
  echo "[e2e]   - Message encrypted by sender, stored by rfed, decrypted by receiver"

  echo ""
  echo "--- rfed propagation log (last 20 lines) ---"
  tail -20 "$LOG_DIR/rfed_e2e.log"
  exit 0
else
  echo ""
  echo "[e2e] FAIL: receiver did not decrypt/deliver message (exit=$SYNC_EXIT)"
  echo "--- rfed log (last 40 lines) ---"
  tail -40 "$LOG_DIR/rfed_e2e.log"
  exit 1
fi
