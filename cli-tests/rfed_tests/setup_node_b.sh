#!/usr/bin/env bash
# setup_node_b.sh — Start rfed Node B for internode sync tests.
#
# Node B runs on port 4245.  Its RNS config connects to Node A (port 4244)
# so both nodes share one mesh.  Node A's hash is injected into Node B's
# rfed.toml as a static peer so sync starts immediately without waiting for
# the announce backoff.
#
# Prerequisite: setup.sh (Node A) must already be running.
#
# Outputs: rfed_data_b/node_hash.txt
#          rfed_data_b/hashes.env

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../.." && pwd)"
RUN_BASE="${RFED_TEST_RUN_DIR:-$TEST_DIR}"
LOG_DIR="$RUN_BASE/logs"
PID_DIR="$RUN_BASE/.pids"
DATA_A="$RUN_BASE/rfed_data"
DATA_B="$RUN_BASE/rfed_data_b"
RFED_BIN="$ROOT_DIR/RFed-rust/target/debug/rfed"

mkdir -p "$LOG_DIR" "$PID_DIR" "$DATA_B"

if [ ! -f "$DATA_B/config" ]; then
  cp "$TEST_DIR/rfed_data_b/config" "$DATA_B/config"
fi

# ── Require Node A to be running ─────────────────────────────────────────────
# ── Load dynamic ports allocated by setup.sh ─────────────────────────────────

if [ ! -f "$DATA_A/ports.env" ]; then
  echo "[setup-b] ERROR: ports.env not found — run setup.sh first"
  exit 1
fi
source "$DATA_A/ports.env"

# ── Require Node A to be running ─────────────────────────────────────────────

if [ ! -f "$DATA_A/node_hash.txt" ]; then
  echo "[setup-b] ERROR: Node A not running — run setup.sh first"
  exit 1
fi

NODE_A_HASH=$(cat "$DATA_A/node_hash.txt")
echo "[setup-b] Node A hash: $NODE_A_HASH"

# ── Generate isolated Node B RNS config for this run ────────────────────────
# Server on RFED_PORT_B; client peer to Node A on RFED_PORT.
# No external connections — fully isolated test topology.

cat > "$DATA_B/config" <<EOF
[reticulum]
  share_instance = No
  enable_transport = No
  panic_on_interface_error = No

[interfaces]

  [[Test TCP Server B]]
    type = TCPServerInterface
    enabled = Yes
    listen_ip = 0.0.0.0
    listen_port = $RFED_PORT_B

  [[Uplink to rnsd]]
    type = TCPClientInterface
    enabled = Yes
    target_host = $RFED_TEST_HOST
    target_port = $RFED_UPLINK_PORT

[node]
  name                      = rfed-test-b
  announce_interval_minutes = 1
  announce_at_start         = yes

[storage]

[peering]

[policy.default]
  stamp_cost = 0
EOF

# ── Stop stale Node B ────────────────────────────────────────────────────────

if [ -f "$PID_DIR/rfed_b.pid" ]; then
  pid=$(cat "$PID_DIR/rfed_b.pid")
  kill "$pid" 2>/dev/null || true
  sleep 1
  rm -f "$PID_DIR/rfed_b.pid"
fi
pkill -f "rfed.*$DATA_B" 2>/dev/null || true

# ── Clear stale Node B state (keep identity so hash is stable) ───────────────

rm -f "$DATA_B/subscriptions.rmp" \
      "$DATA_B/deferred_queue.rmp" \
      "$DATA_B/notify_registrations.rmp" \
      "$DATA_B/peer_state.rmp" \
      "$DATA_B/hashes.env" \
      "$DATA_B/node_hash.txt" \
      "$DATA_B/rfed.toml"
rm -rf "$DATA_B/blobs"
: > "$LOG_DIR/rfed_b.log"

# ── Generate rfed.toml for Node B with Node A's hash injected ────────────────

sed "s/NODE_A_HASH/$NODE_A_HASH/" "$TEST_DIR/rfed_b.toml.tpl" > "$DATA_B/rfed.toml"
echo "[setup-b] generated rfed.toml for Node B (static peer = $NODE_A_HASH)"

# ── Start Node B ─────────────────────────────────────────────────────────────

echo "[setup-b] starting rfed Node B..."
"$RFED_BIN" \
  --config    "$DATA_B" \
  --name      "rfed-test-b" \
  --announce-interval 1 \
  --static-peer "$NODE_A_HASH" \
  > "$LOG_DIR/rfed_b.log" 2>&1 &
echo $! > "$PID_DIR/rfed_b.pid"

# Wait for Node B to announce.
echo "[setup-b] waiting for Node B to announce..."
for i in $(seq 1 30); do
  if grep -q "rfed\.node" "$LOG_DIR/rfed_b.log" 2>/dev/null; then
    break
  fi
  sleep 1
done

if ! grep -q "rfed\.node" "$LOG_DIR/rfed_b.log" 2>/dev/null; then
  echo "[setup-b] ERROR: Node B did not start in time. See $LOG_DIR/rfed_b.log"
  cat "$LOG_DIR/rfed_b.log"
  exit 1
fi

# ── Extract Node B destination hashes ────────────────────────────────────────

extract_hash() {
  grep "rfed\.$1" "$LOG_DIR/rfed_b.log" | grep -oE '[0-9a-f]{32}' | tail -1
}

NODE_B_HASH=$(extract_hash node)
DELIVERY_B_HASH=$(extract_hash delivery)
CHANNEL_B_HASH=$(extract_hash channel)
NOTIFY_B_HASH=$(extract_hash notify)

if [ -z "$NODE_B_HASH" ]; then
  echo "[setup-b] ERROR: could not parse Node B hashes from log"
  cat "$LOG_DIR/rfed_b.log"
  exit 1
fi

echo "$NODE_B_HASH" > "$DATA_B/node_hash.txt"
{
  echo "RFED_NODE_HASH=$NODE_B_HASH"
  echo "RFED_CHANNEL_HASH=$CHANNEL_B_HASH"
  echo "RFED_DELIVERY_HASH=$DELIVERY_B_HASH"
  echo "RFED_NOTIFY_HASH=$NOTIFY_B_HASH"
} > "$DATA_B/hashes.env"

echo ""
echo "[setup-b] Node B running"
echo "  rfed.node     : $NODE_B_HASH"
echo "  rfed.channel  : $CHANNEL_B_HASH"
echo "  rfed.delivery : $DELIVERY_B_HASH"
echo ""
echo "[setup-b] Log: $LOG_DIR/rfed_b.log"
