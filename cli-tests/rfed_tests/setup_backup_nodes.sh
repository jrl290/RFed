#!/usr/bin/env bash
# setup_backup_nodes.sh — Start a primary + backup rfed pair for Scenario 6.
#
# Topology:
#   Primary   → port 4246 (TCP server, acts as its own router)
#   Backup    → port 4247 (TCP server + client to primary via port 4246)
#   Subscriber → connects to port 4247 for failover pull
#
# Three-phase startup (order matters for RNS TCP connectivity):
#   1. Start primary bare (no primary_node yet) → TCP server on 4246 is ready.
#   2. Start backup node with primary as static_peer → backup connects to 4246 → get backup hash.
#   3. Restart primary with primary_node = <backup_hash> so push ticks work.
#
# Outputs:
#   rfed_data_backup_node/node_hash.txt    — backup node rfed.node hash
#   rfed_data_backup_node/hashes.env
#   rfed_data_backup_primary/node_hash.txt — primary rfed.node hash
#   rfed_data_backup_primary/hashes.env

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../.." && pwd)"
RUN_BASE="${RFED_TEST_RUN_DIR:-$TEST_DIR}"
LOG_DIR="$RUN_BASE/logs"
PID_DIR="$RUN_BASE/.pids"
DATA_BN="$RUN_BASE/rfed_data_backup_node"
DATA_BP="$RUN_BASE/rfed_data_backup_primary"
RFED_BIN="$ROOT_DIR/RFed-rust/target/debug/rfed"

mkdir -p "$LOG_DIR" "$PID_DIR" "$DATA_BN" "$DATA_BP"

# Clear stale runtime state from prior runs while keeping identities stable.
rm -f "$DATA_BP/subscriptions.rmp" \
  "$DATA_BP/deferred_queue.rmp" \
  "$DATA_BP/notify_registrations.rmp" \
  "$DATA_BP/peer_state.rmp" \
  "$DATA_BP/hashes.env" \
  "$DATA_BP/node_hash.txt"
rm -rf "$DATA_BP/blobs"

rm -f "$DATA_BN/subscriptions.rmp" \
  "$DATA_BN/deferred_queue.rmp" \
  "$DATA_BN/notify_registrations.rmp" \
  "$DATA_BN/peer_state.rmp" \
  "$DATA_BN/hashes.env" \
  "$DATA_BN/node_hash.txt"
rm -rf "$DATA_BN/blobs"

if [ ! -f "$DATA_BN/config" ]; then
  cp "$TEST_DIR/rfed_data_backup_node/config" "$DATA_BN/config"
fi
if [ ! -f "$DATA_BP/config" ]; then
  cp "$TEST_DIR/rfed_data_backup_primary/config" "$DATA_BP/config"
fi

# ── Kill any stale backup-test processes ─────────────────────────────────────
# ── Load dynamic ports allocated by setup.sh ─────────────────────────────────

PORTS_ENV="$RUN_BASE/rfed_data/ports.env"
if [ ! -f "$PORTS_ENV" ]; then
  echo "[setup-backup] ERROR: ports.env not found — run setup.sh first"
  exit 1
fi
source "$PORTS_ENV"

# ── Generate isolated backup node RNS configs for this run ───────────────────
# Backup primary: TCP server on RFED_PORT_BP only (no external peers).
# Backup node:    TCP server on RFED_PORT_BN + client to primary on RFED_PORT_BP.

cat > "$DATA_BP/config" <<EOF
[reticulum]
  share_instance = No
  enable_transport = Yes
  panic_on_interface_error = No

[interfaces]

  [[Test TCP Server Backup Primary]]
    type = TCPServerInterface
    enabled = Yes
    listen_ip = 0.0.0.0
    listen_port = $RFED_PORT_BP

  [[Uplink to Node A]]
    type = TCPClientInterface
    enabled = Yes
    target_host = 127.0.0.1
    target_port = $RFED_PORT

[node]
  name                      = rfed-backup-primary
  announce_interval_minutes = 1
  announce_at_start         = yes

[storage]

[peering]

[policy.default]
  stamp_cost = 0
EOF

cat > "$DATA_BN/config" <<EOF
[reticulum]
  share_instance = No
  enable_transport = Yes
  panic_on_interface_error = No

[interfaces]

  [[Test TCP Server Backup Node]]
    type = TCPServerInterface
    enabled = Yes
    listen_ip = 0.0.0.0
    listen_port = $RFED_PORT_BN

  [[Uplink to rnsd]]
    type = TCPClientInterface
    enabled = Yes
    target_host = $RFED_TEST_HOST
    target_port = $RFED_UPLINK_PORT

[node]
  name                      = rfed-backup-node
  announce_interval_minutes = 1
  announce_at_start         = yes

[storage]

[peering]

[policy.default]
  stamp_cost = 0
EOF

# ── Kill any stale backup-test processes ─────────────────────────────────────
if [ -f "$PID_DIR/rfed_backup_node.pid" ]; then
  kill "$(cat "$PID_DIR/rfed_backup_node.pid")" 2>/dev/null || true
  rm -f "$PID_DIR/rfed_backup_node.pid"
fi
if [ -f "$PID_DIR/rfed_backup_primary.pid" ]; then
  kill "$(cat "$PID_DIR/rfed_backup_primary.pid")" 2>/dev/null || true
  rm -f "$PID_DIR/rfed_backup_primary.pid"
fi
sleep 0.5

# ── Clear stale state (keep identities for stable hashes) ────────────────────

for DATA_DIR in "$DATA_BN" "$DATA_BP"; do
  rm -f "$DATA_DIR/subscriptions.rmp" \
        "$DATA_DIR/deferred_delivery.rmp" \
        "$DATA_DIR/notify_registrations.rmp" \
        "$DATA_DIR/peer_state.rmp" \
        "$DATA_DIR/peers.rmp" \
        "$DATA_DIR/hashes.env" \
        "$DATA_DIR/node_hash.txt"
  rm -rf "$DATA_DIR/blobs"
done
: > "$LOG_DIR/rfed_backup_node.log"
: > "$LOG_DIR/rfed_backup_primary.log"

extract_hash_from_log() {
  grep "rfed\.$1" "$2" | grep -oE '[0-9a-f]{32}' | tail -1
}

wait_for_start() {
  local logfile="$1"
  local label="$2"
  for i in $(seq 1 30); do
    if grep -q "rfed\.node" "$logfile" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "[setup-backup] ERROR: $label did not start. See $logfile"
  cat "$logfile"
  exit 1
}

# ── Phase 1: Start primary bare (no secondary_node yet) ─────────────────────
# Primary's TCP server must be up BEFORE backup node tries to connect to it.

echo "[setup-backup] phase 1: starting primary node (port 4246)..."
"$RFED_BIN" \
  --config    "$DATA_BP" \
  --name      "rfed-backup-primary" \
  --announce-interval 0.1 \
  > "$LOG_DIR/rfed_backup_primary.log" 2>&1 &
echo $! > "$PID_DIR/rfed_backup_primary.pid"
wait_for_start "$LOG_DIR/rfed_backup_primary.log" "primary"

BP_NODE_HASH=$(extract_hash_from_log node "$LOG_DIR/rfed_backup_primary.log")
BP_CHANNEL_HASH=$(extract_hash_from_log channel "$LOG_DIR/rfed_backup_primary.log")
BP_DELIVERY_HASH=$(extract_hash_from_log delivery "$LOG_DIR/rfed_backup_primary.log")
BP_NOTIFY_HASH=$(extract_hash_from_log notify "$LOG_DIR/rfed_backup_primary.log")

if [ -z "$BP_NODE_HASH" ]; then
  echo "[setup-backup] ERROR: could not parse primary node hashes"
  cat "$LOG_DIR/rfed_backup_primary.log"
  exit 1
fi

echo "$BP_NODE_HASH" > "$DATA_BP/node_hash.txt"
{
  echo "RFED_NODE_HASH=$BP_NODE_HASH"
  echo "RFED_CHANNEL_HASH=$BP_CHANNEL_HASH"
  echo "RFED_DELIVERY_HASH=$BP_DELIVERY_HASH"
  echo "RFED_NOTIFY_HASH=$BP_NOTIFY_HASH"
} > "$DATA_BP/hashes.env"

echo "[setup-backup] Primary (phase 1) up: $BP_NODE_HASH"

# ── Phase 2: Start backup node with primary as static_peer ───────────────────
# Now that primary's TCP server is listening on 4246, backup node can connect.

echo "[setup-backup] phase 2: starting backup node (port 4247)..."
"$RFED_BIN" \
  --config      "$DATA_BN" \
  --name        "rfed-backup-node" \
  --announce-interval 0.1 \
  --static-peer "$BP_NODE_HASH" \
  > "$LOG_DIR/rfed_backup_node.log" 2>&1 &
echo $! > "$PID_DIR/rfed_backup_node.pid"
wait_for_start "$LOG_DIR/rfed_backup_node.log" "backup node"

BN_NODE_HASH=$(extract_hash_from_log node "$LOG_DIR/rfed_backup_node.log")
BN_CHANNEL_HASH=$(extract_hash_from_log channel "$LOG_DIR/rfed_backup_node.log")
BN_DELIVERY_HASH=$(extract_hash_from_log delivery "$LOG_DIR/rfed_backup_node.log")
BN_NOTIFY_HASH=$(extract_hash_from_log notify "$LOG_DIR/rfed_backup_node.log")

if [ -z "$BN_NODE_HASH" ]; then
  echo "[setup-backup] ERROR: could not parse backup node hashes"
  cat "$LOG_DIR/rfed_backup_node.log"
  exit 1
fi

echo "$BN_NODE_HASH" > "$DATA_BN/node_hash.txt"
{
  echo "RFED_NODE_HASH=$BN_NODE_HASH"
  echo "RFED_CHANNEL_HASH=$BN_CHANNEL_HASH"
  echo "RFED_DELIVERY_HASH=$BN_DELIVERY_HASH"
  echo "RFED_NOTIFY_HASH=$BN_NOTIFY_HASH"
} > "$DATA_BN/hashes.env"

echo "[setup-backup] Backup node up: $BN_NODE_HASH"

# ── Phase 3: Restart primary with primary_node = BN_NODE_HASH ────────────────
# Now we know both hashes.  Restart primary so it knows where to push backups.

kill "$(cat "$PID_DIR/rfed_backup_primary.pid")" 2>/dev/null || true
rm -f "$PID_DIR/rfed_backup_primary.pid"
sleep 1

: > "$LOG_DIR/rfed_backup_primary.log"

echo "[setup-backup] phase 3: restarting primary with secondary_node + static_peer = $BN_NODE_HASH..."
"$RFED_BIN" \
  --config         "$DATA_BP" \
  --name           "rfed-backup-primary" \
  --announce-interval 0.1 \
  --secondary-node "$BN_NODE_HASH" \
  --static-peer    "$BN_NODE_HASH" \
  > "$LOG_DIR/rfed_backup_primary.log" 2>&1 &
echo $! > "$PID_DIR/rfed_backup_primary.pid"
wait_for_start "$LOG_DIR/rfed_backup_primary.log" "primary (phase 3)"

# Re-extract hashes in case identity was regenerated (it won't be, but safety).
BP_NODE_HASH=$(extract_hash_from_log node "$LOG_DIR/rfed_backup_primary.log")
if [ -z "$BP_NODE_HASH" ]; then
  echo "[setup-backup] ERROR: primary phase-3 hashes not found"
  cat "$LOG_DIR/rfed_backup_primary.log"
  exit 1
fi
{
  echo "RFED_NODE_HASH=$BP_NODE_HASH"
  echo "RFED_CHANNEL_HASH=$(extract_hash_from_log channel "$LOG_DIR/rfed_backup_primary.log")"
  echo "RFED_DELIVERY_HASH=$(extract_hash_from_log delivery "$LOG_DIR/rfed_backup_primary.log")"
  echo "RFED_NOTIFY_HASH=$(extract_hash_from_log notify "$LOG_DIR/rfed_backup_primary.log")"
} > "$DATA_BP/hashes.env"
echo "$BP_NODE_HASH" > "$DATA_BP/node_hash.txt"

echo ""
echo "[setup-backup] Primary    : $BP_NODE_HASH  (port 4246)"
echo "[setup-backup] Backup node: $BN_NODE_HASH  (port 4247)"
echo "[setup-backup] Backup deliver: $BN_DELIVERY_HASH"
echo ""
echo "[setup-backup] Logs:"
echo "  rfed_backup_primary.log"
echo "  rfed_backup_node.log"
