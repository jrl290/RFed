#!/usr/bin/env bash
# test_channel.sh — End-to-end rfed channel test.
#
# Starts a fresh rfed instance (connected to 192.168.2.107:4242),
# then runs the Rust rfed_channel_e2e binary as sender+receiver.
#
# Usage:
#   ./test_channel.sh [--channel-name NAME] [--message TEXT] [--timeout N]
#
# Requirements:
#   - 192.168.2.107:4242 must be reachable (RPi rnsd)
#   - RFed-rust must be built (cargo build --release or --debug in RFed-rust/)

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../.." && pwd)"

# ── Args ──────────────────────────────────────────────────────────────────────

CHANNEL_NAME="public.test.channel"
MESSAGE="hello from rfed_channel_e2e $(date +%s)"
TIMEOUT=60
RFED_PORT=4246
STAMP_COST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --channel-name) CHANNEL_NAME="$2"; shift 2 ;;
    --message)      MESSAGE="$2";      shift 2 ;;
    --timeout)      TIMEOUT="$2";      shift 2 ;;
    --rfed-port)    RFED_PORT="$2";    shift 2 ;;
    --stamp-cost)   STAMP_COST="$2";   shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ── Paths ─────────────────────────────────────────────────────────────────────

RFED_BIN=""
for candidate in \
    "$ROOT_DIR/RFed-rust/target/release/rfed" \
    "$ROOT_DIR/RFed-rust/target/debug/rfed"
do
    if [[ -f "$candidate" ]]; then
        RFED_BIN="$candidate"
        break
    fi
done

E2E_BIN=""
for candidate in \
    "$ROOT_DIR/RFed-rust/target/release/rfed_channel_e2e" \
    "$ROOT_DIR/RFed-rust/target/debug/rfed_channel_e2e"
do
    if [[ -f "$candidate" ]]; then
        E2E_BIN="$candidate"
        break
    fi
done

if [[ -z "$RFED_BIN" || -z "$E2E_BIN" ]]; then
    echo "[test] Building rfed and rfed_channel_e2e..."
    (cd "$ROOT_DIR/RFed-rust" && cargo build --release --bin rfed --bin rfed_channel_e2e 2>&1)
    RFED_BIN="$ROOT_DIR/RFed-rust/target/release/rfed"
    E2E_BIN="$ROOT_DIR/RFed-rust/target/release/rfed_channel_e2e"
fi

echo "[test] rfed binary:    $RFED_BIN"
echo "[test] e2e binary:     $E2E_BIN"

# ── Fresh rfed data directory ─────────────────────────────────────────────────

RFED_DATA="/tmp/rfed_channel_test_data"
RFED_LOG="/tmp/rfed_channel_test.log"

mkdir -p "$RFED_DATA"

# Clear mutable state; keep identity file for stable hashes across repeated runs.
rm -f "$RFED_DATA/subscriptions.rmp" \
      "$RFED_DATA/deferred_queue.rmp" \
      "$RFED_DATA/notify_registrations.rmp" \
      "$RFED_DATA/peer_state.rmp"
rm -rf "$RFED_DATA/blobs"

# Write rfed config (RNS format — rfed reads interfaces from here).
cat > "$RFED_DATA/config" <<EOF
[reticulum]
  enable_transport = Yes
  share_instance   = No
  panic_on_interface_error = No

[interfaces]

  [[RPi Upstream]]
    type        = TCPClientInterface
    enabled     = Yes
    target_host = 192.168.2.107
    target_port = 4242

  [[Local TCP Server]]
    type       = TCPServerInterface
    enabled    = Yes
    listen_ip  = 127.0.0.1
    listen_port = ${RFED_PORT}

[node]
  name                         = rfed-channel-test
  announce_interval_minutes    = 1
  announce_at_start            = yes
  lxmf_propagation             = no

[storage]
  limit_mb = 100

[policy.default]
  allow_notify_registration = yes
  allow_subscription        = yes
EOF

# Append stamp_cost to config if specified.
if [[ -n "$STAMP_COST" ]]; then
    echo "  stamp_cost                = ${STAMP_COST}" >> "$RFED_DATA/config"
fi

# ── Start rfed ────────────────────────────────────────────────────────────────

# Kill any stale test instance.
pkill -f "rfed --config $RFED_DATA" 2>/dev/null || true
sleep 0.5

: > "$RFED_LOG"
# Short announce interval so the e2e binary catches the re-announce quickly.
"$RFED_BIN" --config "$RFED_DATA" --announce-interval 0.1 > "$RFED_LOG" 2>&1 &
RFED_PID=$!
echo "[test] rfed started (PID $RFED_PID), port $RFED_PORT, log $RFED_LOG"

# Wait for rfed to announce its destinations.
echo "[test] Waiting for rfed to announce..."
for i in $(seq 1 30); do
    if grep -q "rfed\.channel" "$RFED_LOG" 2>/dev/null; then
        echo "[test] rfed is up (${i}s)"
        break
    fi
    if ! kill -0 "$RFED_PID" 2>/dev/null; then
        echo "[test] FAIL: rfed process died. Log:"
        cat "$RFED_LOG"
        exit 1
    fi
    sleep 1
done

if ! grep -q "rfed\.channel" "$RFED_LOG" 2>/dev/null; then
    echo "[test] FAIL: rfed did not announce within 30s. Log:"
    tail -30 "$RFED_LOG"
    kill "$RFED_PID" 2>/dev/null || true
    exit 1
fi

# Parse rfed's channel hash from the log.
RFED_CHANNEL_HASH=$(grep "rfed\.channel" "$RFED_LOG" | grep -oE '[0-9a-f]{32}' | tail -1)
echo "[test] rfed.channel hash: $RFED_CHANNEL_HASH"

# ── Clean up stale test identities ───────────────────────────────────────────

# Remove sender/receiver identities so each run starts fresh.
rm -f /tmp/rfed_channel_e2e/recv_identity \
      /tmp/rfed_channel_e2e/send_identity

# ── Run the e2e test binary ───────────────────────────────────────────────────

echo "[test] Running e2e test..."
echo "---"

set +e
"$E2E_BIN" \
    --rfed-port         "$RFED_PORT" \
    --rfed-channel-hash "$RFED_CHANNEL_HASH" \
    --channel-name      "$CHANNEL_NAME" \
    --message           "$MESSAGE" \
    --timeout           "$TIMEOUT" \
    ${STAMP_COST:+--stamp-cost "$STAMP_COST"}
E2E_EXIT=$?
set -e

echo "---"

# ── Cleanup ───────────────────────────────────────────────────────────────────

kill "$RFED_PID" 2>/dev/null || true

if [[ $E2E_EXIT -eq 0 ]]; then
    echo "[test] ✓ PASS"
else
    echo "[test] ✗ FAIL (exit $E2E_EXIT)"
    echo "[test] === rfed log (last 40 lines) ==="
    tail -40 "$RFED_LOG"
fi

exit $E2E_EXIT
