#!/usr/bin/env bash
# test_registration.sh — Test notify-relay address registration with rfed
#                         using external rnsd at 192.168.2.107:4242
#
# Usage: ./test_registration.sh
#
# What it does:
#   1. Starts rfed connecting to rnsd at 192.168.2.107:4242
#   2. Waits for rfed to announce its rfed.notify destination
#   3. Runs test_reg.py which opens a link, identifies, and sends
#      /rfed/notify/register — verifying rfed responds with True
#   4. Reports PASS or FAIL and cleans up

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TEST_DIR/../.." && pwd)"
RFED_BIN="$ROOT_DIR/RFed-rust/target/debug/rfed"
LOG_DIR="$TEST_DIR/logs"
PID_DIR="$TEST_DIR/.pids"
DATA_DIR="$TEST_DIR/rfed_data_ext"
RNS_CFG_RFED="$TEST_DIR/rns_rfed_ext"
RNS_CFG_CLIENT="$TEST_DIR/rns_client_ext"

mkdir -p "$LOG_DIR" "$PID_DIR" "$DATA_DIR"

green() { echo -e "\033[32m$*\033[0m"; }
red()   { echo -e "\033[31m$*\033[0m"; }

# ── Find a working Python (one that can import RNS) ───────────────────────────

find_python() {
    local candidates=(
        "${PYTHON:-}"
        "$ROOT_DIR/.venv/bin/python"
        "$ROOT_DIR/.venv/bin/python3"
        "$(command -v python3 2>/dev/null)"
        "$(command -v python 2>/dev/null)"
    )
    for py in "${candidates[@]}"; do
        [ -z "$py" ] && continue
        if "$py" -c "import RNS, msgpack" 2>/dev/null; then
            echo "$py"
            return 0
        fi
    done
    return 1
}

PYTHON="$(find_python)" || {
    red "[test] FAIL: no Python found with RNS and msgpack installed"
    red "       Install via: pip3 install --user rns msgpack"
    exit 1
}
echo "[test] using Python: $PYTHON"

# ── Prereq checks ─────────────────────────────────────────────────────────────

if [ ! -f "$RFED_BIN" ]; then
    echo "[test] rfed binary not found — building..."
    (cd "$ROOT_DIR/RFed-rust" && cargo build --bin rfed 2>&1) || {
        red "[test] FAIL: could not build rfed"
        exit 1
    }
fi

# ── Ensure rfed.toml is in data dir ──────────────────────────────────────────

cp "$DATA_DIR/rfed.toml" "$DATA_DIR/rfed.toml" 2>/dev/null || true   # already there

# ── Kill any stale rfed_ext instance ─────────────────────────────────────────

if [ -f "$PID_DIR/rfed_ext.pid" ]; then
    kill "$(cat "$PID_DIR/rfed_ext.pid")" 2>/dev/null || true
    rm -f "$PID_DIR/rfed_ext.pid"
    sleep 0.5
fi

# Wipe stale rfed state (keep identity for stable hash across repeated runs)
rm -f "$DATA_DIR/subscriptions.rmp" \
      "$DATA_DIR/notify_registrations.rmp" \
      "$DATA_DIR/deferred_queue.rmp" \
      "$DATA_DIR/peer_state.rmp"
rm -rf "$DATA_DIR/blobs"

: > "$LOG_DIR/rfed_ext.log"

# ── Start rfed ─────────────────────────────────────────────────────────────────

echo "[test] starting rfed (rnsd: 192.168.2.107:4242)..."
"$RFED_BIN" \
    --config    "$DATA_DIR" \
    --rnsconfig "$RNS_CFG_RFED" \
    >> "$LOG_DIR/rfed_ext.log" 2>&1 &
echo $! > "$PID_DIR/rfed_ext.pid"

# ── Helper: stop rfed on exit ─────────────────────────────────────────────────

cleanup() {
    if [ -f "$PID_DIR/rfed_ext.pid" ]; then
        kill "$(cat "$PID_DIR/rfed_ext.pid")" 2>/dev/null || true
        rm -f "$PID_DIR/rfed_ext.pid"
    fi
}
trap cleanup EXIT

# ── Wait for rfed.notify hash in log ─────────────────────────────────────────

echo "[test] waiting for rfed to announce (up to 30s)..."
RFED_NOTIFY_HASH=""
RFED_NODE_HASH=""

for i in $(seq 1 30); do
    RFED_NOTIFY_HASH=$(grep -o 'rfed\.notify[^|]*|[[:space:]]*[0-9a-f]\{32\}' \
        "$LOG_DIR/rfed_ext.log" 2>/dev/null \
        | grep -oE '[0-9a-f]{32}' | tail -1)

    # Fallback: any 32-hex sequence following 'rfed.notify'
    if [ -z "$RFED_NOTIFY_HASH" ]; then
        RFED_NOTIFY_HASH=$(grep "rfed.notify" "$LOG_DIR/rfed_ext.log" 2>/dev/null \
            | grep -oE '[0-9a-f]{32}' | tail -1)
    fi

    RFED_NODE_HASH=$(grep "rfed.node" "$LOG_DIR/rfed_ext.log" 2>/dev/null \
        | grep -oE '[0-9a-f]{32}' | tail -1)

    [ -n "$RFED_NOTIFY_HASH" ] && break
    sleep 1
done

if [ -z "$RFED_NOTIFY_HASH" ]; then
    red "[test] FAIL: rfed did not announce rfed.notify hash within timeout"
    echo "--- rfed log ---"
    cat "$LOG_DIR/rfed_ext.log"
    exit 1
fi

echo "[test] rfed.notify hash : $RFED_NOTIFY_HASH"
[ -n "$RFED_NODE_HASH" ] && echo "[test] rfed.node hash   : $RFED_NODE_HASH"

# ── Run the registration test client ─────────────────────────────────────────

echo "[test] running registration test..."
"$PYTHON" "$TEST_DIR/test_reg.py" \
    "$RFED_NOTIFY_HASH" \
    "${RFED_NODE_HASH:-}" \
    2>&1 | tee "$LOG_DIR/test_reg.log"
REG_EXIT=${PIPESTATUS[0]}

# ── Report ────────────────────────────────────────────────────────────────────

echo
if [ "$REG_EXIT" = "0" ]; then
    green "  PASS  notify_registration"
else
    red   "  FAIL  notify_registration"
    echo  "        See $LOG_DIR/test_reg.log for details"
    exit 1
fi
