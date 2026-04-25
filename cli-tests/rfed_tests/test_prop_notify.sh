#!/usr/bin/env bash
# test_prop_notify.sh — End-to-end test for rfed propagation notify feature
# Stage 1: compute relay hash offline (no RNS process)
# Stage 2: register relay hash with rfed
# Stage 3: start relay listener in background
# Stage 4: send LXMF propagation batch
# Stage 5: wait for relay to receive wake packet and exit 0

set -euo pipefail
cd "$(dirname "$0")"
TEST_DIR="$(pwd)"

# ── colours ─────────────────────────────────────────────────────────────────
green() { echo -e "\033[32m$*\033[0m"; }
red()   { echo -e "\033[31m$*\033[0m"; }
yellow(){ echo -e "\033[33m$*\033[0m"; }

PYTHON=/usr/bin/python3
RFED_DATA_DIR="$TEST_DIR/rfed_data"
RFED_PID_DIR="$TEST_DIR/.pids"
RFED_PID_FILE="$RFED_PID_DIR/rfed.pid"

# Relay identity is pre-created; hash computed offline from it
RELAY_IDENTITY_FILE="$TEST_DIR/rns_notify_relay/relay_identity"
RELAY_HASH_FILE="$TEST_DIR/relay_hash_result.txt"

# lxmf.propagation hash is computed dynamically from rfed identity (see Stage 0)

# Timeouts (seconds)
REG_TIMEOUT=240    # registration: wait for rfed.notify path + link
RELAY_TIMEOUT=120  # relay: wait for wake packet
SEND_DELAY=5       # seconds to let relay announce before sending

PIDS_TO_KILL=()
trap 'cleanup' EXIT

cleanup() {
    for p in "${PIDS_TO_KILL[@]:-}"; do
        kill "$p" 2>/dev/null || true
        wait "$p" 2>/dev/null || true
    done
}

# ── rfed must already be running ─────────────────────────────────────────────
if [ ! -f "$RFED_PID_FILE" ]; then
    red "[test] rfed PID file missing at $RFED_PID_FILE"
    echo "  Start rfed first:"
    echo "  cd RFed-rust && cargo run -- --rnsconfig ../cli-tests/rfed_tests/rns_node --datadir ../cli-tests/rfed_tests/rfed_data --stamp-cost 0 2>&1 | tee rfed.log &"
    exit 1
fi
RFED_PID=$(cat "$RFED_PID_FILE")
if ! kill -0 "$RFED_PID" 2>/dev/null; then
    red "[test] rfed process $RFED_PID is not running"
    exit 1
fi
yellow "[test] rfed running (PID $RFED_PID)"

# Load rfed hashes
if [ ! -f "$RFED_DATA_DIR/hashes.env" ]; then
    red "[test] $RFED_DATA_DIR/hashes.env not found"
    exit 1
fi
source "$RFED_DATA_DIR/hashes.env"
yellow "[test] rfed.node   hash = $RFED_NODE_HASH"
yellow "[test] rfed.notify hash = $RFED_NOTIFY_HASH"

# ── Stage 0: compute lxmf.propagation hash and subscriber identity hash ──────
LXMF_PROP_HASH=$($PYTHON -c "
import hashlib, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
data = open(sys.argv[1],'rb').read()
enc_pub = X25519PrivateKey.from_private_bytes(data[:32]).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
sign_pub = Ed25519PrivateKey.from_private_bytes(data[32:64]).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
id_hash = hashlib.sha256(enc_pub + sign_pub).digest()[:16]
name_hash = hashlib.sha256(b'lxmf.propagation').digest()[:10]
print(hashlib.sha256(name_hash + id_hash).digest()[:16].hex())
" "$RFED_DATA_DIR/identity")
yellow "[test] lxmf.propagation hash = $LXMF_PROP_HASH"

SUB_IDENTITY_FILE="$TEST_DIR/rns_subscriber/sub_identity"
if [ ! -f "$SUB_IDENTITY_FILE" ]; then
    red "[test] Subscriber identity not found at $SUB_IDENTITY_FILE"
    exit 1
fi
SUB_HASH=$($PYTHON -c "
import hashlib, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
data = open(sys.argv[1],'rb').read()
enc_pub = X25519PrivateKey.from_private_bytes(data[:32]).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
sign_pub = Ed25519PrivateKey.from_private_bytes(data[32:64]).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
print(hashlib.sha256(enc_pub + sign_pub).digest()[:16].hex())
" "$SUB_IDENTITY_FILE")
yellow "[test] subscriber identity hash = $SUB_HASH"

# ── Stage 1: compute relay hash offline ──────────────────────────────────────
echo ""
yellow "[Stage 1] Computing relay destination hash offline..."

if [ ! -f "$RELAY_IDENTITY_FILE" ]; then
    # Need to create relay identity first by running relay briefly
    yellow "[Stage 1] Relay identity not found; running relay briefly to create it..."
    $PYTHON rfed_notify_relay.py "$RFED_NODE_HASH" "0000000000000000000000000000000" --timeout 5 \
        > /tmp/relay_init.log 2>&1 || true
    sleep 6
    if [ ! -f "$RELAY_IDENTITY_FILE" ]; then
        red "[Stage 1] FAIL: relay identity still not created"
        exit 1
    fi
fi

$PYTHON relay_hash.py "$RELAY_IDENTITY_FILE" > "$RELAY_HASH_FILE"
RELAY_HASH=$(cat "$RELAY_HASH_FILE" | tr -d '\n')
if [ -z "$RELAY_HASH" ]; then
    red "[Stage 1] FAIL: relay_hash.py produced empty output"
    exit 1
fi
green "[Stage 1] PASS: relay hash = $RELAY_HASH"

# ── Stage 2: register relay hash with rfed ────────────────────────────────────
echo ""
yellow "[Stage 2] Registering relay hash with rfed (no relay running to avoid interference)..."
yellow "[Stage 2]   rfed.node = $RFED_NODE_HASH"
yellow "[Stage 2]   relay     = $RELAY_HASH"
yellow "[Stage 2]   timeout   = ${REG_TIMEOUT}s"

REG_LOG="/tmp/rfed_notify_register_$$.log"
$PYTHON rfed_notify_register.py "$RFED_NODE_HASH" "$RELAY_HASH" \
    > "$REG_LOG" 2>&1
REG_STATUS=$?

cat "$REG_LOG"
if [ $REG_STATUS -ne 0 ]; then
    red "[Stage 2] FAIL: registration script exited $REG_STATUS"
    exit 1
fi
green "[Stage 2] PASS: relay hash registered with rfed"

# ── Stage 3: start relay listener ────────────────────────────────────────────
echo ""
yellow "[Stage 3] Starting relay listener..."

# SUB_HASH already computed in Stage 0 (identity hash, not destination hash)
yellow "[Stage 3] subscriber identity hash = $SUB_HASH"

RELAY_LOG="/tmp/rfed_notify_relay_$$.log"
$PYTHON rfed_notify_relay.py "$RFED_NODE_HASH" "$SUB_HASH" --timeout "$RELAY_TIMEOUT" \
    > "$RELAY_LOG" 2>&1 &
RELAY_PID=$!
PIDS_TO_KILL+=($RELAY_PID)
yellow "[Stage 3] relay PID = $RELAY_PID"

# Give relay time to start and announce
yellow "[Stage 3] Waiting ${SEND_DELAY}s for relay to announce..."
sleep "$SEND_DELAY"

if ! kill -0 "$RELAY_PID" 2>/dev/null; then
    red "[Stage 3] FAIL: relay process died before we could send"
    cat "$RELAY_LOG"
    exit 1
fi
green "[Stage 3] PASS: relay is listening"

# ── Stage 4: send LXMF propagation batch ────────────────────────────────────
echo ""
yellow "[Stage 4] Sending LXMF propagation batch..."
yellow "[Stage 4]   lxmf.propagation hash = $LXMF_PROP_HASH"
yellow "[Stage 4]   subscriber hash       = $SUB_HASH"

SEND_LOG="/tmp/rfed_lxmf_prop_sender_$$.log"
$PYTHON lxmf_prop_sender.py "$RFED_DATA_DIR/identity" "$SUB_HASH" \
    > "$SEND_LOG" 2>&1
SEND_STATUS=$?

cat "$SEND_LOG"
if [ $SEND_STATUS -ne 0 ]; then
    red "[Stage 4] FAIL: lxmf_prop_sender exited $SEND_STATUS"
    exit 1
fi
green "[Stage 4] PASS: propagation batch sent"

# ── Stage 5: wait for relay to receive wake packet ───────────────────────────
echo ""
yellow "[Stage 5] Waiting up to ${RELAY_TIMEOUT}s for relay to receive wake packet..."

wait "$RELAY_PID"
RELAY_STATUS=$?

echo "--- relay log ---"
cat "$RELAY_LOG"
echo "-----------------"

if [ $RELAY_STATUS -ne 0 ]; then
    red "[Stage 5] FAIL: relay exited $RELAY_STATUS (expected 0)"
    exit 1
fi
green "[Stage 5] PASS: relay received wake packet and exited 0"

echo ""
green "============================================"
green "  ALL STAGES PASSED — test_prop_notify PASS"
green "============================================"
exit 0
