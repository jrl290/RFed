#!/usr/bin/env python3
"""rfed_notify_relay.py — Acts as an rfed.notify relay for rfed wake-up tests.

Usage:
    rfed_notify_relay.py <rfed_node_hash_hex> [subscriber_hash_hex] [--timeout N]

The relay:
  1. Creates an inbound rfed.notify destination (persistent identity) and announces it.
  2. Writes its hash to rfed_data/notify_relay_hash.txt for the test harness.
  3. Waits for wake packets from rfed.
  4. Decodes the msgpack Map payload and extracts the 'receiver' field.
  5. Exits (with code 0) if matching subscriber hash received within timeout.

The subscriber registers this relay with rfed via rfed_notify_register.py.
"""
import os, sys, time, threading
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)

from channel_hash import ensure_config_dir, sandbox_path

import RNS
import msgpack

# ── Config ───────────────────────────────────────────────────────────────────

TEST_NS           = os.environ.get("RFED_TEST_NAMESPACE", "default")
RNS_CONFIG_DIR    = ensure_config_dir(f"rns_notify_relay_{TEST_NS}", template="rns_notify_relay")
RELAY_IDENTITY_FILE = os.path.join(RNS_CONFIG_DIR, "relay_identity")
RELAY_HASH_FILE   = sandbox_path("rfed_data", "notify_relay_hash.txt")
TIMEOUT         = 60
EXPECTED_HASH   = None

if len(sys.argv) < 2:
    print("Usage: rfed_notify_relay.py <rfed_node_hash_hex> [subscriber_hash_hex] [--timeout N]")
    sys.exit(1)

for i, a in enumerate(sys.argv):
    if a == "--timeout" and i + 1 < len(sys.argv):
        TIMEOUT = int(sys.argv[i + 1])

# Optional: expected subscriber hash to match against (verify correct wakeup).
if len(sys.argv) > 2 and not sys.argv[2].startswith("--"):
    EXPECTED_HASH = bytes.fromhex(sys.argv[2].strip())

# ── Boot RNS ─────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR)
print("[relay] RNS ready", flush=True)

# ── Load or create a persistent relay identity ────────────────────────────────

os.makedirs(RNS_CONFIG_DIR, exist_ok=True)
if os.path.exists(RELAY_IDENTITY_FILE):
    relay_identity = RNS.Identity(create_keys=False)
    relay_identity.load_private_key(open(RELAY_IDENTITY_FILE, "rb").read())
    print(f"[relay] loaded existing relay identity {relay_identity.hash.hex()}", flush=True)
else:
    relay_identity = RNS.Identity()
    with open(RELAY_IDENTITY_FILE, "wb") as _f:
        _f.write(relay_identity.get_private_key())
    print(f"[relay] created new relay identity {relay_identity.hash.hex()}", flush=True)

# ── Create inbound rfed.notify destination ────────────────────────────────────

# rfed sends wake packets to destinations with app_name="rfed", aspect="notify".
# Using the same app+aspect as notify/rns.rs: Destination::new(..., "rfed", ["notify"])
relay_dest = RNS.Destination(
    relay_identity, RNS.Destination.IN,
    RNS.Destination.SINGLE, "rfed", "notify"
)

wake_event = threading.Event()
wake_received = []

def on_notify_packet(data, packet):
    """Called when rfed sends a wake-up DATA packet.

    rfed sends a msgpack Map: {"receiver": <16-byte subscriber hash>,
                               "sender":   <16-byte sender hash>,    (optional)
                               "channel":  <16-byte channel hash>}   (optional)
    Keys may be str or bytes depending on rmpv serialisation.
    """
    try:
        payload = msgpack.unpackb(data, raw=False)
        # Accept both str keys and bytes keys from rmpv
        receiver = payload.get("receiver") or payload.get(b"receiver")
        if receiver is None:
            print(f"[relay] no 'receiver' key in payload: {payload!r}  raw={data.hex()}", flush=True)
            return
        if isinstance(receiver, memoryview):
            receiver = bytes(receiver)
        print(f"[relay] *** WAKE PACKET *** receiver={receiver.hex()}", flush=True)
        wake_received.append(receiver)
        wake_event.set()
    except Exception as e:
        print(f"[relay] decode error: {e}  raw={data.hex()}", flush=True)

relay_dest.set_packet_callback(on_notify_packet)

# Announce so rfed can find this relay and route wake packets.
relay_dest.announce()
print(f"[relay] rfed.notify dest hash: {relay_dest.hash.hex()}", flush=True)

# Write hash so the test harness / subscriber script can register it.
os.makedirs(os.path.dirname(RELAY_HASH_FILE), exist_ok=True)
with open(RELAY_HASH_FILE, "w") as f:
    f.write(relay_dest.hash.hex())
print(f"[relay] hash written to {RELAY_HASH_FILE}", flush=True)

# ── Wait for wake packet ──────────────────────────────────────────────────────

print(f"[relay] waiting up to {TIMEOUT}s for a wake packet...", flush=True)
wake_event.wait(timeout=TIMEOUT)

if not wake_received:
    print("[relay] FAIL: no wake packet received within timeout", flush=True)
    sys.exit(1)

# Verify subscriber hash if expected.
if EXPECTED_HASH:
    matched = any(h == EXPECTED_HASH for h in wake_received)
    if matched:
        print(f"[relay] PASS: wake packet for correct subscriber ✓", flush=True)
        sys.exit(0)
    else:
        print(f"[relay] FAIL: got {[h.hex() for h in wake_received]}, expected {EXPECTED_HASH.hex()}", flush=True)
        sys.exit(1)

print(f"[relay] PASS: {len(wake_received)} wake packet(s) received ✓", flush=True)
sys.exit(0)
