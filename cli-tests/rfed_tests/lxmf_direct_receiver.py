#!/usr/bin/env python3
"""
lxmf_direct_receiver.py — Wait for a direct LXMF message using the rns_subscriber identity.
Announces continuously so the sender can discover the path.

Usage:
    python3 lxmf_direct_receiver.py [--timeout N]
"""
import os, sys, time, signal
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
LXMF_DIR = os.path.join(os.path.dirname(os.path.dirname(TEST_DIR)), "LXMF-master")
if os.path.isdir(LXMF_DIR):
    sys.path.insert(0, LXMF_DIR)

import RNS
import LXMF

RNS_CONFIG_DIR = os.path.join(TEST_DIR, "rns_subscriber")
IDENTITY_FILE  = os.path.join(RNS_CONFIG_DIR, "sub_identity")
STORAGE_DIR    = "/tmp/lxmf_direct_rx_storage"

TIMEOUT = 300  # seconds to wait
for i, a in enumerate(sys.argv):
    if a == "--timeout" and i + 1 < len(sys.argv):
        TIMEOUT = int(sys.argv[i + 1])

received = []

def delivery_callback(message):
    print(f"\n{'='*60}")
    print(f"[RX] MESSAGE RECEIVED!")
    print(f"[RX] From    : {RNS.prettyhexrep(message.source_hash)}")
    print(f"[RX] To      : {RNS.prettyhexrep(message.destination_hash)}")
    print(f"[RX] Title   : {message.title_as_string()!r}")
    print(f"[RX] Content : {message.content_as_string()!r}")
    fields = message.get_fields() or {}
    if fields:
        print(f"[RX] Fields  : {list(fields.keys())}")
    print(f"{'='*60}\n")
    received.append(message)

os.makedirs(STORAGE_DIR, exist_ok=True)

print("[rx] starting RNS...", flush=True)
RNS.Reticulum(configdir=RNS_CONFIG_DIR, loglevel=RNS.LOG_WARNING)

print("[rx] loading identity...", flush=True)
identity = RNS.Identity.from_file(IDENTITY_FILE)
print(f"[rx] identity hash : {identity.hash.hex()}", flush=True)

print("[rx] starting LXMF router...", flush=True)
router = LXMF.LXMRouter(storagepath=STORAGE_DIR, enforce_stamps=False)

dest = router.register_delivery_identity(identity, display_name="RfedTestReceiver", stamp_cost=None)
dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
print(f"[rx] LXMF delivery dest : {dest.hash.hex()}", flush=True)

router.register_delivery_callback(delivery_callback)

print(f"[rx] announcing — waiting up to {TIMEOUT}s for messages...", flush=True)
print(f"[rx] send to hash: {dest.hash.hex()}", flush=True)

last_announce = 0.0
deadline = time.time() + TIMEOUT

def handle_sigint(sig, frame):
    print("\n[rx] interrupted", flush=True)
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

while time.time() < deadline:
    now = time.time()
    if now - last_announce >= 10:
        router.announce(dest.hash)
        last_announce = now
    if received:
        print(f"[rx] {len(received)} message(s) received so far, continuing to wait...", flush=True)
    time.sleep(1)

if received:
    print(f"\n[rx] done — received {len(received)} message(s) total", flush=True)
else:
    print("\n[rx] timeout — no messages received", flush=True)
