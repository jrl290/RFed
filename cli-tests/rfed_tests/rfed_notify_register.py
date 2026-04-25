#!/usr/bin/env python3
"""
rfed_notify_register.py — Register a notify relay with an rfed node.

Usage:
    rfed_notify_register.py <rfed_node_hash_hex> <relay_hash_hex>

Reads the relay hash from rfed_data/notify_relay_hash.txt if <relay_hash_hex>
is the special token "auto".

The CALLER identity is the subscriber — rfed uses it to key the registration.
Uses the same persistent identity file as rfed_subscriber.py.
"""
import os, sys, time, threading
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)
from channel_hash import AnnounceHandler, ensure_config_dir, load_hashes, sandbox_path

import RNS
import msgpack

TEST_NS         = os.environ.get("RFED_TEST_NAMESPACE", "default")
RNS_CONFIG_DIR  = ensure_config_dir(f"rns_subscriber_{TEST_NS}", template="rns_subscriber")
IDENTITY_FILE   = os.path.join(RNS_CONFIG_DIR, "sub_identity")
RELAY_HASH_FILE = sandbox_path("rfed_data", "notify_relay_hash.txt")
PATH_TIMEOUT    = 180   # rfed announces every 60s; allow 3 cycles as buffer

if len(sys.argv) < 3:
    print("Usage: rfed_notify_register.py <rfed_node_hash_hex> <relay_hash_hex|auto>")
    sys.exit(1)

rfed_node_hash = bytes.fromhex(sys.argv[1].strip())
relay_hash_arg = sys.argv[2].strip()

if relay_hash_arg == "auto":
    with open(RELAY_HASH_FILE) as f:
        relay_hash_hex = f.read().strip()
else:
    relay_hash_hex = relay_hash_arg

if len(relay_hash_hex) != 32 or not all(c in "0123456789abcdefABCDEF" for c in relay_hash_hex):
    print(f"[reg] ERROR: relay_hash must be 32 hex chars, got {relay_hash_hex!r}")
    sys.exit(1)

print(f"[reg] registering relay {relay_hash_hex} with rfed...", flush=True)

# ── Boot RNS ─────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR)

hash_env            = load_hashes()
rfed_notify_hash_env = hash_env.get("RFED_NOTIFY_HASH")
rfed_node_hash_env  = hash_env.get("RFED_NODE_HASH") or rfed_node_hash

# Load subscriber identity (same as rfed_subscriber.py so hashes match).
if os.path.exists(IDENTITY_FILE):
    my_identity = RNS.Identity(create_keys=False)
    my_identity.load_private_key(open(IDENTITY_FILE, "rb").read())
    print(f"[reg] loaded existing subscriber identity {my_identity.hash.hex()}", flush=True)
else:
    my_identity = RNS.Identity()
    with open(IDENTITY_FILE, "wb") as f:
        f.write(my_identity.get_private_key())
    print(f"[reg] created new identity", flush=True)

# ── Find rfed.notify ─────────────────────────────────────────────────────────

notify_dest_ref = [None]
node_identity_ref = [None]
notify_found = threading.Event()

RFED_NOTIFY_HASH_BYTES = rfed_notify_hash_env if isinstance(rfed_notify_hash_env, bytes) else bytes.fromhex(rfed_notify_hash_env) if rfed_notify_hash_env else None
_node_hash_str = hash_env.get("RFED_NODE_HASH")
RFED_NODE_HASH_BYTES   = _node_hash_str if isinstance(_node_hash_str, bytes) else bytes.fromhex(_node_hash_str) if _node_hash_str else rfed_node_hash

def on_any_announce(dest_hash, announced_identity, app_data, ann_hash, is_path):
    """Single handler with aspect_filter=None to bypass the broken
    hash_from_name_and_identity(aspect, None) filter in Python RNS."""
    if announced_identity is None:
        return
    if RFED_NOTIFY_HASH_BYTES and dest_hash == RFED_NOTIFY_HASH_BYTES:
        if notify_dest_ref[0] is None:
            try:
                dest = RNS.Destination(
                    announced_identity, RNS.Destination.OUT,
                    RNS.Destination.SINGLE, "rfed", "notify"
                )
                notify_dest_ref[0] = dest
                notify_found.set()
            except Exception as e:
                print(f"[reg] notify announce error: {e}", flush=True)
    elif RFED_NODE_HASH_BYTES and dest_hash == RFED_NODE_HASH_BYTES:
        if node_identity_ref[0] is None:
            node_identity_ref[0] = announced_identity
            notify_found.set()

RNS.Transport.register_announce_handler(
    AnnounceHandler(aspect_filter=None, callback=on_any_announce,
                    receive_path_responses=True)
)

print("[reg] requesting paths to rfed destinations...", flush=True)
for h in filter(None, [rfed_notify_hash_env, rfed_node_hash_env]):
    RNS.Transport.request_path(h)

# Keep re-requesting every 20s so we don't rely solely on a single request_path.
import threading as _threading
def _path_retry():
    start = time.time()
    while not notify_found.is_set():
        time.sleep(20)
        if notify_found.is_set():
            break
        elapsed = time.time() - start
        print(f"[reg] [{elapsed:.0f}s] re-requesting path...", flush=True)
        for h in filter(None, [rfed_notify_hash_env, rfed_node_hash_env]):
            RNS.Transport.request_path(h)
_t = _threading.Thread(target=_path_retry, daemon=True)
_t.start()

notify_found.wait(timeout=PATH_TIMEOUT)

if notify_dest_ref[0] is None:
    if node_identity_ref[0] is not None:
        notify_dest_ref[0] = RNS.Destination(
            node_identity_ref[0], RNS.Destination.OUT,
            RNS.Destination.SINGLE, "rfed", "notify"
        )
        print("[reg] constructed rfed.notify from node path-response identity", flush=True)
    else:
        for h in filter(None, [rfed_notify_hash_env, rfed_node_hash_env, rfed_node_hash]):
            rfed_identity = RNS.Identity.recall(h)
            if rfed_identity:
                notify_dest_ref[0] = RNS.Destination(
                    rfed_identity, RNS.Destination.OUT,
                    RNS.Destination.SINGLE, "rfed", "notify"
                )
                print("[reg] using Identity.recall fallback for rfed.notify", flush=True)
                break
        if notify_dest_ref[0] is None:
            print("[reg] ERROR: cannot find rfed identity after timeout", flush=True)
            sys.exit(1)

notify_dest = notify_dest_ref[0]
print(f"[reg] rfed.notify: {notify_dest.hash.hex()}", flush=True)

# ── Ensure we have a live path before opening the link ───────────────────────
if not RNS.Transport.has_path(notify_dest.hash):
    print("[reg] no path cached — requesting path and waiting...", flush=True)
    RNS.Transport.request_path(notify_dest.hash)
    path_wait_start = time.time()
    while not RNS.Transport.has_path(notify_dest.hash):
        elapsed = time.time() - path_wait_start
        if elapsed > PATH_TIMEOUT:
            print("[reg] ERROR: could not discover path to rfed.notify", flush=True)
            sys.exit(1)
        # Re-request every 20s in case the first request was dropped
        if elapsed > 0 and int(elapsed) % 20 == 0 and int(elapsed * 5) % 5 == 0:
            print(f"[reg] [{elapsed:.0f}s] re-requesting path...", flush=True)
            RNS.Transport.request_path(notify_dest.hash)
        time.sleep(0.2)
    print("[reg] path acquired", flush=True)

# ── Open link using subscriber identity and send REGISTER request ─────────────

link = RNS.Link(notify_dest)

link_active = threading.Event()
link.set_link_established_callback(lambda l: link_active.set())
link_active.wait(timeout=15)

if link.status != RNS.Link.ACTIVE:
    print("[reg] ERROR: link to rfed.notify did not activate", flush=True)
    sys.exit(1)

link.identify(my_identity)
time.sleep(0.3)
print(f"[reg] identified on link as {my_identity.hash.hex()}", flush=True)

reg_done   = threading.Event()
reg_result = [None]

def on_reg_response(receipt):
    resp = receipt.response
    if isinstance(resp, bool):
        # Python RNS already decoded the msgpack bool for us
        reg_result[0] = resp
    elif resp:
        try:
            reg_result[0] = msgpack.unpackb(resp)
        except Exception:
            reg_result[0] = None
    else:
        reg_result[0] = None
    reg_done.set()

def on_reg_failed(receipt):
    reg_result[0] = False
    reg_done.set()

link.request(
    "/rfed/notify/register",
    msgpack.packb(relay_hash_hex, use_bin_type=True),
    response_callback=on_reg_response,
    failed_callback=on_reg_failed,
    timeout=10,
)

reg_done.wait(timeout=12)
link.teardown()

if reg_result[0] is not False and reg_result[0] is not None:
    print(f"[reg] notify relay registered ✓  result={reg_result[0]}", flush=True)
    sys.exit(0)
else:
    print(f"[reg] notify relay registration FAILED  result={reg_result[0]}", flush=True)
    sys.exit(1)
