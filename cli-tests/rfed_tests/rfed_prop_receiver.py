#!/usr/bin/env python3
"""
rfed_prop_receiver.py — Self-contained receiver for the LXMF propagation notify scenario.

This script:
  1. Creates (or loads) a persistent identity in rns_prop_receiver/prop_receiver_identity.
  2. Creates an inbound rfed.notify destination with that identity (the relay endpoint).
  3. Saves the identity hash to rfed_data/prop_receiver_hash.txt so the sender knows
     what hash to embed in the LXMF payload.
  4. Registers itself with rfed's rfed.notify destination:
       subscriber = own identity
       relay_hash = own rfed.notify dest hash
  5. Prints "REGISTERED" once registration is confirmed, then listens for wake packets.
  6. Exits 0 and prints "PASS" when a wake packet arrives within --timeout seconds.

Usage:
    rfed_prop_receiver.py <rfed_node_hash_hex> [--timeout N]
"""
import os, sys, time, threading
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)
from channel_hash import AnnounceHandler, ensure_config_dir, load_hashes, sandbox_path

import RNS
import msgpack

# ── Config ────────────────────────────────────────────────────────────────────

TEST_NS           = os.environ.get("RFED_TEST_NAMESPACE", "default")
RNS_CONFIG_DIR    = ensure_config_dir(f"rns_prop_receiver_{TEST_NS}", template="rns_prop_receiver")
IDENTITY_FILE     = os.path.join(RNS_CONFIG_DIR, "prop_receiver_identity")
HASH_OUTPUT_FILE  = sandbox_path("rfed_data", "prop_receiver_hash.txt")
PATH_TIMEOUT      = 30
LINK_TIMEOUT      = 15
TIMEOUT           = 60

if len(sys.argv) < 2:
    print("Usage: rfed_prop_receiver.py <rfed_node_hash_hex> [--timeout N] [--rns-config DIR]")
    sys.exit(1)

for i, a in enumerate(sys.argv):
    if a == "--timeout" and i + 1 < len(sys.argv):
        TIMEOUT = int(sys.argv[i + 1])
    elif a == "--rns-config" and i + 1 < len(sys.argv):
        RNS_CONFIG_DIR = sys.argv[i + 1]
        IDENTITY_FILE  = os.path.join(RNS_CONFIG_DIR, "prop_receiver_identity")

rfed_node_hash_arg = sys.argv[1].strip()

# ── Boot RNS ──────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR)
print("[recv] RNS ready", flush=True)

hash_env             = load_hashes()
# load_hashes() returns bytes values; rfed_node_hash_arg is a hex string.
_notify_from_env     = hash_env.get("RFED_NOTIFY_HASH")    # bytes or None
_node_from_env       = hash_env.get("RFED_NODE_HASH")      # bytes or None
rfed_notify_hash_env = _notify_from_env                    # bytes or None
rfed_node_hash_env   = _node_from_env if _node_from_env is not None else bytes.fromhex(rfed_node_hash_arg)

# ── Load or create a persistent receiver identity ─────────────────────────────

os.makedirs(RNS_CONFIG_DIR, exist_ok=True)
if os.path.exists(IDENTITY_FILE):
    my_identity = RNS.Identity(create_keys=False)
    my_identity.load_private_key(open(IDENTITY_FILE, "rb").read())
    print(f"[recv] loaded existing identity {my_identity.hash.hex()}", flush=True)
else:
    my_identity = RNS.Identity()
    with open(IDENTITY_FILE, "wb") as f:
        f.write(my_identity.get_private_key())
    print(f"[recv] created new identity {my_identity.hash.hex()}", flush=True)

# ── Create inbound rfed.notify destination (the relay endpoint) ───────────────

wake_event    = threading.Event()
wake_received = []

relay_dest = RNS.Destination(
    my_identity, RNS.Destination.IN,
    RNS.Destination.SINGLE, "rfed", "notify"
)

def on_wake_packet(data, packet):
    """Called when rfed sends a wake-up DATA packet to our rfed.notify dest."""
    try:
        payload  = msgpack.unpackb(data, raw=False)
        receiver = payload.get("receiver") or payload.get(b"receiver")
        if receiver is None:
            print(f"[recv] no 'receiver' key in wake payload: {payload!r}", flush=True)
            return
        if isinstance(receiver, memoryview):
            receiver = bytes(receiver)
        print(f"[recv] *** WAKE PACKET *** receiver={receiver.hex()}", flush=True)
        wake_received.append(receiver)
        wake_event.set()
    except Exception as e:
        print(f"[recv] decode error: {e}  raw={data.hex()}", flush=True)

relay_dest.set_packet_callback(on_wake_packet)

# Announce so rfed can route wake packets back to us.
relay_dest.announce()
relay_hash_hex = relay_dest.hash.hex()
print(f"[recv] rfed.notify relay dest: {relay_hash_hex}", flush=True)

# ── Save hashes for the sender ───────────────────────────────────────────────
# rfed stores messages keyed by lxmf_data[0:16], and /get filters by the
# lxmf.delivery destination hash derived from the identifying identity.
# We write that delivery hash so the sender can put it in bytes 0-15.
# (We still also write the identity hash for diagnostic reference.)

lxmf_delivery_dest = RNS.Destination(
    my_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "lxmf", "delivery"
)
DELIVERY_HASH_OUTPUT_FILE = sandbox_path("rfed_data", "prop_receiver_delivery_hash.txt")

os.makedirs(os.path.dirname(HASH_OUTPUT_FILE), exist_ok=True)
with open(HASH_OUTPUT_FILE, "w") as f:
    f.write(my_identity.hash.hex())
with open(DELIVERY_HASH_OUTPUT_FILE, "w") as f:
    f.write(lxmf_delivery_dest.hash.hex())
print(f"[recv] identity hash:       {my_identity.hash.hex()}", flush=True)
print(f"[recv] lxmf.delivery hash:  {lxmf_delivery_dest.hash.hex()}", flush=True)

# ── Load rfed identity and construct rfed.notify destination ──────────────────
# Load rfed's identity from rfed_data/identity and inject a synthetic path.
# This works whether clients connect to rfed directly (port 4244) or through
# a shared rnsd hub (port 4242) — no announce or path-request round trip needed.
# Use the sandbox path so sandbox runs pick up the correct per-run identity.
RFED_IDENTITY_FILE = sandbox_path("rfed_data", "identity")
if not os.path.exists(RFED_IDENTITY_FILE):
    print(f"[recv] ERROR: rfed identity not found at {RFED_IDENTITY_FILE}")
    sys.exit(1)

rfed_identity = RNS.Identity.from_file(RFED_IDENTITY_FILE)
if rfed_identity is None:
    print("[recv] ERROR: could not load rfed identity")
    sys.exit(1)

notify_dest = RNS.Destination(
    rfed_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "rfed", "notify"
)
print(f"[recv] rfed.notify dest: {notify_dest.hash.hex()}", flush=True)

# Inject a direct path so RNS.Link can route without waiting for path discovery.
tcp_iface = None
for iface in RNS.Transport.interfaces:
    if hasattr(iface, 'target_ip'):
        tcp_iface = iface
        break

if tcp_iface is None:
    print("[recv] FAIL: no TCP interface found")
    sys.exit(1)

_now = time.time()
RNS.Transport.path_table[notify_dest.hash] = [
    _now,               # timestamp
    notify_dest.hash,   # next hop (direct — destination itself)
    1,                  # hops
    _now + 86400,       # expires
    [],                 # randblobs
    tcp_iface,          # received-on interface
    None,               # packet
]
print(f"[recv] injected direct path for rfed.notify via {tcp_iface}", flush=True)

# ── Open link and register ────────────────────────────────────────────────────

link = RNS.Link(notify_dest)
link_active = threading.Event()
link.set_link_established_callback(lambda l: link_active.set())
link_active.wait(timeout=LINK_TIMEOUT)

if link.status != RNS.Link.ACTIVE:
    print("[recv] ERROR: link to rfed.notify did not activate", flush=True)
    sys.exit(1)

link.identify(my_identity)
time.sleep(0.3)
print(f"[recv] identified on link as {my_identity.hash.hex()}", flush=True)

reg_done   = threading.Event()
reg_result = [None]

def on_reg_response(receipt):
    resp = receipt.response
    if isinstance(resp, bool):
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

if reg_result[0] is False or reg_result[0] is None:
    print(f"[recv] FAIL: registration rejected by rfed (result={reg_result[0]})", flush=True)
    sys.exit(1)

print(f"[recv] REGISTERED with rfed.notify ✓  relay={relay_hash_hex}", flush=True)

# ── Wait for wake packet ──────────────────────────────────────────────────────

print(f"[recv] waiting up to {TIMEOUT}s for LXMF propagation wake packet...", flush=True)
wake_event.wait(timeout=TIMEOUT)

if not wake_received:
    print("[recv] FAIL: no wake packet received within timeout", flush=True)
    sys.exit(1)

print(f"[recv] PASS: wake packet received for subscriber {wake_received[0].hex()} ✓", flush=True)

# ── Retrieve messages via /get on lxmf.propagation ───────────────────────────
# Standard two-phase protocol (matches Python lxmd and rfed):
#   Phase 1: request [None, None]  → node returns [transient_id, ...]
#   Phase 2: request [wants, [], None]  → node returns [lxmf_data_bytes, ...]
# The link must stay open between both requests.

print(f"[recv] retrieving messages from lxmf.propagation...", flush=True)

prop_dest = RNS.Destination(
    rfed_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "lxmf", "propagation"
)

_now2 = time.time()
RNS.Transport.path_table[prop_dest.hash] = [
    _now2, prop_dest.hash, 1, _now2 + 86400, [], tcp_iface, None
]
print(f"[recv] lxmf.propagation dest: {prop_dest.hash.hex()}", flush=True)

prop_link_ready = threading.Event()
prop_link_ref   = [None]

def on_prop_link(lnk):
    prop_link_ref[0] = lnk
    prop_link_ready.set()

prop_link = RNS.Link(prop_dest)
prop_link.set_link_established_callback(on_prop_link)
prop_link_ready.wait(timeout=LINK_TIMEOUT)

if not prop_link_ready.is_set() or prop_link_ref[0] is None:
    print("[recv] FAIL: could not open link to lxmf.propagation", flush=True)
    sys.exit(1)

lnk = prop_link_ref[0]
lnk.identify(my_identity)
time.sleep(0.4)  # give rfed time to process identify

# ── Phase 1: list available transient IDs ────────────────────────────────────

list_done     = threading.Event()
list_response = [None]

def on_list_response(receipt):
    list_response[0] = receipt.response
    list_done.set()

def on_list_failed(receipt):
    print("[recv] /get phase-1 (list) failed", flush=True)
    list_done.set()

lnk.request(
    "/get",
    data=msgpack.packb([None, None], use_bin_type=True),
    response_callback=on_list_response,
    failed_callback=on_list_failed,
    timeout=20,
)
list_done.wait(timeout=25)

transient_ids = list_response[0]
if transient_ids is None:
    print("[recv] FAIL: /get phase-1 returned no response", flush=True)
    lnk.teardown()
    sys.exit(1)

if not isinstance(transient_ids, list):
    print(f"[recv] FAIL: /get phase-1 unexpected type {type(transient_ids)}: {transient_ids!r}", flush=True)
    lnk.teardown()
    sys.exit(1)

print(f"[recv] /get phase-1: {len(transient_ids)} message(s) available", flush=True)
for i, tid in enumerate(transient_ids):
    b = bytes(tid) if isinstance(tid, (bytes, memoryview)) else tid
    print(f"  [{i}] transient_id={b.hex() if isinstance(b, bytes) else b!r}", flush=True)

if len(transient_ids) == 0:
    print("[recv] WARN: /get phase-1 returned empty list (0 messages available)", flush=True)
    lnk.teardown()
    sys.exit(0)

# ── Phase 2: fetch wanted messages ────────────────────────────────────────────

wants = [bytes(tid) if isinstance(tid, memoryview) else tid for tid in transient_ids]

get_done     = threading.Event()
get_response = [None]

def on_get_response(receipt):
    get_response[0] = receipt.response
    get_done.set()

def on_get_failed(receipt):
    print("[recv] /get phase-2 (fetch) failed", flush=True)
    get_done.set()

lnk.request(
    "/get",
    data=msgpack.packb([wants, [], None], use_bin_type=True),
    response_callback=on_get_response,
    failed_callback=on_get_failed,
    timeout=30,
)
get_done.wait(timeout=35)
lnk.teardown()

messages = get_response[0]
if messages is None:
    print("[recv] FAIL: /get phase-2 returned no response", flush=True)
    sys.exit(1)

if not isinstance(messages, list):
    print(f"[recv] FAIL: /get phase-2 unexpected type {type(messages)}: {messages!r}", flush=True)
    sys.exit(1)

print(f"[recv] /get phase-2: received {len(messages)} message(s)", flush=True)
for i, msg in enumerate(messages):
    b = bytes(msg) if isinstance(msg, memoryview) else msg
    if isinstance(b, bytes):
        dest_hash = b[:16].hex() if len(b) >= 16 else b.hex()
        print(f"  [{i}] dest_hash={dest_hash}  total_len={len(b)}", flush=True)
    else:
        print(f"  [{i}] {type(b)}: {b!r}", flush=True)

if len(messages) > 0:
    print("[recv] PASS: message retrieved from propagation node ✓", flush=True)
    sys.exit(0)
else:
    print("[recv] WARN: /get phase-2 returned 0 messages", flush=True)
    sys.exit(0)
