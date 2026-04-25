#!/usr/bin/env python3
"""
rfed_sync_subscriber.py — Subscribe on Node B and wait for a synced blob.

Used by Scenario 5 (internode sync):
  - Connects to Node B (port 4245).
  - Subscribes to a channel on Node B (pull-only — blob arrives via sync, not fanout).
  - After a delay, PULLs from Node B's delivery destination.
  - Exits 0 if the expected blob is found, 1 otherwise.

Usage:
    rfed_sync_subscriber.py <node_b_hash_hex> <channel_name> <expected_blob> [--timeout N]
"""
import os, sys, time, threading
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)
from channel_hash import compute_channel_hash, channel_decrypt, ensure_config_dir, sandbox_path

import RNS
import msgpack

# ── Args ─────────────────────────────────────────────────────────────────────

if len(sys.argv) < 4:
    print("Usage: rfed_sync_subscriber.py <node_b_hash> <channel_name> <expected_blob> [--timeout N]")
    sys.exit(1)

node_b_hash_hex = sys.argv[1].strip()
channel_name    = sys.argv[2]
expected_blob   = sys.argv[3].encode()
WAIT_TIMEOUT    = 60

for i, a in enumerate(sys.argv):
    if a == "--timeout" and i + 1 < len(sys.argv):
        WAIT_TIMEOUT = int(sys.argv[i + 1])

# ── Config ───────────────────────────────────────────────────────────────────

TEST_NS          = os.environ.get("RFED_TEST_NAMESPACE", "default")
RNS_CONFIG_DIR   = ensure_config_dir(f"rns_sub_node_b_{TEST_NS}", template="rns_sub_node_b")
IDENTITY_FILE    = os.path.join(RNS_CONFIG_DIR, "sub_identity")
DATA_B_DIR       = sandbox_path("rfed_data_b")

# ── Boot RNS ─────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR, loglevel=RNS.LOG_DEBUG)
print(f"[sub-b] RNS ready, connecting to Node B", flush=True)

# ── Identity ─────────────────────────────────────────────────────────────────

if os.path.exists(IDENTITY_FILE):
    my_identity = RNS.Identity(create_keys=False)
    my_identity.load_private_key(open(IDENTITY_FILE, "rb").read())
    print(f"[sub-b] loaded existing identity", flush=True)
else:
    my_identity = RNS.Identity()
    with open(IDENTITY_FILE, "wb") as f:
        f.write(my_identity.get_private_key())
    print(f"[sub-b] created new identity", flush=True)

print(f"[sub-b] identity hash: {my_identity.hash.hex()}", flush=True)

# ── Discover Node B destinations via path request ────────────────────────────

node_b_hash = bytes.fromhex(node_b_hash_hex)

path_events = {"channel": threading.Event(), "delivery": threading.Event()}
channel_dest_hash  = [None]
delivery_dest_hash = [None]

class AnnounceHandler:
    aspect_filter = None
    def received_announce(self, destination_hash, announced_identity, app_data):
        h = destination_hash.hex()
        if h == channel_dest_hash[0]:
            path_events["channel"].set()
        if h == delivery_dest_hash[0]:
            path_events["delivery"].set()

RNS.Transport.register_announce_handler(AnnounceHandler())

# Read Node B's hashes from rfed_data_b
hashes_env = os.path.join(DATA_B_DIR, "hashes.env")
b_hashes = {}
if os.path.exists(hashes_env):
    with open(hashes_env) as f:
        for line in f:
            k, _, v = line.strip().partition("=")
            b_hashes[k] = v

rfed_b_channel_hash  = b_hashes.get("RFED_CHANNEL_HASH")
rfed_b_delivery_hash = b_hashes.get("RFED_DELIVERY_HASH")

if not rfed_b_channel_hash or not rfed_b_delivery_hash:
    print(f"[sub-b] ERROR: rfed_data_b/hashes.env missing or incomplete", flush=True)
    sys.exit(1)

channel_dest_hash[0]  = rfed_b_channel_hash
delivery_dest_hash[0] = rfed_b_delivery_hash

print(f"[sub-b] requesting paths to Node B destinations...", flush=True)
RNS.Transport.request_path(bytes.fromhex(rfed_b_channel_hash))
RNS.Transport.request_path(bytes.fromhex(rfed_b_delivery_hash))

deadline = time.time() + 30
while time.time() < deadline:
    if (RNS.Transport.has_path(bytes.fromhex(rfed_b_channel_hash)) and
            RNS.Transport.has_path(bytes.fromhex(rfed_b_delivery_hash))):
        break
    time.sleep(0.5)

if not RNS.Transport.has_path(bytes.fromhex(rfed_b_channel_hash)):
    print(f"[sub-b] ERROR: no path to Node B channel dest", flush=True)
    sys.exit(1)

print(f"[sub-b] Node B channel:  {rfed_b_channel_hash}", flush=True)
print(f"[sub-b] Node B delivery: {rfed_b_delivery_hash}", flush=True)

# ── Subscribe on Node B ───────────────────────────────────────────────────────

channel_hash = compute_channel_hash(channel_name)
print(f"[sub-b] subscribing to '{channel_name}' ({channel_hash.hex()})...", flush=True)

channel_dest_id = RNS.Identity.recall(bytes.fromhex(rfed_b_channel_hash))
if channel_dest_id is None:
    print(f"[sub-b] ERROR: no identity for Node B channel dest", flush=True)
    sys.exit(1)
channel_dest = RNS.Destination(
    channel_dest_id,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "rfed", "channel"
)

link_active = threading.Event()
link = RNS.Link(channel_dest)
link.set_link_established_callback(lambda l: link_active.set())
link_active.wait(timeout=15)
if link.status != RNS.Link.ACTIVE:
    print(f"[sub-b] ERROR: channel link to Node B did not activate", flush=True)
    sys.exit(1)

link.identify(my_identity)
time.sleep(0.3)

sub_resp_event = threading.Event()
sub_result = [None]

def sub_response_cb(request_receipt):
    raw = request_receipt.response
    if isinstance(raw, bool):
        sub_result[0] = raw
    else:
        try:
            sub_result[0] = msgpack.unpackb(raw, raw=False) if raw else None
        except Exception:
            sub_result[0] = raw
    print(f"[sub-b] subscribe response: {sub_result[0]}", flush=True)
    sub_resp_event.set()

link.request(
    "/rfed/subscribe",
    msgpack.packb(channel_hash, use_bin_type=True),
    response_callback=sub_response_cb,
    failed_callback=lambda r: sub_resp_event.set(),
    timeout=10,
)
sub_resp_event.wait(timeout=15)
link.teardown()

# ── Wait for sync to deliver the blob to Node B ──────────────────────────────

print(f"[sub-b] waiting {WAIT_TIMEOUT}s for sync to propagate blob to Node B...", flush=True)
time.sleep(WAIT_TIMEOUT)

# ── PULL from Node B delivery ─────────────────────────────────────────────────

print(f"[sub-b] pulling from Node B delivery...", flush=True)

# Discover the delivery identity via path request + announce.
delivery_ident = RNS.Identity.recall(bytes.fromhex(rfed_b_delivery_hash))
if delivery_ident is None:
    RNS.Transport.request_path(bytes.fromhex(rfed_b_delivery_hash))
    deadline_d = time.time() + 30
    while time.time() < deadline_d:
        delivery_ident = RNS.Identity.recall(bytes.fromhex(rfed_b_delivery_hash))
        if delivery_ident:
            break
        time.sleep(0.5)

if delivery_ident is None:
    # Last resort: re-request node path; the node announce carries the delivery identity.
    RNS.Transport.request_path(bytes.fromhex(b_hashes.get("RFED_NODE_HASH", "")))
    time.sleep(5)
    delivery_ident = RNS.Identity.recall(bytes.fromhex(rfed_b_delivery_hash))

if delivery_ident is None:
    print(f"[sub-b] ERROR: could not discover Node B delivery identity", flush=True)
    sys.exit(1)

delivery_dest = RNS.Destination(
    delivery_ident,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "rfed", "delivery"
)

dl_link_active = threading.Event()
dl_link = RNS.Link(delivery_dest)
dl_link.set_link_established_callback(lambda l: dl_link_active.set())
dl_link_active.wait(timeout=15)
if dl_link.status != RNS.Link.ACTIVE:
    print(f"[sub-b] ERROR: delivery link to Node B did not activate", flush=True)
    sys.exit(1)

dl_link.identify(my_identity)
time.sleep(0.3)

pull_resp_event = threading.Event()
pull_result = [None]

def pull_response_cb(request_receipt):
    pull_result[0] = request_receipt.response
    pull_resp_event.set()

dl_link.request(
    "/rfed/pull",
    b"",
    response_callback=pull_response_cb,
    failed_callback=lambda r: pull_resp_event.set(),
)
pull_resp_event.wait(timeout=30)
dl_link.teardown()

raw = pull_result[0]
if not raw:
    print(f"[sub-b] PULL returned empty response", flush=True)
    sys.exit(1)

try:
    if isinstance(raw, list):
        pairs = raw
    else:
        pairs = msgpack.unpackb(raw, raw=True)
except Exception as e:
    print(f"[sub-b] PULL decode error: {e}", flush=True)
    sys.exit(1)

if not pairs:
    print(f"[sub-b] PULL returned 0 blob(s)", flush=True)
    sys.exit(1)

print(f"[sub-b] PULL returned {len(pairs)} blob(s) ✓", flush=True)
found = False
for i, pair in enumerate(pairs):
    ch_h, blob = pair[0], pair[1]
    if isinstance(ch_h, (bytes, bytearray)):
        ch_str = ch_h.hex()
    else:
        ch_str = str(ch_h)
    try:
        decrypted = channel_decrypt(channel_name, blob)
    except Exception:
        decrypted = blob
    print(f"[sub-b]   pull[{i}] channel={ch_str} decrypted={decrypted!r}", flush=True)
    if decrypted == expected_blob:
        found = True

if found:
    print(f"[sub-b] PASS: synced blob received on Node B ✓", flush=True)
    sys.exit(0)
else:
    print(f"[sub-b] FAIL: expected blob {expected_blob!r} not found in PULL results", flush=True)
    sys.exit(1)
