#!/usr/bin/env python3
"""
rfed_backup_subscriber.py — Scenario 6: backup failover.

Steps:
  1.  Connect to PRIMARY node (port 4246), subscribe to channel (pull-only,
      so rfed will treat this subscriber as offline and queue for backup push).
  2.  Wait for `--pre-kill-wait` seconds (default 10s) — allows the primary's
      backup-push tick to fire and push the subscription entry to the backup node.
  3.  Script exits; caller (run_tests.sh) kills the primary.
  4.  Script is called again in a second invocation with --pull-from-backup:
      connect to BACKUP node (port 4247) and PULL.  Exits 0 + prints PASS
      if the expected blob is present.

Because run_tests.sh cannot easily re-invoke with different phases, the script
accepts a --phase argument:
  --phase register  : subscribe on primary then exit (phase 1)
  --phase pull      : pull from backup node then exit (phase 2 — after failover)

Usage:
    rfed_backup_subscriber.py <primary_hash> <backup_hash> <channel_name> <expected_blob> \\
        --phase (register|pull) [--timeout N]
"""
import os, sys, time, threading
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)
from channel_hash import compute_channel_hash, channel_decrypt, ensure_config_dir, sandbox_path

import RNS
import msgpack

# ── Args ──────────────────────────────────────────────────────────────────────

if len(sys.argv) < 5:
    print("Usage: rfed_backup_subscriber.py <primary_hash> <backup_hash> "
          "<channel_name> <expected_blob> --phase (register|pull) [--timeout N]")
    sys.exit(1)

primary_hash_hex = sys.argv[1].strip()
backup_hash_hex  = sys.argv[2].strip()
channel_name     = sys.argv[3]
expected_blob    = sys.argv[4].encode()
PHASE            = "register"
WAIT_TIMEOUT     = 60

for i, a in enumerate(sys.argv):
    if a == "--phase" and i + 1 < len(sys.argv):
        PHASE = sys.argv[i + 1]
    if a == "--timeout" and i + 1 < len(sys.argv):
        WAIT_TIMEOUT = int(sys.argv[i + 1])

if PHASE not in ("register", "pull"):
    print(f"[bk-sub] ERROR: unknown --phase '{PHASE}'")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────

# Register phase: connect directly to PRIMARY (port 4246) so path resolution
# for rfed.channel works without relying on announce rebroadcast from the
# backup transport node.
# Pull phase: connect to BACKUP (port 4247) to verify failover delivery.
if PHASE == "register":
    TEST_NS = os.environ.get("RFED_TEST_NAMESPACE", "default")
    RNS_CONFIG_DIR = ensure_config_dir(f"rns_backup_subscriber_register_{TEST_NS}", template="rns_backup_subscriber_register")
else:
    TEST_NS = os.environ.get("RFED_TEST_NAMESPACE", "default")
    RNS_CONFIG_DIR = ensure_config_dir(f"rns_backup_subscriber_{TEST_NS}", template="rns_backup_subscriber")
IDENTITY_DIR   = ensure_config_dir(f"rns_backup_subscriber_{TEST_NS}", template="rns_backup_subscriber")
IDENTITY_FILE  = os.path.join(IDENTITY_DIR, "sub_identity")

DATA_BP_DIR    = sandbox_path("rfed_data_backup_primary")
DATA_BN_DIR    = sandbox_path("rfed_data_backup_node")

# ── Boot RNS ──────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR, loglevel=RNS.LOG_DEBUG)
print(f"[bk-sub] RNS ready (phase={PHASE})", flush=True)

# ── Identity ──────────────────────────────────────────────────────────────────

if os.path.exists(IDENTITY_FILE):
    my_identity = RNS.Identity(create_keys=False)
    my_identity.load_private_key(open(IDENTITY_FILE, "rb").read())
    print(f"[bk-sub] loaded existing identity", flush=True)
else:
    my_identity = RNS.Identity()
    os.makedirs(RNS_CONFIG_DIR, exist_ok=True)
    with open(IDENTITY_FILE, "wb") as f:
        f.write(my_identity.get_private_key())
    print(f"[bk-sub] created new identity", flush=True)

print(f"[bk-sub] identity hash: {my_identity.hash.hex()}", flush=True)

# ── Load hashes from rfed data dirs ──────────────────────────────────────────

def load_hashes(data_dir):
    env = os.path.join(data_dir, "hashes.env")
    h = {}
    if os.path.exists(env):
        with open(env) as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                h[k] = v
    return h

bp_hashes = load_hashes(DATA_BP_DIR)
bn_hashes = load_hashes(DATA_BN_DIR)

# ─────────────────────────────────────────────────────────────────────────────
# PHASE: register
#   Connect to the PRIMARY's rfed.channel destination and subscribe.
#   The subscription is stored with pull-only semantics (no live path).
#   The primary will push this subscription entry to the backup node on the
#   next backup_push_tick (every backup_tick_secs seconds).
# ─────────────────────────────────────────────────────────────────────────────

if PHASE == "register":
    rfed_bp_channel_hash = bp_hashes.get("RFED_CHANNEL_HASH")
    if not rfed_bp_channel_hash:
        print("[bk-sub] ERROR: rfed_data_backup_primary/hashes.env missing RFED_CHANNEL_HASH")
        sys.exit(1)

    print(f"[bk-sub] requesting path to primary channel {rfed_bp_channel_hash}...", flush=True)
    RNS.Transport.request_path(bytes.fromhex(rfed_bp_channel_hash))

    deadline = time.time() + 30
    while time.time() < deadline:
        if RNS.Transport.has_path(bytes.fromhex(rfed_bp_channel_hash)):
            break
        time.sleep(0.5)

    if not RNS.Transport.has_path(bytes.fromhex(rfed_bp_channel_hash)):
        print("[bk-sub] ERROR: no path to primary channel destination", flush=True)
        sys.exit(1)

    channel_hash = compute_channel_hash(channel_name)
    print(f"[bk-sub] subscribing to '{channel_name}' ({channel_hash.hex()})...", flush=True)

    channel_dest_id = RNS.Identity.recall(bytes.fromhex(rfed_bp_channel_hash))
    if channel_dest_id is None:
        print("[bk-sub] ERROR: no identity for primary channel dest", flush=True)
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
        print("[bk-sub] ERROR: channel link to primary did not activate", flush=True)
        sys.exit(1)

    link.identify(my_identity)
    time.sleep(0.3)

    sub_event  = threading.Event()
    sub_result = [None]

    def sub_cb(rr):
        raw = rr.response
        try:
            sub_result[0] = msgpack.unpackb(raw, raw=False) if raw else None
        except Exception:
            sub_result[0] = raw
        print(f"[bk-sub] subscribe response: {sub_result[0]}", flush=True)
        sub_event.set()

    link.request(
        "/rfed/subscribe",
        msgpack.packb(channel_hash, use_bin_type=True),
        response_callback=sub_cb,
        failed_callback=lambda r: sub_event.set(),
        timeout=10,
    )
    sub_event.wait(timeout=15)
    link.teardown()

    print("[bk-sub] REGISTERED — subscription sent to primary (pull-only entry).", flush=True)
    print("[bk-sub] Primary will push this to backup node on next backup_push_tick.", flush=True)
    sys.exit(0)

# ─────────────────────────────────────────────────────────────────────────────
# PHASE: pull
#   The primary has been killed.  Connect to the BACKUP NODE's rfed.delivery
#   destination and PULL.  The backup node should have:
#     - The subscription entry (pushed from primary via BACKUP_PUSH_PATH)
#     - The blob (synced from primary via blob sync)
#     - The blob in the deferred queue after backup_delivery_tick fired
# ─────────────────────────────────────────────────────────────────────────────

rfed_bn_channel_hash  = bn_hashes.get("RFED_CHANNEL_HASH")
rfed_bn_delivery_hash = bn_hashes.get("RFED_DELIVERY_HASH")
rfed_bn_node_hash     = bn_hashes.get("RFED_NODE_HASH")

if not rfed_bn_delivery_hash:
    print("[bk-sub] ERROR: rfed_data_backup_node/hashes.env missing RFED_DELIVERY_HASH")
    sys.exit(1)

print(f"[bk-sub] requesting path to backup node delivery {rfed_bn_delivery_hash}...", flush=True)
RNS.Transport.request_path(bytes.fromhex(rfed_bn_delivery_hash))

deadline = time.time() + 30
while time.time() < deadline:
    if RNS.Transport.has_path(bytes.fromhex(rfed_bn_delivery_hash)):
        break
    time.sleep(0.5)

if not RNS.Transport.has_path(bytes.fromhex(rfed_bn_delivery_hash)):
    # Try via node path
    if rfed_bn_node_hash:
        print(f"[bk-sub] retrying via node path {rfed_bn_node_hash}...", flush=True)
        RNS.Transport.request_path(bytes.fromhex(rfed_bn_node_hash))
        time.sleep(5)
    delivery_ident = RNS.Identity.recall(bytes.fromhex(rfed_bn_delivery_hash))
    if delivery_ident is None:
        print("[bk-sub] ERROR: no path to backup node delivery destination", flush=True)
        sys.exit(1)
else:
    delivery_ident = RNS.Identity.recall(bytes.fromhex(rfed_bn_delivery_hash))

if delivery_ident is None:
    print("[bk-sub] ERROR: could not recall backup node delivery identity", flush=True)
    sys.exit(1)

# First, re-subscribe on the BACKUP NODE so it knows our identity for PULL.
# (The backup node has our subscription entry but needs to see our identity
#  on the new link to release queued blobs.)
if rfed_bn_channel_hash:
    channel_dest_id = RNS.Identity.recall(bytes.fromhex(rfed_bn_channel_hash))
    if channel_dest_id is None:
        RNS.Transport.request_path(bytes.fromhex(rfed_bn_channel_hash))
        time.sleep(5)
        channel_dest_id = RNS.Identity.recall(bytes.fromhex(rfed_bn_channel_hash))

    if channel_dest_id:
        channel_hash = compute_channel_hash(channel_name)
        print(f"[bk-sub] re-subscribing on backup node for '{channel_name}'...", flush=True)
        bk_ch_dest = RNS.Destination(
            channel_dest_id,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "rfed", "channel"
        )
        clink_active = threading.Event()
        clink = RNS.Link(bk_ch_dest)
        clink.set_link_established_callback(lambda l: clink_active.set())
        clink_active.wait(timeout=15)
        if clink.status == RNS.Link.ACTIVE:
            clink.identify(my_identity)
            time.sleep(0.3)
            sub2_event = threading.Event()
            clink.request(
                "/rfed/subscribe",
                msgpack.packb(channel_hash, use_bin_type=True),
                response_callback=lambda rr: (
                    print(f"[bk-sub] backup-sub response: {rr.response!r}", flush=True),
                    sub2_event.set()
                ),
                failed_callback=lambda r: sub2_event.set(),
                timeout=10,
            )
            sub2_event.wait(timeout=15)
            clink.teardown()

# Give the backup node a moment to process the subscription and notice queued blobs.
time.sleep(2)

# ── PULL from backup node delivery ───────────────────────────────────────────

print(f"[bk-sub] PULLing from backup node delivery...", flush=True)

delivery_dest = RNS.Destination(
    delivery_ident,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "rfed", "delivery"
)

dl_active = threading.Event()
dl_link   = RNS.Link(delivery_dest)
dl_link.set_link_established_callback(lambda l: dl_active.set())
dl_active.wait(timeout=15)
if dl_link.status != RNS.Link.ACTIVE:
    print("[bk-sub] ERROR: delivery link to backup node did not activate", flush=True)
    sys.exit(1)

dl_link.identify(my_identity)
time.sleep(0.3)

pull_event  = threading.Event()
pull_result = [None]

def pull_cb(rr):
    pull_result[0] = rr.response
    pull_event.set()

dl_link.request(
    "/rfed/pull",
    b"",
    response_callback=pull_cb,
    failed_callback=lambda r: pull_event.set(),
    timeout=30,
)
pull_event.wait(timeout=WAIT_TIMEOUT)
dl_link.teardown()

raw = pull_result[0]
if not raw:
    print("[bk-sub] PULL returned empty response", flush=True)
    sys.exit(1)

try:
    if isinstance(raw, list):
        pairs = raw
    else:
        pairs = msgpack.unpackb(raw, raw=True)
except Exception as e:
    print(f"[bk-sub] PULL decode error: {e}", flush=True)
    sys.exit(1)

if not pairs:
    print("[bk-sub] PULL returned 0 blob(s)", flush=True)
    sys.exit(1)

print(f"[bk-sub] PULL returned {len(pairs)} blob(s) ✓", flush=True)
found = False
for i, pair in enumerate(pairs):
    ch_h, blob = pair[0], pair[1]
    ch_str = ch_h.hex() if isinstance(ch_h, (bytes, bytearray)) else str(ch_h)
    try:
        decrypted = channel_decrypt(channel_name, blob)
    except Exception:
        decrypted = blob
    print(f"[bk-sub]   pull[{i}] channel={ch_str} decrypted={decrypted!r}", flush=True)
    if decrypted == expected_blob:
        found = True

if found:
    print("[bk-sub] PASS: backup failover blob received on backup node ✓", flush=True)
    sys.exit(0)
else:
    print(f"[bk-sub] FAIL: expected {expected_blob!r} not found in PULL", flush=True)
    sys.exit(1)
