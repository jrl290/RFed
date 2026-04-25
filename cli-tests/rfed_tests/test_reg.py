#!/usr/bin/env python3
"""
test_reg.py — Test successful notify-relay address registration with rfed.

Usage:
    test_reg.py <rfed_notify_hash_hex> [rfed_node_hash_hex]

Connects to rnsd at 192.168.2.107:4242, discovers the running rfed instance,
opens a link to rfed.notify, identifies, and sends a /rfed/notify/register
request with a freshly-generated relay hash.  Exits 0 on PASS, 1 on FAIL.
"""
import os, sys, time, threading
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)
from channel_hash import AnnounceHandler

import RNS
import msgpack

# ── Config ────────────────────────────────────────────────────────────────────

RNS_CONFIG_DIR = os.path.join(TEST_DIR, "rns_subscriber")
PATH_TIMEOUT   = 30
LINK_TIMEOUT   = 15
REQ_TIMEOUT    = 10

if len(sys.argv) < 2:
    print("Usage: test_reg.py <rfed_notify_hash_hex> [rfed_node_hash_hex]")
    sys.exit(1)

rfed_notify_hash_hex = sys.argv[1].strip()
rfed_node_hash_hex   = sys.argv[2].strip() if len(sys.argv) > 2 else ""

rfed_notify_hash = bytes.fromhex(rfed_notify_hash_hex)
rfed_node_hash   = bytes.fromhex(rfed_node_hash_hex) if rfed_node_hash_hex else None

# ── Boot RNS ──────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR, loglevel=RNS.LOG_DEBUG)

# ── Fresh subscriber identity (no persistence needed for a one-shot test) ─────

my_identity = RNS.Identity()
print(f"[test] subscriber hash : {my_identity.hash.hex()}", flush=True)

# ── Fresh relay identity — its hash is what we register ──────────────────────

relay_identity = RNS.Identity()
relay_hash_hex = relay_identity.hash.hex()
print(f"[test] relay hash      : {relay_hash_hex}", flush=True)

# ── Discover rfed.notify ──────────────────────────────────────────────────────

notify_dest_ref  = [None]
node_identity_ref = [None]
found_event = threading.Event()

def on_notify_announce(dest_hash, announced_identity, app_data, ann_hash, is_path):
    if notify_dest_ref[0] is None and announced_identity is not None:
        try:
            dest = RNS.Destination(
                announced_identity, RNS.Destination.OUT,
                RNS.Destination.SINGLE, "rfed", "notify"
            )
            notify_dest_ref[0] = dest
            found_event.set()
        except Exception as e:
            print(f"[test] announce error: {e}", flush=True)

def on_node_announce(dest_hash, announced_identity, app_data, ann_hash, is_path):
    if node_identity_ref[0] is None and announced_identity is not None:
        node_identity_ref[0] = announced_identity
        found_event.set()

RNS.Transport.register_announce_handler(
    AnnounceHandler(aspect_filter="rfed.notify", callback=on_notify_announce,
                    receive_path_responses=True)
)
RNS.Transport.register_announce_handler(
    AnnounceHandler(aspect_filter="rfed.node", callback=on_node_announce,
                    receive_path_responses=True)
)

print(f"[test] requesting path to rfed.notify {rfed_notify_hash_hex}...", flush=True)
RNS.Transport.request_path(rfed_notify_hash)
if rfed_node_hash:
    RNS.Transport.request_path(rfed_node_hash)

found_event.wait(timeout=PATH_TIMEOUT)

# Fallback: construct from node identity if notify didn't resolve directly
if notify_dest_ref[0] is None:
    if node_identity_ref[0] is not None:
        notify_dest_ref[0] = RNS.Destination(
            node_identity_ref[0], RNS.Destination.OUT,
            RNS.Destination.SINGLE, "rfed", "notify"
        )
        print("[test] constructed rfed.notify from node path-response identity", flush=True)
    else:
        for h in filter(None, [rfed_notify_hash, rfed_node_hash]):
            recalled = RNS.Identity.recall(h)
            if recalled:
                notify_dest_ref[0] = RNS.Destination(
                    recalled, RNS.Destination.OUT,
                    RNS.Destination.SINGLE, "rfed", "notify"
                )
                print("[test] constructed rfed.notify via Identity.recall", flush=True)
                break

if notify_dest_ref[0] is None:
    print("[test] FAIL: could not resolve rfed.notify destination", flush=True)
    sys.exit(1)

notify_dest = notify_dest_ref[0]
print(f"[test] rfed.notify     : {notify_dest.hash.hex()}", flush=True)

# ── Open link, identify, and send register request ────────────────────────────

link = RNS.Link(notify_dest)

link_active = threading.Event()
link.set_link_established_callback(lambda l: link_active.set())
link_active.wait(timeout=LINK_TIMEOUT)

if link.status != RNS.Link.ACTIVE:
    print("[test] FAIL: link to rfed.notify did not become active", flush=True)
    sys.exit(1)

link.identify(my_identity)
time.sleep(1.0)
print(f"[test] link active, identified as {my_identity.hash.hex()}", flush=True)

# ── Send /rfed/notify/register ────────────────────────────────────────────────

reg_done   = threading.Event()
reg_result = [None]

def on_response(receipt):
    raw = receipt.response
    print(f"[test] on_response: raw={raw!r} type={type(raw).__name__}", flush=True)
    try:
        reg_result[0] = msgpack.unpackb(raw) if raw else None
    except Exception as e:
        print(f"[test] response decode error: {e}  raw={raw!r}", flush=True)
        reg_result[0] = None
    reg_done.set()

def on_failed(receipt):
    print(f"[test] request failed (status={receipt.status})", flush=True)
    reg_result[0] = False
    reg_done.set()

link.request(
    "/rfed/notify/register",
    msgpack.packb(relay_hash_hex, use_bin_type=True),
    response_callback=on_response,
    failed_callback=on_failed,
    timeout=REQ_TIMEOUT,
)

reg_done.wait(timeout=REQ_TIMEOUT + 2)
link.teardown()

# ── Evaluate ──────────────────────────────────────────────────────────────────

result = reg_result[0]
if result is True:
    print(f"[test] PASS: rfed accepted registration, response={result!r}", flush=True)
    sys.exit(0)
elif result is False:
    print("[test] FAIL: rfed rejected or timed out", flush=True)
    sys.exit(1)
else:
    print(f"[test] FAIL: unexpected response={result!r}", flush=True)
    sys.exit(1)
