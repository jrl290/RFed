#!/usr/bin/env python3
"""
rfed_subscriber.py — Subscribe to a channel and receive blobs from an rfed node.

Usage:
    rfed_subscriber.py <rfed_node_hash_hex> [channel_name] [--pull-only] [--timeout N]

Scenarios covered:
  Default  — Subscribe, announce rfed.delivery (live fanout), wait for blobs.
  --pull-only — Subscribe but do NOT announce (stay "offline"), then PULL at end.

The subscriber persists its identity within the current test namespace only.
"""
import os, sys, time, threading
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)
from channel_hash import compute_channel_hash, channel_decrypt, AnnounceHandler, ensure_config_dir, load_hashes, sandbox_path

import RNS
import msgpack

# ── Config ───────────────────────────────────────────────────────────────────

TEST_NS         = os.environ.get("RFED_TEST_NAMESPACE", "default")
RNS_CONFIG_DIR  = ensure_config_dir(f"rns_subscriber_{TEST_NS}", template="rns_subscriber")
IDENTITY_FILE   = os.path.join(RNS_CONFIG_DIR, "sub_identity")
CHANNEL_NAME    = "public.test"
PATH_TIMEOUT    = 30
RECEIVE_TIMEOUT = 30

if len(sys.argv) < 2:
    print("Usage: rfed_subscriber.py <rfed_node_hash_hex> [channel_name] [--pull-only] [--timeout N]")
    sys.exit(1)

rfed_node_hash = bytes.fromhex(sys.argv[1].strip())
pull_only = "--pull-only" in sys.argv
for i, a in enumerate(sys.argv):
    if a == "--timeout" and i + 1 < len(sys.argv):
        RECEIVE_TIMEOUT = int(sys.argv[i + 1])
for a in sys.argv[2:]:
    if not a.startswith("--"):
        CHANNEL_NAME = a
        break

print(f"[sub] channel: {CHANNEL_NAME}", flush=True)
print(f"[sub] pull_only: {pull_only}", flush=True)

# ── Boot RNS ─────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR, loglevel=RNS.LOG_DEBUG)

hash_env = load_hashes()
rfed_channel_hash  = hash_env.get("RFED_CHANNEL_HASH")
rfed_delivery_hash = hash_env.get("RFED_DELIVERY_HASH")
rfed_node_hash_env = hash_env.get("RFED_NODE_HASH") or rfed_node_hash
expected_node_hashes = set(filter(None, [rfed_node_hash_env, rfed_node_hash]))
expected_channel_hashes = set(filter(None, [rfed_channel_hash]))
expected_delivery_hashes = set(filter(None, [rfed_delivery_hash]))

# Load or create a persistent subscriber identity.
if os.path.exists(IDENTITY_FILE):
    my_identity = RNS.Identity(create_keys=False)
    my_identity.load_private_key(open(IDENTITY_FILE, "rb").read())
    print(f"[sub] loaded existing identity", flush=True)
else:
    my_identity = RNS.Identity()
    with open(IDENTITY_FILE, "wb") as f:
        f.write(my_identity.get_private_key())
    print(f"[sub] created new identity", flush=True)

print(f"[sub] identity hash: {my_identity.hash.hex()}", flush=True)


def wait_for_path(dest_hash: bytes, label: str, timeout: int = PATH_TIMEOUT) -> bool:
    """Actively request a path and wait for transport to learn it."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if RNS.Transport.has_path(dest_hash):
            return True
        RNS.Transport.request_path(dest_hash)
        time.sleep(0.5)
    return RNS.Transport.has_path(dest_hash)

# ── Inbound rfed.delivery destination (our inbox) ────────────────────────────

received_blobs = []
blob_event = threading.Event()

my_delivery = RNS.Destination(
    my_identity, RNS.Destination.IN,
    RNS.Destination.SINGLE, "rfed", "delivery"
)

def on_delivery_packet(data, packet):
    try:
        plaintext = channel_decrypt(CHANNEL_NAME, data)
        print(f"[sub] *** LIVE DELIVERY *** {len(data)} bytes encrypted, decrypted: {plaintext!r}", flush=True)
        received_blobs.append(plaintext)
    except Exception as e:
        print(f"[sub] *** LIVE DELIVERY *** {len(data)} bytes (decrypt failed: {e}), raw: {data!r}", flush=True)
        received_blobs.append(data)
    blob_event.set()

my_delivery.set_packet_callback(on_delivery_packet)

if not pull_only:
    my_delivery.announce()
    print(f"[sub] announced rfed.delivery: {my_delivery.hash.hex()}", flush=True)
else:
    print(f"[sub] rfed.delivery NOT announced (pull-only mode)", flush=True)

# ── Discover rfed.channel ─────────────────────────────────────────────────────
# Register handlers with receive_path_responses=True so a path request
# response also triggers the callback.  We request paths immediately after
# registering so that rnsd's cached path triggers a response.

channel_dest_ref  = [None]
node_identity_ref = [None]
channel_found     = threading.Event()

def on_channel_announce(dest_hash, announced_identity, app_data, ann_hash, is_path):
    if expected_channel_hashes and dest_hash not in expected_channel_hashes:
        return
    if channel_dest_ref[0] is None and announced_identity is not None:
        try:
            dest = RNS.Destination(
                announced_identity, RNS.Destination.OUT,
                RNS.Destination.SINGLE, "rfed", "channel"
            )
            channel_dest_ref[0] = dest
            channel_found.set()
        except Exception as e:
            print(f"[sub] channel announce error: {e}", flush=True)

def on_node_announce(dest_hash, announced_identity, app_data, ann_hash, is_path):
    if expected_node_hashes and dest_hash not in expected_node_hashes:
        return
    if node_identity_ref[0] is None and announced_identity is not None:
        node_identity_ref[0] = announced_identity
        channel_found.set()

RNS.Transport.register_announce_handler(
    AnnounceHandler(aspect_filter="rfed.channel", callback=on_channel_announce,
                    receive_path_responses=True)
)
RNS.Transport.register_announce_handler(
    AnnounceHandler(aspect_filter="rfed.node", callback=on_node_announce,
                    receive_path_responses=True)
)

print("[sub] requesting paths to rfed destinations...", flush=True)
for h in filter(None, [rfed_channel_hash, rfed_node_hash_env]):
    RNS.Transport.request_path(h)

channel_found.wait(timeout=PATH_TIMEOUT)

if channel_dest_ref[0] is None:
    if node_identity_ref[0] is not None:
        channel_dest_ref[0] = RNS.Destination(
            node_identity_ref[0], RNS.Destination.OUT,
            RNS.Destination.SINGLE, "rfed", "channel"
        )
        print("[sub] constructed rfed.channel from node path-response identity", flush=True)
    else:
        rfed_identity = None
        for h in filter(None, [rfed_channel_hash, rfed_node_hash_env, rfed_node_hash]):
            rfed_identity = RNS.Identity.recall(h)
            if rfed_identity:
                break
        if rfed_identity is None:
            print("[sub] ERROR: cannot find rfed identity after timeout", flush=True)
            sys.exit(1)
        channel_dest_ref[0] = RNS.Destination(
            rfed_identity, RNS.Destination.OUT,
            RNS.Destination.SINGLE, "rfed", "channel"
        )
        print("[sub] using Identity.recall fallback for rfed.channel", flush=True)

channel_dest = channel_dest_ref[0]
print(f"[sub] rfed.channel: {channel_dest.hash.hex()}", flush=True)

if not wait_for_path(channel_dest.hash, "rfed.channel"):
    print(f"[sub] ERROR: no path to rfed.channel {channel_dest.hash.hex()}", flush=True)
    sys.exit(1)

# ── Open Link and SUBSCRIBE ───────────────────────────────────────────────────

print(f"[sub] opening link to rfed.channel...", flush=True)
link = RNS.Link(channel_dest)

link_active = threading.Event()
link.set_link_established_callback(lambda l: link_active.set())
link_active.wait(timeout=15)

if link.status != RNS.Link.ACTIVE:
    print("[sub] ERROR: link to rfed.channel did not activate", flush=True)
    sys.exit(1)

print(f"[sub] link active", flush=True)

# Identify ourselves on the link so rfed knows our subscriber hash.
# Must be done before calling link.request(), and we wait a moment
# to ensure rfed has processed the LINKIDENTIFY packet.
link.identify(my_identity)
time.sleep(0.3)
print(f"[sub] identified on link as {my_identity.hash.hex()}", flush=True)

ch_hash = compute_channel_hash(CHANNEL_NAME)
print(f"[sub] subscribing to '{CHANNEL_NAME}' ({ch_hash.hex()})...", flush=True)

subscribe_done   = threading.Event()
subscribe_result = [None]

def on_subscribe_response(receipt):
    print(f"[sub] *** RESPONSE CB: response={receipt.response!r}", flush=True)
    resp = receipt.response
    if isinstance(resp, bool):
        # Python RNS already decoded the msgpack bool for us
        subscribe_result[0] = resp
    elif resp:
        try:
            subscribe_result[0] = msgpack.unpackb(resp)
        except Exception as e:
            subscribe_result[0] = f"decode error: {e}"
    else:
        subscribe_result[0] = None
    subscribe_done.set()

def on_subscribe_failed(receipt):
    subscribe_result[0] = "FAILED"
    subscribe_done.set()

link.request(
    "/rfed/subscribe",
    msgpack.packb(ch_hash, use_bin_type=True),
    response_callback=on_subscribe_response,
    failed_callback=on_subscribe_failed,
    timeout=10,
)

subscribe_done.wait(timeout=12)
print(f"[sub] subscribe result: {subscribe_result[0]}", flush=True)

link.teardown()

# ── Wait for live fanout delivery ─────────────────────────────────────────────

if pull_only:
    print("[sub] pull-only mode: not waiting for live delivery", flush=True)
else:
    print(f"[sub] waiting {RECEIVE_TIMEOUT}s for live fanout delivery...", flush=True)
    blob_event.wait(timeout=RECEIVE_TIMEOUT)
    if received_blobs:
        print(f"[sub] received {len(received_blobs)} blob(s) via live fanout ✓", flush=True)
        for i, b in enumerate(received_blobs):
            print(f"[sub]   blob[{i}]: {b!r}", flush=True)
    else:
        print("[sub] no blobs received via live fanout (may have been deferred)", flush=True)

# ── PULL path ─────────────────────────────────────────────────────────────────

print("\n[sub] attempting PULL from rfed.delivery...", flush=True)

server_delivery_ref = [None]
delivery_found      = threading.Event()

def on_delivery_announce(dest_hash, announced_identity, app_data, ann_hash, is_path):
    if expected_delivery_hashes and dest_hash not in expected_delivery_hashes:
        return
    if server_delivery_ref[0] is None and announced_identity is not None:
        try:
            dest = RNS.Destination(
                announced_identity, RNS.Destination.OUT,
                RNS.Destination.SINGLE, "rfed", "delivery"
            )
            server_delivery_ref[0] = dest
            delivery_found.set()
        except Exception as e:
            print(f"[sub] delivery announce error: {e}", flush=True)

def on_node_for_delivery(dest_hash, announced_identity, app_data, ann_hash, is_path):
    if expected_node_hashes and dest_hash not in expected_node_hashes:
        return
    if server_delivery_ref[0] is None and announced_identity is not None:
        try:
            dest = RNS.Destination(
                announced_identity, RNS.Destination.OUT,
                RNS.Destination.SINGLE, "rfed", "delivery"
            )
            server_delivery_ref[0] = dest
            delivery_found.set()
        except Exception:
            pass

RNS.Transport.register_announce_handler(
    AnnounceHandler(aspect_filter="rfed.delivery", callback=on_delivery_announce,
                    receive_path_responses=True)
)
RNS.Transport.register_announce_handler(
    AnnounceHandler(aspect_filter="rfed.node", callback=on_node_for_delivery,
                    receive_path_responses=True)
)

for h in filter(None, [rfed_delivery_hash, rfed_node_hash_env]):
    RNS.Transport.request_path(h)

delivery_found.wait(timeout=PATH_TIMEOUT)

if server_delivery_ref[0] is None:
    if node_identity_ref[0] is not None:
        server_delivery_ref[0] = RNS.Destination(
            node_identity_ref[0], RNS.Destination.OUT,
            RNS.Destination.SINGLE, "rfed", "delivery"
        )
        print("[sub] using rfed.node identity fallback for server delivery dest", flush=True)

if server_delivery_ref[0] is None:
    for h in filter(None, [rfed_delivery_hash, rfed_node_hash_env, rfed_node_hash]):
        rfed_identity = RNS.Identity.recall(h)
        if rfed_identity:
            server_delivery_ref[0] = RNS.Destination(
                rfed_identity, RNS.Destination.OUT,
                RNS.Destination.SINGLE, "rfed", "delivery"
            )
            print("[sub] using Identity.recall for server delivery dest", flush=True)
            break

# Last resort: load rfed's identity directly from the sandbox identity file.
if server_delivery_ref[0] is None:
    rfed_id_file = sandbox_path("rfed_data", "identity")
    if os.path.exists(rfed_id_file):
        rfed_id = RNS.Identity.from_file(rfed_id_file)
        if rfed_id is not None:
            server_delivery_ref[0] = RNS.Destination(
                rfed_id, RNS.Destination.OUT,
                RNS.Destination.SINGLE, "rfed", "delivery"
            )
            print("[sub] using sandbox identity file for server delivery dest", flush=True)

if server_delivery_ref[0] is None:
    print("[sub] WARNING: could not find rfed.delivery, skipping pull", flush=True)
else:
    if not RNS.Transport.has_path(server_delivery_ref[0].hash):
        tcp_iface = next((i for i in RNS.Transport.interfaces if hasattr(i, "target_ip")), None)
        if tcp_iface is not None:
            now = time.time()
            RNS.Transport.path_table[server_delivery_ref[0].hash] = [
                now,                         # timestamp
                server_delivery_ref[0].hash, # next hop (direct)
                1,                           # hops
                now + 86400,                 # expires
                [],                          # randblobs
                tcp_iface,                   # received-on interface
                None,                        # packet
            ]
            print("[sub] injected direct path for rfed.delivery", flush=True)

    if not wait_for_path(server_delivery_ref[0].hash, "rfed.delivery"):
        print(f"[sub] WARNING: no path to rfed.delivery {server_delivery_ref[0].hash.hex()}, skipping pull", flush=True)
        print("\n[sub] done", flush=True)
        sys.exit(0)

    pull_link = RNS.Link(server_delivery_ref[0])
    pull_link_active = threading.Event()
    pull_link.set_link_established_callback(lambda l: pull_link_active.set())
    pull_link_active.wait(timeout=15)

    if pull_link.status != RNS.Link.ACTIVE:
        print("[sub] WARNING: pull link did not activate", flush=True)
    else:
        # Identify ourselves so rfed can look up our deferred queue.
        pull_link.identify(my_identity)
        time.sleep(0.3)
        print(f"[sub] identified on pull link as {my_identity.hash.hex()}", flush=True)

        pull_done   = threading.Event()
        pull_result = [None]

        def on_pull_response(receipt):
            pull_result[0] = receipt.response
            pull_done.set()

        def on_pull_failed(receipt):
            pull_result[0] = b""
            pull_done.set()

        pull_link.request(
            "/rfed/pull", b"",
            response_callback=on_pull_response,
            failed_callback=on_pull_failed,
            timeout=15,
        )
        pull_done.wait(timeout=17)
        pull_link.teardown()

        if pull_result[0]:
            try:
                raw = pull_result[0]
                # Python RNS may have already decoded the msgpack array for us
                if isinstance(raw, list):
                    blobs = raw
                else:
                    blobs = msgpack.unpackb(raw, raw=True)
                print(f"[sub] PULL returned {len(blobs)} blob(s) ✓", flush=True)
                for i, pair in enumerate(blobs):
                    ch, blob = pair[0], pair[1]
                    try:
                        plaintext = channel_decrypt(CHANNEL_NAME, blob)
                        print(f"[sub]   pull[{i}] channel={ch.hex()} decrypted={plaintext!r}", flush=True)
                    except Exception as e:
                        print(f"[sub]   pull[{i}] channel={ch.hex()} decrypt failed: {e}, raw={blob!r}", flush=True)
            except Exception as e:
                print(f"[sub] pull decode error: {e}", flush=True)
        else:
            print("[sub] PULL returned empty (no deferred blobs)", flush=True)

print("\n[sub] done", flush=True)
