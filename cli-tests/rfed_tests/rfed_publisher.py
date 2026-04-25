#!/usr/bin/env python3
"""
rfed_publisher.py — Send a channel blob to an rfed node.

Usage:
    rfed_publisher.py <rfed_node_hash_hex> [channel_name] [message]

Wire format (stamp_cost = 0 in test, so trivial 16-byte zero stamp appended):
    channel_hash(16) | encrypted_blob(*) | stamp(32 zero bytes)

The inner blob is encrypted to the channel's deterministic X25519 public key
before embedding.  The rfed node cannot decrypt it — only subscribers who
know the channel name can recover the plaintext (same model as LXMF
propagation).
"""
import os, sys, time, threading
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)
from channel_hash import compute_channel_hash, channel_encrypt, AnnounceHandler, ensure_config_dir, load_hashes

import RNS

# ── Config ───────────────────────────────────────────────────────────────────

TEST_NS         = os.environ.get("RFED_TEST_NAMESPACE", "default")
RNS_CONFIG_DIR  = ensure_config_dir(f"rns_publisher_{TEST_NS}", template="rns_publisher")
CHANNEL_NAME    = sys.argv[2] if len(sys.argv) > 2 else "public.test"
MESSAGE_TEXT    = " ".join(sys.argv[3:]) if len(sys.argv) > 3 else "Hello from rfed_publisher"
STAMP_BYTES     = bytes(32)   # trivial stamp — satisfies stamp_cost=0 (LXStamper::STAMP_SIZE=32)
PATH_TIMEOUT    = 30

if len(sys.argv) < 2:
    print("Usage: rfed_publisher.py <rfed_node_hash_hex> [channel_name] [message]")
    sys.exit(1)

rfed_node_hash = bytes.fromhex(sys.argv[1].strip())

# ── Boot RNS ─────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR)
print("[pub] RNS ready", flush=True)

# ── Discover rfed.channel ─────────────────────────────────────────────────────
# Strategy:
#   1. Read rfed.channel hash from hashes.env (written by setup.sh).
#   2. Register announce handler with receive_path_responses=True so that
#      a path request response also provides the destination identity.
#   3. Call request_path(channel_hash) — if rnsd cached rfed's announce this
#      triggers a path response → callback fires with identity.
#   4. Or if a live announce arrives first, the callback fires directly.
#   5. Fallback: recall identity from rfed.node announce.

hash_env = load_hashes()
rfed_channel_hash = hash_env.get("RFED_CHANNEL_HASH") or None
rfed_node_hash_env = hash_env.get("RFED_NODE_HASH") or rfed_node_hash

channel_found = threading.Event()
channel_dest_ref = [None]

def on_channel_announce(dest_hash, announced_identity, app_data, ann_hash, is_path):
    # Ignore announces from other rfed nodes on the shared backbone.
    if rfed_channel_hash and dest_hash != rfed_channel_hash:
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
            print(f"[pub] channel announce error: {e}", flush=True)

RNS.Transport.register_announce_handler(
    AnnounceHandler(aspect_filter="rfed.channel", callback=on_channel_announce,
                    receive_path_responses=True)
)

# Also watch for rfed.node announces as a fallback identity source.
node_identity_ref = [None]
def on_node_announce(dest_hash, announced_identity, app_data, ann_hash, is_path):
    # Only accept our expected rfed node's announce.
    expected = set(filter(None, [rfed_node_hash_env, rfed_node_hash]))
    if expected and dest_hash not in expected:
        return
    if node_identity_ref[0] is None and announced_identity is not None:
        node_identity_ref[0] = announced_identity
        channel_found.set()  # will fall back below

RNS.Transport.register_announce_handler(
    AnnounceHandler(aspect_filter="rfed.node", callback=on_node_announce,
                    receive_path_responses=True)
)

# Request paths to trigger path responses (works if rnsd cached rfed's announces).
if rfed_channel_hash:
    print(f"[pub] requesting path to rfed.channel {rfed_channel_hash.hex()}...", flush=True)
    RNS.Transport.request_path(rfed_channel_hash)
if rfed_node_hash_env:
    RNS.Transport.request_path(rfed_node_hash_env)

print(f"[pub] waiting for rfed.channel announce/path-response...", flush=True)
channel_found.wait(timeout=PATH_TIMEOUT)

if channel_dest_ref[0] is None:
    # Fallback A: identity arrived via rfed.node announce.
    if node_identity_ref[0] is not None:
        channel_dest_ref[0] = RNS.Destination(
            node_identity_ref[0], RNS.Destination.OUT,
            RNS.Destination.SINGLE, "rfed", "channel"
        )
        print("[pub] constructed rfed.channel from rfed.node identity", flush=True)
    else:
        # Fallback B: try Identity.recall from the known channel or node hash.
        rfed_identity = None
        for h in [rfed_channel_hash, rfed_node_hash_env, rfed_node_hash]:
            if h:
                rfed_identity = RNS.Identity.recall(h)
                if rfed_identity:
                    break
        if rfed_identity is None:
            print("[pub] ERROR: cannot find rfed identity after timeout", flush=True)
            sys.exit(1)
        channel_dest_ref[0] = RNS.Destination(
            rfed_identity, RNS.Destination.OUT,
            RNS.Destination.SINGLE, "rfed", "channel"
        )
        print("[pub] constructed rfed.channel via Identity.recall fallback", flush=True)

channel_dest = channel_dest_ref[0]
print(f"[pub] rfed.channel hash: {channel_dest.hash.hex()}", flush=True)

# ── Build and send the SEND packet ───────────────────────────────────────────

ch_hash    = compute_channel_hash(CHANNEL_NAME)
plaintext  = MESSAGE_TEXT.encode("utf-8")
inner_blob = channel_encrypt(CHANNEL_NAME, plaintext)
payload    = ch_hash + inner_blob + STAMP_BYTES  # channel_hash | encrypted_blob | trivial stamp

print(f"[pub] channel '{CHANNEL_NAME}' hash: {ch_hash.hex()}", flush=True)
print(f"[pub] plaintext: {plaintext!r} ({len(plaintext)} bytes)", flush=True)
print(f"[pub] encrypted blob: {len(inner_blob)} bytes", flush=True)
print(f"[pub] total packet payload: {len(payload)} bytes", flush=True)

packet = RNS.Packet(channel_dest, payload, RNS.Packet.DATA)
receipt = packet.send()

if receipt:
    print(f"[pub] SEND packet enqueued (receipt: {receipt})", flush=True)
else:
    print("[pub] WARNING: send returned no receipt (may still have been sent)", flush=True)

# Give the transport layer time to deliver.
time.sleep(2)
print("[pub] done", flush=True)
