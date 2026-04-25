#!/usr/bin/env python3
"""
lxmf_e2e_receiver.py — Standard LXMF propagation store-and-forward receiver.

Uses the real Python LXMRouter to:
  Phase 1 (--announce): create identity, announce, write pubkey/hash files.
  Phase 2 (--sync):     sync from rfed's lxmf.propagation node and verify
                        a message is received and decryptable.

Exit 0 on success, 1 on failure.
"""
import os, sys, time, threading
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(os.path.dirname(TEST_DIR))
for lib in ["Reticulum-master", "LXMF-master"]:
    p = os.path.join(WORKSPACE, lib)
    if p not in sys.path:
        sys.path.insert(0, p)

import RNS
import LXMF

# Import sandbox utilities — channel_hash lives next to this script.
if TEST_DIR not in sys.path:
    sys.path.insert(0, TEST_DIR)
from channel_hash import sandbox_path, ensure_config_dir

TEST_NS             = os.environ.get("RFED_TEST_NAMESPACE", "default")
RNS_CONFIG_DIR      = ensure_config_dir(f"rns_prop_receiver_{TEST_NS}", template="rns_prop_receiver")
LXMF_STORAGE        = sandbox_path("lxmf_storage", f"e2e_receiver_{TEST_NS}")
RFED_IDENTITY_FILE  = sandbox_path("rfed_data", "identity")
RECEIVER_ID_FILE    = sandbox_path("rfed_data", "e2e_receiver_identity")
RECEIVER_HASH_FILE  = sandbox_path("rfed_data", "lxmf_receiver_hash.txt")
PROP_NODE_HASH_FILE = sandbox_path("rfed_data", "prop_node_hash.txt")
TIMEOUT           = 60
LINK_TIMEOUT      = 20
SYNC_RETRIES      = 3

phase = "announce"
for i, a in enumerate(sys.argv[1:]):
    if a in ("--announce", "--sync"):
        phase = a.lstrip("-")
    if a == "--timeout" and i + 2 < len(sys.argv):
        TIMEOUT = int(sys.argv[i + 2])

os.makedirs(LXMF_STORAGE, exist_ok=True)

# ── Boot RNS ──────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR)
print(f"[recv] RNS ready  (phase={phase})", flush=True)

# ── Load or create persistent receiver identity ───────────────────────────────

if os.path.exists(RECEIVER_ID_FILE):
    receiver_identity = RNS.Identity.from_file(RECEIVER_ID_FILE)
    print(f"[recv] loaded existing identity", flush=True)
else:
    receiver_identity = RNS.Identity()
    receiver_identity.to_file(RECEIVER_ID_FILE)
    print(f"[recv] created new identity", flush=True)

# ── Boot LXMF router ─────────────────────────────────────────────────────────

router = LXMF.LXMRouter(storagepath=LXMF_STORAGE, enforce_stamps=False)
dest = router.register_delivery_identity(receiver_identity, display_name="e2e_receiver", stamp_cost=None)
print(f"[recv] lxmf.delivery dest: {dest.hash.hex()}", flush=True)

# Write hash file so sender knows who to address the message to
with open(RECEIVER_HASH_FILE, "w") as f:
    f.write(dest.hash.hex())
print(f"[recv] wrote delivery hash to {RECEIVER_HASH_FILE}", flush=True)

# ── Determine prop node hash ──────────────────────────────────────────────────

rfed_identity = RNS.Identity.from_file(RFED_IDENTITY_FILE)
if rfed_identity is None:
    print("[recv] ERROR: could not load rfed identity")
    sys.exit(1)

prop_dest = RNS.Destination(rfed_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "propagation")
print(f"[recv] lxmf.propagation dest: {prop_dest.hash.hex()}", flush=True)

with open(PROP_NODE_HASH_FILE, "w") as f:
    f.write(prop_dest.hash.hex())
print(f"[recv] wrote prop node hash to {PROP_NODE_HASH_FILE}", flush=True)

# ── Inject direct path to prop node ──────────────────────────────────────────

tcp_iface = None
for iface in RNS.Transport.interfaces:
    if hasattr(iface, 'target_ip'):
        tcp_iface = iface
        break

if tcp_iface is None:
    print("[recv] FAIL: no TCP interface found")
    sys.exit(1)

_now = time.time()
RNS.Transport.path_table[prop_dest.hash] = [_now, prop_dest.hash, 1, _now + 86400, [], tcp_iface, None]
print(f"[recv] injected path for lxmf.propagation via {tcp_iface}", flush=True)

# LXMRouter.request_messages_from_propagation_node internally calls
# RNS.Identity.recall(prop_node_hash) to rebuild the destination.
# Without an announce, known_destinations is empty — register the rfed
# identity manually so the recall succeeds.
RNS.Identity.remember(b'\x00' * 16, prop_dest.hash, rfed_identity.get_public_key())
print(f"[recv] registered rfed identity in known_destinations for prop_dest.hash", flush=True)

# ── Phase 1: announce ─────────────────────────────────────────────────────────

router.announce(dest.hash)
print(f"[recv] announced identity — sender can now address us", flush=True)

if phase == "announce":
    # Stay up briefly so the announce propagates through rfed/rnsd
    print("[recv] phase=announce: sleeping to let announce propagate...", flush=True)
    time.sleep(5)
    print("[recv] announce phase done", flush=True)
    sys.exit(0)

# ── Phase 2: sync from prop node ─────────────────────────────────────────────

received_messages = []
received_event = threading.Event()

def on_message(message):
    content = message.content_as_string() if hasattr(message, 'content_as_string') else str(message.content)
    print(f"[recv] *** MESSAGE RECEIVED ***", flush=True)
    print(f"[recv]   from:    {message.source_hash.hex() if message.source_hash else 'unknown'}", flush=True)
    print(f"[recv]   content: {content}", flush=True)
    received_messages.append(message)
    received_event.set()

router.register_delivery_callback(on_message)

router.set_outbound_propagation_node(prop_dest.hash)
# In isolated tests we may not receive propagation announce app-data, so seed
# stamp-cost cache directly for sync requests to avoid a false failure path.
router.update_stamp_cost(prop_dest.hash, 0)
print(f"[recv] syncing from prop node {prop_dest.hash.hex()}...", flush=True)

attempt = 1
deadline = time.time() + TIMEOUT
while attempt <= SYNC_RETRIES and not received_messages and time.time() < deadline:
    RNS.Transport.request_path(prop_dest.hash)
    router.request_messages_from_propagation_node(receiver_identity)

    wait_slice = max(1, int((deadline - time.time()) / max(1, (SYNC_RETRIES - attempt + 1))))
    received_event.wait(timeout=wait_slice)
    if received_messages:
        break

    state = router.propagation_transfer_state
    progress = router.propagation_transfer_progress
    print(f"[recv] sync attempt {attempt} incomplete (state={state}, progress={progress:.1%})", flush=True)
    if attempt < SYNC_RETRIES:
        # Reset link and retry. The first establish can race on fresh startup.
        router.cancel_propagation_node_requests()
        time.sleep(0.8)
    attempt += 1

if received_messages:
    msg = received_messages[0]
    content = msg.content_as_string() if hasattr(msg, 'content_as_string') else str(msg.content)
    print(f"[recv] PASS: received {len(received_messages)} message(s) ✓", flush=True)
    print(f"[recv]   content: {content}", flush=True)
    sys.exit(0)
else:
    state = router.propagation_transfer_state
    progress = router.propagation_transfer_progress
    print(f"[recv] FAIL: no message received (state={state}, progress={progress:.1%})", flush=True)
    sys.exit(1)
