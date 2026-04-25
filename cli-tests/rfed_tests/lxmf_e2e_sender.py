#!/usr/bin/env python3
"""
lxmf_e2e_sender.py — Send a real encrypted LXMF message via rfed's propagation node.

Uses the real Python LXMRouter with PROPAGATED delivery method.
Reads the receiver's lxmf.delivery dest hash from rfed_data/lxmf_receiver_hash.txt
and the prop node hash from rfed_data/prop_node_hash.txt.

Exit 0 on success (message stored on prop node), 1 on failure.
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

TEST_NS              = os.environ.get("RFED_TEST_NAMESPACE", "default")
RNS_CONFIG_DIR       = ensure_config_dir(f"rns_prop_sender_{TEST_NS}", template="rns_prop_sender")
LXMF_STORAGE         = sandbox_path("lxmf_storage", f"e2e_sender_{TEST_NS}")
RFED_IDENTITY_FILE   = sandbox_path("rfed_data", "identity")
RECEIVER_HASH_FILE   = sandbox_path("rfed_data", "lxmf_receiver_hash.txt")
RECEIVER_ID_FILE     = sandbox_path("rfed_data", "e2e_receiver_identity")
PROP_NODE_HASH_FILE  = sandbox_path("rfed_data", "prop_node_hash.txt")
TIMEOUT            = 60
LINK_TIMEOUT       = 20

for i, a in enumerate(sys.argv[1:]):
    if a == "--timeout" and i + 2 < len(sys.argv):
        TIMEOUT = int(sys.argv[i + 2])

# ── Read config files ─────────────────────────────────────────────────────────

for f, label in [(RECEIVER_HASH_FILE, "receiver hash"), (PROP_NODE_HASH_FILE, "prop node hash"), (RECEIVER_ID_FILE, "receiver identity")]:
    if not os.path.exists(f):
        print(f"[sender] ERROR: {label} file not found: {f}")
        sys.exit(1)

receiver_delivery_hash = bytes.fromhex(open(RECEIVER_HASH_FILE).read().strip())
prop_node_hash         = bytes.fromhex(open(PROP_NODE_HASH_FILE).read().strip())
print(f"[sender] receiver delivery hash: {receiver_delivery_hash.hex()}", flush=True)
print(f"[sender] prop node hash:         {prop_node_hash.hex()}", flush=True)

os.makedirs(LXMF_STORAGE, exist_ok=True)

# ── Boot RNS ──────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR)
print("[sender] RNS ready", flush=True)

# ── Inject path to prop node ──────────────────────────────────────────────────

rfed_identity = RNS.Identity.from_file(RFED_IDENTITY_FILE)
if rfed_identity is None:
    print("[sender] ERROR: could not load rfed identity")
    sys.exit(1)

prop_dest = RNS.Destination(rfed_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "propagation")

tcp_iface = None
for iface in RNS.Transport.interfaces:
    if hasattr(iface, 'target_ip'):
        tcp_iface = iface
        break

if tcp_iface is None:
    print("[sender] FAIL: no TCP interface found")
    sys.exit(1)

_now = time.time()
RNS.Transport.path_table[prop_dest.hash] = [_now, prop_dest.hash, 1, _now + 86400, [], tcp_iface, None]
print(f"[sender] injected path for lxmf.propagation: {prop_dest.hash.hex()}", flush=True)

# Register rfed identity so LXMRouter can recall it when establishing the link.
RNS.Identity.remember(b'\x00' * 16, prop_dest.hash, rfed_identity.get_public_key())
print(f"[sender] registered rfed identity in known_destinations", flush=True)

# ── Load receiver identity (public key only, saved by receiver) ───────────────
# The receiver script saves its full identity file; we load it as public-key-only.

receiver_identity = RNS.Identity.from_file(RECEIVER_ID_FILE)
if receiver_identity is None:
    print("[sender] ERROR: could not load receiver identity from file")
    sys.exit(1)

dest = RNS.Destination(receiver_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
print(f"[sender] receiver dest: {dest.hash.hex()}", flush=True)

if dest.hash != receiver_delivery_hash:
    print(f"[sender] WARNING: computed dest hash {dest.hash.hex()} != expected {receiver_delivery_hash.hex()}")

# ── Boot LXMF router and send ─────────────────────────────────────────────────

router = LXMF.LXMRouter(storagepath=LXMF_STORAGE, enforce_stamps=False)
sender_identity = RNS.Identity()
source = router.register_delivery_identity(sender_identity, display_name="e2e_sender", stamp_cost=None)
print(f"[sender] sender delivery dest: {source.hash.hex()}", flush=True)

router.set_outbound_propagation_node(prop_node_hash)
# We inject a direct path and identity, but no propagation announce app-data.
# Seed a zero stamp-cost cache entry so LXMRouter does not fail while waiting
# for announce metadata that may not exist in isolated test topologies.
router.update_stamp_cost(prop_node_hash, 0)
print(f"[sender] outbound prop node: {prop_node_hash.hex()}", flush=True)

message = LXMF.LXMessage(dest, source, "Hello via rfed store-and-forward!", title="E2E PropTest")
message.desired_method = LXMF.LXMessage.PROPAGATED

state_event = threading.Event()
final_state = [None]

def on_state(msg):
    final_state[0] = msg.state
    if msg.state in (LXMF.LXMessage.DELIVERED, LXMF.LXMessage.FAILED, LXMF.LXMessage.SENT):
        state_event.set()

message.register_delivery_callback(on_state)
message.register_failed_callback(on_state)

# Wait for the TCP interface to be connected before sending
print("[sender] waiting for TCP interface to be online...", flush=True)
for _ in range(30):
    if any(hasattr(iface, 'target_ip') and iface.online for iface in RNS.Transport.interfaces):
        break
    time.sleep(0.5)
else:
    print("[sender] WARNING: TCP interface not confirmed online, sending anyway", flush=True)

router.handle_outbound(message)
print("[sender] message queued (PROPAGATED)", flush=True)

state_event.wait(timeout=TIMEOUT)

STATE_NAMES = {
    LXMF.LXMessage.OUTBOUND:  "OUTBOUND",
    LXMF.LXMessage.SENDING:   "SENDING",
    LXMF.LXMessage.SENT:      "SENT",
    LXMF.LXMessage.DELIVERED: "DELIVERED",
    LXMF.LXMessage.FAILED:    "FAILED",
}
state_name = STATE_NAMES.get(message.state, str(message.state))

# PROPAGATED delivery is confirmed when the prop node stores the message —
# LXMRouter marks the message as SENT after the prop node acknowledges storage.
if message.state in (LXMF.LXMessage.SENT, LXMF.LXMessage.DELIVERED):
    print(f"[sender] PASS: message stored on prop node (state={state_name}) ✓", flush=True)
    sys.exit(0)
elif message.state == LXMF.LXMessage.FAILED:
    print(f"[sender] FAIL: message delivery failed", flush=True)
    sys.exit(1)
else:
    print(f"[sender] FAIL: timeout (state={state_name})", flush=True)
    sys.exit(1)
