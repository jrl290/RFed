#!/usr/bin/env python3
"""
lxmf_e2e_ext.py — End-to-end LXMF store-and-forward test against a real remote rfed node.

Usage:
    python3 lxmf_e2e_ext.py --prop-hash <hex> [--stamp-cost N] [--timeout N]

Connects via rns_client_ext config (192.168.2.107:4242).
Pre-generates the propagation stamp (avoids the msgpack strict_map_key bug with
rfed's integer-keyed metadata announce) before queuing the message.

Exit 0 on full round-trip (send + receive), 1 on failure.
"""
import os, sys, time, threading

TEST_DIR  = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(os.path.dirname(TEST_DIR))
for lib in ["Reticulum-master", "LXMF-master"]:
    p = os.path.join(WORKSPACE, lib)
    if p not in sys.path:
        sys.path.insert(0, p)

import RNS
import LXMF

PROP_NODE_HASH_HEX = "0f75ac15961b7d2b1577a57bdb1fda3c"
STAMP_COST         = 12   # from rfed config default policy
RNS_CONFIG_DIR     = os.path.join(TEST_DIR, "rns_client_rmap")
LXMF_STORAGE_RX    = "/tmp/e2e_ext_receiver"
LXMF_STORAGE_TX    = "/tmp/e2e_ext_sender"
RECEIVER_ID_FILE   = "/tmp/e2e_ext_receiver_identity"
STAMP_TIMEOUT      = 600  # 10 min for cost=12 single-core
SEND_TIMEOUT       = 120
RECV_TIMEOUT       = 90

for i, a in enumerate(sys.argv[1:]):
    if a == "--prop-hash"  and i + 2 < len(sys.argv): PROP_NODE_HASH_HEX = sys.argv[i + 2]
    if a == "--stamp-cost" and i + 2 < len(sys.argv): STAMP_COST         = int(sys.argv[i + 2])
    if a == "--timeout"    and i + 2 < len(sys.argv):
        STAMP_TIMEOUT = int(sys.argv[i + 2])
        SEND_TIMEOUT  = int(sys.argv[i + 2])

PROP_NODE_HASH = bytes.fromhex(PROP_NODE_HASH_HEX)

sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)
os.makedirs(LXMF_STORAGE_RX, exist_ok=True)
os.makedirs(LXMF_STORAGE_TX, exist_ok=True)

def log(msg): print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

# ── Boot RNS ──────────────────────────────────────────────────────────────────
RNS.Reticulum(configdir=RNS_CONFIG_DIR)
log("RNS ready")

# Request a fresh path to the propagation node (even if identity is cached, the
# routing table entry may be stale — a fresh path request forces rnsd to populate it)
log("requesting fresh path to prop node (waiting up to 30s for rmap.world announce)...")
RNS.Transport.request_path(PROP_NODE_HASH)

# Wait for path + identity (up to 30s — rmap.world needs time to relay the announce)
deadline = time.time() + 30
while time.time() < deadline:
    if RNS.Transport.has_path(PROP_NODE_HASH) and RNS.Identity.recall(PROP_NODE_HASH):
        break
    time.sleep(0.5)

prop_identity = RNS.Identity.recall(PROP_NODE_HASH)
has_path = RNS.Transport.has_path(PROP_NODE_HASH)
if prop_identity is None:
    log("FAIL: cannot recall prop node identity"); sys.exit(1)
if not has_path:
    log("WARNING: no routing path to prop node — link may fail")
log(f"prop identity: {prop_identity.hash.hex()}, has_path={has_path}")

# ── Receiver: create identity and announce ────────────────────────────────────
router_rx = LXMF.LXMRouter(storagepath=LXMF_STORAGE_RX, enforce_stamps=False)
if os.path.exists(RECEIVER_ID_FILE):
    rx_identity = RNS.Identity.from_file(RECEIVER_ID_FILE)
    log("loaded existing receiver identity")
else:
    rx_identity = RNS.Identity()
    rx_identity.to_file(RECEIVER_ID_FILE)
    log("created new receiver identity")

rx_dest = router_rx.register_delivery_identity(rx_identity, display_name="ext_e2e_rx", stamp_cost=None)
log(f"receiver delivery dest: {rx_dest.hash.hex()}")
router_rx.announce(rx_dest.hash)
log("receiver announced — sleeping 3s for propagation")
time.sleep(3)

# ── Sender: build message and PRE-GENERATE stamp ──────────────────────────────
# The Python msgpack library refuses to parse rfed's announce app_data (integer
# key in the metadata dict → strict_map_key error), so LXMRouter.get_outbound_
# propagation_cost() returns None and deferred stamp generation fails.
# Work around it: pack the message to get its transient_id, then call
# get_propagation_stamp(target_cost=STAMP_COST) explicitly before queuing.
router_tx = LXMF.LXMRouter(storagepath=LXMF_STORAGE_TX, enforce_stamps=False)
tx_identity = RNS.Identity()
tx_dest_obj = router_tx.register_delivery_identity(tx_identity, display_name="ext_e2e_tx", stamp_cost=None)
router_tx.set_outbound_propagation_node(PROP_NODE_HASH)

msg_dest = RNS.Destination(rx_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
msg = LXMF.LXMessage(msg_dest, tx_dest_obj, "Hello from e2e ext test!", title="ExtE2ETest")
msg.desired_method = LXMF.LXMessage.PROPAGATED

# Pack first so transient_id is available for stamp generation
msg.pack()
log(f"message packed, transient_id={msg.transient_id.hex() if msg.transient_id else 'None'}")

log(f"generating propagation stamp (cost={STAMP_COST}) — this may take several minutes on single core...")
stamp_start = time.time()

stamp_done = threading.Event()
stamp_result = [None]

def do_stamp():
    stamp_result[0] = msg.get_propagation_stamp(target_cost=STAMP_COST)
    stamp_done.set()

threading.Thread(target=do_stamp, daemon=True).start()

while not stamp_done.is_set():
    elapsed = time.time() - stamp_start
    if elapsed > STAMP_TIMEOUT:
        log(f"FAIL: stamp generation timed out after {elapsed:.0f}s")
        sys.exit(1)
    log(f"  stamping t+{elapsed:.0f}s ...")
    stamp_done.wait(timeout=30)

stamp_elapsed = time.time() - stamp_start
if stamp_result[0] is None:
    log(f"FAIL: stamp generation returned None"); sys.exit(1)
log(f"stamp generated in {stamp_elapsed:.1f}s ✓")

# ── Queue and send ────────────────────────────────────────────────────────────
sent_event = threading.Event()
NAMES = {0x01:"OUTBOUND",0x02:"SENDING",0x04:"SENT",0x08:"DELIVERED",0xFF:"FAILED"}

def on_state(m):
    if m.state in (LXMF.LXMessage.SENT, LXMF.LXMessage.DELIVERED, LXMF.LXMessage.FAILED):
        sent_event.set()

msg.register_delivery_callback(on_state)
msg.register_failed_callback(on_state)
router_tx.handle_outbound(msg)
log("message queued (stamp pre-generated)")

start = time.time()
while not sent_event.is_set():
    elapsed = time.time() - start
    if elapsed > SEND_TIMEOUT: break
    log(f"  send t+{elapsed:.0f}s state={NAMES.get(msg.state,msg.state)} prog={getattr(msg,'progress',0):.0%}")
    sent_event.wait(timeout=10)

sname = NAMES.get(msg.state, str(msg.state))
if msg.state in (LXMF.LXMessage.SENT, LXMF.LXMessage.DELIVERED):
    log(f"PASS: message stored on prop node (state={sname}) ✓")
else:
    log(f"FAIL: send failed (state={sname})"); sys.exit(1)

# ── Receiver: sync from prop node ─────────────────────────────────────────────
log("syncing from prop node...")
router_rx.set_outbound_propagation_node(PROP_NODE_HASH)

received = []
recv_event = threading.Event()

def on_msg(message):
    content = message.content_as_string() if hasattr(message, "content_as_string") else str(message.content)
    log(f"*** MESSAGE RECEIVED: {content}")
    received.append(message)
    recv_event.set()

router_rx.register_delivery_callback(on_msg)
# Register rfed identity so LXMRouter can build the link destination
RNS.Identity.remember(b'\x00' * 16, PROP_NODE_HASH, prop_identity.get_public_key())
router_rx.request_messages_from_propagation_node(rx_identity)

start = time.time()
while not recv_event.is_set():
    elapsed = time.time() - start
    if elapsed > RECV_TIMEOUT: break
    pr = router_rx.propagation_transfer_state
    prog = router_rx.propagation_transfer_progress
    log(f"  sync t+{elapsed:.0f}s pr_state={pr:#x} progress={prog:.0%}")
    recv_event.wait(timeout=5)

if received:
    log(f"PASS: received {len(received)} message(s) ✓")
    sys.exit(0)
else:
    pr = router_rx.propagation_transfer_state
    log(f"FAIL: no message received (pr_state={pr:#x})")
    sys.exit(1)
