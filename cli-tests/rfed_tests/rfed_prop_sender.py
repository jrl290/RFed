#!/usr/bin/env python3
"""
rfed_prop_sender.py — Send an LXMF propagation batch to rfed for Scenario 7.

Reads the subscriber identity hash from rfed_data/prop_receiver_hash.txt
(written by rfed_prop_receiver.py), then sends a minimal LXMF propagation
batch to rfed's lxmf.propagation destination with that hash as the recipient.

rfed sees the recipient hash, looks it up in the notify registry, and fires
a wake-up packet to the registered relay (rfed_prop_receiver.py).

Usage:
    rfed_prop_sender.py <rfed_node_hash_hex> [--timeout N]

Wire format matches lxmf_prop_sender.py expectations:
  Outer:  msgpack [type:int, messages:[[lxmf_payload:bytes], ...]]
  lxmf_payload bytes 0-15:   recipient identity hash  (plaintext)
  bytes 16-143:              zeroed sender/sig/ts/overhead fields
  With rfed stamp_cost=0 all zero stamps are accepted.

Exit codes:
  0 — batch delivered to rfed lxmf.propagation link
  1 — timeout or failure
"""
import os, sys, time, threading
sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)

from channel_hash import ensure_config_dir, sandbox_path

import RNS
import msgpack

# ── Config ────────────────────────────────────────────────────────────────────

TEST_NS           = os.environ.get("RFED_TEST_NAMESPACE", "default")
RNS_CONFIG_DIR    = ensure_config_dir(f"rns_prop_sender_{TEST_NS}", template="rns_prop_sender")
DATA_DIR          = sandbox_path("rfed_data")
IDENTITY_FILE     = os.path.join(DATA_DIR, "identity")
RECEIVER_HASH_FILE = os.path.join(DATA_DIR, "prop_receiver_delivery_hash.txt")
LINK_TIMEOUT      = 30
TIMEOUT           = 60

if len(sys.argv) < 2:
    print("Usage: rfed_prop_sender.py <rfed_node_hash_hex> [--timeout N] [--rns-config DIR]")
    sys.exit(1)

for i, a in enumerate(sys.argv):
    if a == "--timeout" and i + 1 < len(sys.argv):
        TIMEOUT = int(sys.argv[i + 1])
    elif a == "--rns-config" and i + 1 < len(sys.argv):
        RNS_CONFIG_DIR = sys.argv[i + 1]

rfed_node_hash_arg = sys.argv[1].strip()

# ── Read subscriber hash ──────────────────────────────────────────────────────

if not os.path.exists(RECEIVER_HASH_FILE):
    print(f"[sender] ERROR: {RECEIVER_HASH_FILE} not found — run rfed_prop_receiver.py first")
    sys.exit(1)

subscriber_hash_hex = open(RECEIVER_HASH_FILE).read().strip()
if len(subscriber_hash_hex) != 32:
    print(f"[sender] ERROR: prop_receiver_delivery_hash.txt has bad length ({len(subscriber_hash_hex)})")
    sys.exit(1)

subscriber_hash = bytes.fromhex(subscriber_hash_hex)
print(f"[sender] subscriber lxmf.delivery hash: {subscriber_hash_hex}", flush=True)

# ── Build the LXMF payload ────────────────────────────────────────────────────
#
# rfed's lxmf_propagation handler extracts the first 16 bytes as the
# recipient dest hash, looks it up in the notify registry, and fires notify.
# With stamp_cost=0 the zero stamp always passes.

LXMF_OVERHEAD = 112   # 2×16 (hashes) + 64 (sig) + 8 (ts) + 8 (struct)
STAMP_SIZE    = 32

lxmf_payload = (
    subscriber_hash                        +  # bytes   0-15: recipient hash
    b'\x00' * (LXMF_OVERHEAD - 16)        +  # bytes  16-111: zeroed fields
    b'\x01'                                +  # byte  112: 1 content byte (len > OVERHEAD+STAMP)
    b'\x00' * STAMP_SIZE                   )  # bytes 113-144: zero stamp (cost=0 passes)

assert len(lxmf_payload) == LXMF_OVERHEAD + 1 + STAMP_SIZE

batch = msgpack.packb([1, [lxmf_payload]], use_bin_type=True)
print(f"[sender] payload: {len(lxmf_payload)} bytes  batch: {len(batch)} bytes packed", flush=True)

# ── Boot RNS ──────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR)
print("[sender] RNS ready", flush=True)

# ── Load rfed identity and construct lxmf.propagation destination ─────────────

if not os.path.exists(IDENTITY_FILE):
    print(f"[sender] ERROR: rfed identity not found at {IDENTITY_FILE}")
    sys.exit(1)

prop_identity = RNS.Identity.from_file(IDENTITY_FILE)
if prop_identity is None:
    print(f"[sender] ERROR: could not load rfed identity from {IDENTITY_FILE}")
    sys.exit(1)

prop_dest = RNS.Destination(
    prop_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "lxmf", "propagation"
)
print(f"[sender] lxmf.propagation dest: {prop_dest.hash.hex()}", flush=True)

# ── Inject a direct path so RNS.Link can route without waiting for propagation ─
# rfed acts as its own router (no separate rnsd), so path responses go back
# directly over the TCP interface.  Insert a synthetic direct-hop path entry.

tcp_iface = None
for iface in RNS.Transport.interfaces:
    if hasattr(iface, 'target_ip'):
        tcp_iface = iface
        break

if tcp_iface is None:
    print("[sender] FAIL: no TCP interface found")
    sys.exit(1)

now = time.time()
path_entry = [
    now,             # IDX_PT_TIMESTAMP
    prop_dest.hash,  # IDX_PT_NEXT_HOP (direct — the destination itself)
    1,               # IDX_PT_HOPS
    now + 86400,     # IDX_PT_EXPIRES
    None,            # IDX_PT_RANDBLOBS
    tcp_iface,       # IDX_PT_RVCD_IF
    None,            # IDX_PT_PACKET
]
RNS.Transport.path_table[prop_dest.hash] = path_entry
print(f"[sender] injected direct path via {tcp_iface} for {prop_dest.hexhash}", flush=True)

# ── Open link and send the batch ──────────────────────────────────────────────

link_ready  = threading.Event()
link_failed = threading.Event()
active_link = [None]

def on_link_established(link):
    print("[sender] link established", flush=True)
    active_link[0] = link
    link_ready.set()

def on_link_closed(link):
    print("[sender] link closed", flush=True)
    link_failed.set()

print("[sender] opening link to lxmf.propagation...", flush=True)
link = RNS.Link(prop_dest)
link.set_link_established_callback(on_link_established)
link.set_link_closed_callback(on_link_closed)

start = time.monotonic()
while not link_ready.is_set() and not link_failed.is_set():
    time.sleep(0.2)
    if time.monotonic() - start > LINK_TIMEOUT:
        print(f"[sender] FAIL: link did not become active within {LINK_TIMEOUT}s")
        sys.exit(1)

if link_failed.is_set():
    print("[sender] FAIL: link closed before becoming active")
    sys.exit(1)

lnk = active_link[0]
print(f"[sender] sending batch on link...", flush=True)
pkt = RNS.Packet(lnk, batch)
result = pkt.send()

if result:
    print(f"[sender] OK: batch sent — rfed should fire notify for {subscriber_hash_hex}", flush=True)
    time.sleep(2)  # let the link flush before exit
    sys.exit(0)
else:
    print("[sender] FAIL: Packet.send() returned False", flush=True)
    sys.exit(1)
