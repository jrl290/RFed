#!/usr/bin/env python3
"""
lxmf_prop_sender.py — Send a minimal LXMF propagation batch to rfed.

Usage:
    lxmf_prop_sender.py <rfed_identity_file> <subscriber_hash_hex> [--timeout N]

What it does:
  1. Loads the rfed identity from file to construct the lxmf.propagation destination.
  2. Opens a Reticulum Link to it.
  3. Sends a minimal LXMF propagation batch whose recipient hash is
     <subscriber_hash_hex>.  rfed will see the recipient, look it up in the
     notify registry, and fire a wake-up packet to the registered relay.

Wire format (matches lxmf_propagation_notification.rs expectations):
  - Outer envelope: msgpack [type:int, messages:[[lxmf_payload:bytes], ...]]
  - lxmf_payload:
      bytes  0-15  recipient destination hash  (16 bytes, plaintext)
      bytes 16-31  sender destination hash     (16 bytes, zeroed)
      bytes 32-95  signature placeholder       (64 bytes, zeroed)
      bytes 96-103 timestamp placeholder       (8 bytes,  zeroed)
      bytes 104-111 struct overhead            (8 bytes,  zeroed)
      bytes 112-143 PN stamp                   (32 bytes, zeroed)
    Total: 144 bytes (> LXMF_OVERHEAD(96) + STAMP_SIZE(32) = 128  ✓)
  - With rfed stamp_cost=0, min_cost=0, any stamp value passes.

Exit codes:
  0  — batch delivered to rfed propagation link
  1  — timeout or failure
"""
import os
import sys
import time
import threading

sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

import RNS
import msgpack

# ── Configuration ─────────────────────────────────────────────────────────────

RNS_CONFIG_DIR = os.path.join(TEST_DIR, "rns_subscriber")  # reuse subscriber config
LINK_TIMEOUT   = 30   # seconds to wait for link to become ACTIVE
TIMEOUT        = 60

if len(sys.argv) < 3:
    print("Usage: lxmf_prop_sender.py <rfed_identity_file> <subscriber_hash_hex> [--timeout N]")
    sys.exit(1)

for i, a in enumerate(sys.argv):
    if a == "--timeout" and i + 1 < len(sys.argv):
        TIMEOUT = int(sys.argv[i + 1])

rfed_identity_file   = sys.argv[1].strip()
subscriber_hash_hex  = sys.argv[2].strip()

if not os.path.exists(rfed_identity_file):
    print(f"[sender] ERROR: rfed identity file not found: {rfed_identity_file}")
    sys.exit(1)
if len(subscriber_hash_hex) != 32:
    print(f"[sender] ERROR: subscriber_hash must be 32 hex chars, got {len(subscriber_hash_hex)}")
    sys.exit(1)

subscriber_hash   = bytes.fromhex(subscriber_hash_hex)

# ── Build the LXMF payload ────────────────────────────────────────────────────
#
# lx_stamper.rs validate_pn_stamp check:
#   len(data) > LXMF_OVERHEAD(112) + STAMP_SIZE(32) = 144
# We need len > 144.
#
# LXMF_OVERHEAD = 2*DESTINATION_LENGTH(16) + SIGNATURE_LENGTH(64) + TIMESTAMP_SIZE(8) + STRUCT_OVERHEAD(8) = 112
# With rfed stamp_cost=0: min_cost=0, stamp_valid always returns True,
# so the 32-byte zero stamp at the end passes unconditionally.

LXMF_OVERHEAD = 112  # 2*16 (hashes) + 64 (sig) + 8 (ts) + 8 (struct)
STAMP_SIZE    = 32   # HASHLENGTH(256) / 8

lxmf_payload = (
    subscriber_hash          +  # bytes  0-15:  recipient dest hash (plaintext)
    b'\x00' * (LXMF_OVERHEAD - 16) +  # bytes 16-111: sender/sig/ts/struct (zeroed)
    b'\x01'                  +  # byte  112:    at least 1 byte of content (> OVERHEAD+STAMP)
    b'\x00' * STAMP_SIZE     )  # bytes 113-144: PN stamp (zeroed, cost=0 → always valid)

assert len(lxmf_payload) == LXMF_OVERHEAD + 1 + STAMP_SIZE  # 145 > 144 ✓

batch = msgpack.packb([1, [lxmf_payload]], use_bin_type=True)

print(f"[sender] identity   : {rfed_identity_file}", flush=True)
print(f"[sender] subscriber : {subscriber_hash_hex}", flush=True)
print(f"[sender] payload    : {len(lxmf_payload)} bytes", flush=True)

# ── Boot RNS ──────────────────────────────────────────────────────────────────

RNS.Reticulum(configdir=RNS_CONFIG_DIR)
print("[sender] RNS ready", flush=True)

# ── Load rfed identity and construct destination directly ─────────────────────

prop_identity = RNS.Identity.from_file(rfed_identity_file)
if prop_identity is None:
    print(f"[sender] FAIL: could not load identity from {rfed_identity_file}")
    sys.exit(1)

prop_dest = RNS.Destination(
    prop_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "lxmf", "propagation"
)
print(f"[sender] constructed lxmf.propagation dest: {prop_dest.hash.hex()}", flush=True)

# ── Inject a synthetic path so RNS.Link can route to rfed ─────────────────────
# rfed's path responses go to the upstream interface, not back to the local
# client; so path_request never succeeds.  Work around it by inserting a
# direct-hop path entry pointing at the first TCP interface we see.

tcp_iface = None
for iface in RNS.Transport.interfaces:
    if hasattr(iface, 'target_ip'):
        tcp_iface = iface
        break

if tcp_iface is None:
    print("[sender] FAIL: no TCP interface found for path injection")
    sys.exit(1)

# Python Transport path_table entry format (from Transport.py):
#   [timestamp, next_hop, hops, expires, recv_interface, packet_hash]
# IDX: 0=timestamp, 1=next_hop, 2=hops, 3=expires, 4=random_blobs, 5=recv_interface, 6=packet_hash
now = time.time()
path_entry = [
    now,                          # IDX_PT_TIMESTAMP(0)
    prop_dest.hash,               # IDX_PT_NEXT_HOP(1) = destination itself (direct)
    1,                            # IDX_PT_HOPS(2)
    now + 86400,                  # IDX_PT_EXPIRES(3)
    None,                         # IDX_PT_RANDBLOBS(4)
    tcp_iface,                    # IDX_PT_RVCD_IF(5) = the TCP interface
    None,                         # IDX_PT_PACKET(6)
]
RNS.Transport.path_table[prop_dest.hash] = path_entry
print(f"[sender] injected direct path ({tcp_iface}) for {prop_dest.hexhash}", flush=True)
print(f"[sender] opening link to lxmf.propagation...", flush=True)

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

# ── Send the LXMF propagation batch ───────────────────────────────────────────

lnk = active_link[0]
print(f"[sender] sending batch ({len(batch)} bytes packed) on link...", flush=True)
pkt = RNS.Packet(lnk, batch)
result = pkt.send()

if result:
    print(f"[sender] OK: batch sent — rfed should fire notify for {subscriber_hash_hex}", flush=True)
    # Give the link a moment to flush before we exit.
    time.sleep(2)
    sys.exit(0)
else:
    print("[sender] FAIL: Packet.send() returned False", flush=True)
    sys.exit(1)
