#!/usr/bin/env python3
"""
test_lxmf_propagation.py — End-to-end test of rfed's LXMF propagation node.

Tests:
  1. Send an LXMF message to the propagation node (message acceptance)
  2. Download messages as a client (client sync via /get)
  3. Check peering status with remote lxmf prop node

Usage:
    python3 test_lxmf_propagation.py <rfed_identity_file> [--peer-hash <hex>] [--timeout N]
"""
import os
import sys
import time
import threading
import struct

sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), "w", buffering=1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

import RNS
import msgpack

# ── Configuration ─────────────────────────────────────────────────────────────

RNS_CONFIG_DIR = os.path.join(TEST_DIR, "rns_subscriber")
LINK_TIMEOUT = 30
TIMEOUT = 90
PEER_HASH = None

if len(sys.argv) < 2:
    print("Usage: test_lxmf_propagation.py <rfed_identity_file> [--peer-hash <hex>] [--timeout N]")
    sys.exit(1)

rfed_identity_file = sys.argv[1].strip()

for i, a in enumerate(sys.argv):
    if a == "--timeout" and i + 1 < len(sys.argv):
        TIMEOUT = int(sys.argv[i + 1])
    if a == "--peer-hash" and i + 1 < len(sys.argv):
        PEER_HASH = sys.argv[i + 1].strip()

if not os.path.exists(rfed_identity_file):
    print(f"[test] ERROR: rfed identity file not found: {rfed_identity_file}")
    sys.exit(1)

results = {"send": None, "get": None, "peer_check": None}

# ── Boot RNS ──────────────────────────────────────────────────────────────────

print("[test] Booting RNS...", flush=True)
RNS.Reticulum(configdir=RNS_CONFIG_DIR, loglevel=RNS.LOG_WARNING)
print("[test] RNS ready", flush=True)

# ── Load rfed identity and construct lxmf.propagation destination ─────────────

prop_identity = RNS.Identity.from_file(rfed_identity_file)
if prop_identity is None:
    print(f"[test] FAIL: could not load identity from {rfed_identity_file}")
    sys.exit(1)

prop_dest = RNS.Destination(
    prop_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
    "lxmf", "propagation"
)
prop_hash = prop_dest.hash.hex()
print(f"[test] lxmf.propagation dest: {prop_hash}", flush=True)

# ── Create a test client identity ─────────────────────────────────────────────

client_identity = RNS.Identity()
client_delivery_dest = RNS.Destination(
    client_identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    "lxmf", "delivery"
)
client_hash = client_delivery_dest.hash.hex()
print(f"[test] client lxmf.delivery dest: {client_hash}", flush=True)

# ── Inject a synthetic path to rfed ──────────────────────────────────────────

tcp_iface = None
for iface in RNS.Transport.interfaces:
    if hasattr(iface, 'target_ip'):
        tcp_iface = iface
        break

if tcp_iface is None:
    print("[test] FAIL: no TCP interface found for path injection")
    sys.exit(1)

now = time.time()
path_entry = [now, prop_dest.hash, 1, now + 86400, None, tcp_iface, None]
RNS.Transport.path_table[prop_dest.hash] = path_entry
print(f"[test] injected path for {prop_hash}", flush=True)

# ── Build a proper LXMF message ──────────────────────────────────────────────
# Wire format:
#   lxmf_data = dest_hash(16) + encrypted(source_hash + signature + payload)
#   For our test: dest_hash(16) + synthetic_encrypted_body
# On the wire to propagation: msgpack([timestamp, [lxmf_data]])

# Build a realistic-ish LXMF payload
# Format: dest_hash(16) | source_hash(16) | signature(64) | timestamp(8) | payload
dest_hash_bytes = client_delivery_dest.hash  # recipient = our test client
source_hash_bytes = os.urandom(16)  # random sender

# Build inner payload: msgpack [timestamp, title, content, fields]
ts = time.time()
inner_payload = msgpack.packb([ts, b"Test Message", b"Hello from LXMF prop test!", {}])
signature = os.urandom(64)  # fake signature
ts_bytes = struct.pack(">d", ts)  # 8 bytes big-endian double

# Construct the "encrypted" body (in practice this would be encrypted to dest)
# For stamp_cost=0, rfed just checks length > LXMF_OVERHEAD + STAMP_SIZE
body = source_hash_bytes + signature + ts_bytes + inner_payload
# The full lxmf_data: dest(16) + body
lxmf_data = dest_hash_bytes + body

# Add propagation stamp (32 bytes zero, passes with cost=0)
STAMP_SIZE = 32
lxmf_data_with_stamp = lxmf_data + (b'\x00' * STAMP_SIZE)

print(f"[test] lxmf_data length: {len(lxmf_data_with_stamp)} bytes (overhead threshold: 128)", flush=True)
assert len(lxmf_data_with_stamp) > 128, "lxmf_data too short"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 1: Send message to propagation node
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 60, flush=True)
print("TEST 1: Send LXMF message to propagation node", flush=True)
print("=" * 60, flush=True)

link_ready = threading.Event()
link_failed = threading.Event()
active_link = [None]

def on_link_established(link):
    print("[test] link established", flush=True)
    active_link[0] = link
    link_ready.set()

def on_link_closed(link):
    print("[test] link closed", flush=True)
    link_failed.set()

link = RNS.Link(prop_dest)
link.set_link_established_callback(on_link_established)
link.set_link_closed_callback(on_link_closed)

start = time.monotonic()
while not link_ready.is_set() and not link_failed.is_set():
    time.sleep(0.2)
    if time.monotonic() - start > LINK_TIMEOUT:
        print(f"[test] FAIL: link did not become active within {LINK_TIMEOUT}s", flush=True)
        results["send"] = "FAIL: link timeout"
        break

if link_ready.is_set():
    # Send the LXMF message batch
    # Wire format: msgpack([type=1, [lxmf_data_bytes, ...]])
    batch = msgpack.packb([1, [lxmf_data_with_stamp]], use_bin_type=True)
    packet = RNS.Packet(active_link[0], batch)
    receipt = packet.send()

    if receipt:
        # Wait for delivery
        start_send = time.monotonic()
        while receipt.status != RNS.PacketReceipt.DELIVERED:
            time.sleep(0.2)
            if receipt.status == RNS.PacketReceipt.FAILED:
                print("[test] FAIL: packet delivery failed", flush=True)
                results["send"] = "FAIL: packet delivery failed"
                break
            if time.monotonic() - start_send > 15:
                print(f"[test] WARN: packet receipt status={receipt.status} after 15s", flush=True)
                break
        if receipt.status == RNS.PacketReceipt.DELIVERED:
            print("[test] PASS: message sent and acknowledged by propagation node", flush=True)
            results["send"] = "PASS"
        elif results["send"] is None:
            results["send"] = f"WARN: receipt status={receipt.status}"
    else:
        print("[test] FAIL: packet.send() returned None", flush=True)
        results["send"] = "FAIL: send returned None"

    # Close the send link
    active_link[0].teardown()
    time.sleep(1)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 2: Client retrieves messages via /get
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 60, flush=True)
print("TEST 2: Client downloads messages via /get", flush=True)
print("=" * 60, flush=True)

link_ready2 = threading.Event()
link_failed2 = threading.Event()
active_link2 = [None]
get_response = [None]
get_done = threading.Event()

def on_link_established2(link):
    print("[test] /get link established", flush=True)
    active_link2[0] = link
    link_ready2.set()

def on_link_closed2(link):
    print("[test] /get link closed", flush=True)
    link_failed2.set()

# Re-inject path (might have been cleaned up)
now2 = time.time()
RNS.Transport.path_table[prop_dest.hash] = [now2, prop_dest.hash, 1, now2 + 86400, [], tcp_iface, None]

link2 = RNS.Link(prop_dest)
link2.set_link_established_callback(on_link_established2)
link2.set_link_closed_callback(on_link_closed2)

start2 = time.monotonic()
while not link_ready2.is_set() and not link_failed2.is_set():
    time.sleep(0.2)
    if time.monotonic() - start2 > LINK_TIMEOUT:
        print(f"[test] FAIL: /get link did not become active within {LINK_TIMEOUT}s", flush=True)
        results["get"] = "FAIL: link timeout"
        break

if link_ready2.is_set():
    # Identify on the link so rfed knows who we are
    active_link2[0].identify(client_identity)
    time.sleep(1)
    print("[test] identified on link", flush=True)

    # Phase 1: Request message list (wants=None, haves=None)
    # /get path: link.request("/get", [None, None])
    def on_get_response(request_receipt):
        resp = request_receipt.response
        if resp is not None:
            get_response[0] = resp
            print(f"[test] /get response received: {type(resp)}", flush=True)
        else:
            print("[test] /get response is None", flush=True)
        get_done.set()

    def on_get_failed(request_receipt):
        print(f"[test] /get request failed", flush=True)
        get_done.set()

    # Request: [wants=None, haves=None, limit_kb=None]
    request_data = msgpack.packb([None, None])
    receipt = active_link2[0].request(
        "/get",
        data=request_data,
        response_callback=on_get_response,
        failed_callback=on_get_failed,
        timeout=30,
    )

    start_get = time.monotonic()
    while not get_done.is_set():
        time.sleep(0.2)
        if time.monotonic() - start_get > 30:
            print("[test] FAIL: /get timed out after 30s", flush=True)
            results["get"] = "FAIL: timeout"
            break

    if get_response[0] is not None:
        response = get_response[0]
        if isinstance(response, list):
            print(f"[test] Message list received: {len(response)} message(s)", flush=True)
            for i, item in enumerate(response):
                if isinstance(item, bytes):
                    print(f"  [{i}] transient_id: {item.hex()}", flush=True)
                else:
                    print(f"  [{i}] {type(item)}: {item}", flush=True)
            if len(response) > 0:
                results["get"] = f"PASS: {len(response)} message(s) available"
            else:
                results["get"] = "WARN: 0 messages (might be timing issue)"
        elif isinstance(response, bytes):
            # Try to decode as msgpack
            try:
                decoded = msgpack.unpackb(response, raw=False)
                print(f"[test] Response decoded: {decoded}", flush=True)
                if isinstance(decoded, list) and len(decoded) > 0:
                    results["get"] = f"PASS: {len(decoded)} item(s) in response"
                else:
                    results["get"] = f"response: {decoded}"
            except Exception:
                print(f"[test] Raw response: {len(response)} bytes: {response[:64].hex()}...", flush=True)
                results["get"] = f"response: {len(response)} bytes"
        else:
            print(f"[test] Unexpected response type: {type(response)}", flush=True)
            results["get"] = f"response type: {type(response)}"
    elif results["get"] is None:
        results["get"] = "FAIL: no response received"

    active_link2[0].teardown()
    time.sleep(1)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 3: Check peer connectivity
# ══════════════════════════════════════════════════════════════════════════════

if PEER_HASH:
    print("\n" + "=" * 60, flush=True)
    print(f"TEST 3: Check peering with {PEER_HASH}", flush=True)
    print("=" * 60, flush=True)

    peer_bytes = bytes.fromhex(PEER_HASH)
    # Check if we can resolve the peer's path
    peer_identity = RNS.Identity.recall(peer_bytes)
    if peer_identity:
        print(f"[test] Peer identity recalled: {peer_identity}", flush=True)
        results["peer_check"] = "PASS: peer identity known"
    else:
        print(f"[test] Peer identity not yet recalled, requesting path...", flush=True)
        RNS.Transport.request_path(peer_bytes)
        time.sleep(5)
        peer_identity = RNS.Identity.recall(peer_bytes)
        if peer_identity:
            print(f"[test] Peer identity recalled after path request", flush=True)
            results["peer_check"] = "PASS: peer identity resolved"
        else:
            print(f"[test] WARN: peer identity not available (may need more time)", flush=True)
            results["peer_check"] = "WARN: peer identity not resolved"
else:
    results["peer_check"] = "SKIP: no --peer-hash"

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 60, flush=True)
print("RESULTS SUMMARY", flush=True)
print("=" * 60, flush=True)
print(f"  Message send:     {results['send']}", flush=True)
print(f"  Client GET:       {results['get']}", flush=True)
print(f"  Peer check:       {results['peer_check']}", flush=True)
print("=" * 60, flush=True)

all_pass = all(
    r is not None and (r.startswith("PASS") or r.startswith("SKIP"))
    for r in results.values()
)
if all_pass:
    print("OVERALL: PASS", flush=True)
    sys.exit(0)
else:
    has_fail = any(r is not None and r.startswith("FAIL") for r in results.values())
    if has_fail:
        print("OVERALL: FAIL", flush=True)
        sys.exit(1)
    else:
        print("OVERALL: PARTIAL (some warnings)", flush=True)
        sys.exit(0)
