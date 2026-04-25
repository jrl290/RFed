#!/usr/bin/env python3
"""Minimal diagnostic: can we establish a raw RNS link to rfed's lxmf.propagation destination?"""
import sys, time, threading

sys.path.insert(0, '/Users/james/Library/CloudStorage/SynologyDrive-Development/Rust/Reticulum/Reticulum-master')
import RNS

PROP_HASH = bytes.fromhex("0f75ac15961b7d2b1577a57bdb1fda3c")
RNS_CONFIG = '/Users/james/Library/CloudStorage/SynologyDrive-Development/Rust/Reticulum/cli-tests/rfed_tests/rns_client_ext'

RNS.Reticulum(configdir=RNS_CONFIG)
print("RNS ready")

# Request fresh path and wait up to 10s
RNS.Transport.request_path(PROP_HASH)
deadline = time.time() + 10
while time.time() < deadline:
    if RNS.Transport.has_path(PROP_HASH): break
    time.sleep(0.3)

hp    = RNS.Transport.has_path(PROP_HASH)
ident = RNS.Identity.recall(PROP_HASH)
print(f"has_path={hp}, identity={'yes:'+ident.hash.hex() if ident else 'no'}")

if not ident or not hp:
    print("DIAG FAIL: no path or identity")
    sys.exit(1)

dest = RNS.Destination(ident, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "propagation")
print(f"dest hash: {dest.hash.hex()}")
print(f"dest hash matches input: {dest.hash.hex() == PROP_HASH.hex()}")

link_event = threading.Event()
link_result = [None]

def on_established(link):
    print(f"LINK ESTABLISHED: {link}")
    link_result[0] = link
    link_event.set()

link = RNS.Link(dest)
link.set_link_established_callback(on_established)
print("link request sent, waiting up to 45s...")

link_event.wait(timeout=45)
if link_result[0]:
    print("SUCCESS: link established to rfed propagation dest!")
else:
    print(f"FAIL: link establishment timed out (status={link.status})")
sys.exit(0 if link_result[0] else 1)

import RNS

RNS_CONFIG_DIR = os.path.join(TEST_DIR, "rns_subscriber")
RFED_NOTIFY_HASH = bytes.fromhex("0e964f6233736c2adb1b899e50e5bcae")

print("[diag] Starting RNS...", flush=True)
RNS.Reticulum(configdir=RNS_CONFIG_DIR, loglevel=RNS.LOG_DEBUG)

# Check if identity already known
known = RNS.Identity.recall(RFED_NOTIFY_HASH)
print(f"[diag] Identity.recall for rfed.notify: {known}", flush=True)

# Register announce handler to detect when announce arrives
announce_received = threading.Event()

class AH:
    aspect_filter = "rfed.notify"
    receive_path_responses = True
    def received_announce(self, destination_hash, announced_identity, app_data, announce_packet_hash=None, is_path_response=False):
        print(f"[diag] ANNOUNCE RECEIVED: hash={destination_hash.hex()} identity={announced_identity} is_path_response={is_path_response}", flush=True)
        if announced_identity is not None:
            announce_received.set()

RNS.Transport.register_announce_handler(AH())

# Request path
print("[diag] Requesting path for rfed.notify...", flush=True)
RNS.Transport.request_path(RFED_NOTIFY_HASH)

# Wait for announce
print("[diag] Waiting 15s for announce...", flush=True)
got_announce = announce_received.wait(timeout=15)
print(f"[diag] Announce received: {got_announce}", flush=True)

# Try to get identity
known = RNS.Identity.recall(RFED_NOTIFY_HASH)
print(f"[diag] Identity after wait: {known}", flush=True)

if known is None:
    print("[diag] ERROR: no identity found - cannot open link", flush=True)
    sys.exit(1)

# Try to open link
dest = RNS.Destination(known, RNS.Destination.OUT, RNS.Destination.SINGLE, "rfed", "notify")
print(f"[diag] Destination hash: {dest.hash.hex()}", flush=True)

link_active = threading.Event()
link_obj = [None]

def on_link_established(l):
    print(f"[diag] LINK ESTABLISHED! link_id={l.link_id.hex()}", flush=True)
    link_obj[0] = l
    link_active.set()

link = RNS.Link(dest, established_callback=on_link_established)
print(f"[diag] Link object created, waiting 15s...", flush=True)
activated = link_active.wait(timeout=15)
print(f"[diag] Link activated: {activated}", flush=True)

if activated:
    print("[diag] SUCCESS: link established", flush=True)
    link_obj[0].teardown()
else:
    print(f"[diag] FAILED: link status={link.status}", flush=True)
