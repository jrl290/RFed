#!/usr/bin/env python3
"""Simple standalone LXMF receiver — connects directly to NAS, no rfed."""
import sys, os, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../LXMF-master'))

import RNS
import LXMF

CONFIGDIR    = os.path.join(os.path.dirname(__file__), 'rns_node')
IDENTITY_FILE = os.path.join(os.path.dirname(__file__), 'rns_subscriber/sub_identity')
STORAGE_PATH = '/tmp/simple_lxmf_rx_storage'

def message_received(message):
    print(f"\n[RX] Message from: {RNS.prettyhexrep(message.source_hash)}")
    print(f"[RX] Content: {message.content_as_string()}")

print("[*] Starting RNS...")
RNS.Reticulum(configdir=CONFIGDIR, loglevel=RNS.LOG_WARNING)

print("[*] Loading identity...")
identity = RNS.Identity.from_file(IDENTITY_FILE)
print(f"[*] Identity hash : {identity.hash.hex()}")

print("[*] Starting LXMF router...")
router = LXMF.LXMRouter(storagepath=STORAGE_PATH, enforce_stamps=False)
dest = router.register_delivery_identity(identity, display_name="SimpleRx")
router.register_delivery_callback(message_received)

print(f"[*] LXMF delivery dest : {dest.hash.hex()}")
print("[*] Announcing...")

while True:
    router.announce(dest.hash)
    print("[*] Announced — waiting for messages (Ctrl+C to exit)...")
    time.sleep(15)
