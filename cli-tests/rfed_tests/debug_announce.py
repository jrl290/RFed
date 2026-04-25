#!/usr/bin/env python3
"""
Test if rfed (Rust) announces are received by Python RNS clients.
Run AFTER rnsd is started but BEFORE rfed starts (or right as rfed starts).

Usage:
    Step 1: start rnsd
    Step 2: run this script (it will wait for announces)
    Step 3: start rfed
    Observe: does on_announce fire?
"""
import sys, os, time

root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, root)

import RNS

RNS.Reticulum(configdir=os.path.join(os.path.dirname(os.path.abspath(__file__)), "rns_subscriber"))
print("[listener] RNS ready. Listening for any announces...", flush=True)

class AnyAnnounceHandler:
    aspect_filter = None
    receive_path_responses = True

    def received_announce(self, dest_hash, announced_identity, app_data, ann_hash=None, is_path_response=None):
        print(f"[listener] GOT ANNOUNCE: dest={dest_hash.hex()} is_path={is_path_response} identity={announced_identity}", flush=True)
        if app_data:
            print(f"[listener]   app_data={app_data!r}", flush=True)

RNS.Transport.register_announce_handler(AnyAnnounceHandler())
print("[listener] announce handler registered. Waiting 60s...", flush=True)
time.sleep(60)
print("[listener] done", flush=True)
