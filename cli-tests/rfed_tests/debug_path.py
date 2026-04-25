#!/usr/bin/env python3
import sys, os, time

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)
from channel_hash import AnnounceHandler

import RNS

RNS.Reticulum(configdir=os.path.join(TEST_DIR, "rns_publisher"))

node_hash = bytes.fromhex("8c7ca26f7b4f640cc05a9f55494b3392")
ch_hash = bytes.fromhex("adbb9fb6a9d338594cd29e005c461dbc")

# Register announce handler
def on_announce(dest_hash, announced_identity, app_data, ann_hash, is_path):
    print(f"[ANNOUNCE] dest={dest_hash.hex()} is_path={is_path} identity={announced_identity}", flush=True)

RNS.Transport.register_announce_handler(
    AnnounceHandler(aspect_filter=None, callback=on_announce, receive_path_responses=True)
)

time.sleep(2)
print(f"after 2s: has_path(node)={RNS.Transport.has_path(node_hash)}", flush=True)
print(f"          has_path(ch)={RNS.Transport.has_path(ch_hash)}", flush=True)
print(f"          recall(node)={RNS.Identity.recall(node_hash)}", flush=True)
print("requesting path to node...", flush=True)
RNS.Transport.request_path(node_hash)
for i in range(8):
    time.sleep(1)
    hp_node = RNS.Transport.has_path(node_hash)
    hp_ch = RNS.Transport.has_path(ch_hash)
    id_n = RNS.Identity.recall(node_hash)
    id_c = RNS.Identity.recall(ch_hash)
    print(f"t={i+1}s node: has_path={hp_node} identity={id_n} | ch: has_path={hp_ch} identity={id_c}", flush=True)
    if hp_node:
        break
print("done", flush=True)
