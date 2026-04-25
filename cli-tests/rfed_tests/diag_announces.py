#!/usr/bin/env python3
"""Diagnostic: listen for all announces from the subscriber perspective."""
import RNS, time, os, sys
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TEST_DIR)

NOTIFY = bytes.fromhex('0e964f6233736c2adb1b899e50e5bcae')
NODE   = bytes.fromhex('8c7ca26f7b4f640cc05a9f55494b3392')

class AllAnnounces:
    aspect_filter = None
    receive_path_responses = True

    def received_announce(self, destination_hash, announced_identity, app_data,
                          announce_packet_hash=None, is_path_response=False):
        label = ''
        if destination_hash == NOTIFY: label = '  <<< rfed.NOTIFY!'
        if destination_hash == NODE:   label = '  <<< rfed.NODE!'
        print(f'ANN: {destination_hash.hex()} id={announced_identity is not None} path_resp={is_path_response}{label}', flush=True)

RNS.Reticulum(configdir=os.path.join(TEST_DIR, 'rns_subscriber'), loglevel=RNS.LOG_WARNING)
RNS.Transport.register_announce_handler(AllAnnounces())

print('[diag] Requesting paths for rfed.notify and rfed.node...')
RNS.Transport.request_path(NOTIFY)
RNS.Transport.request_path(NODE)

print('[diag] Listening 30 seconds for all announces...')
time.sleep(30)

print(f'\n[diag] has_path notify: {RNS.Transport.has_path(NOTIFY)}')
print(f'[diag] has_path node:   {RNS.Transport.has_path(NODE)}')
