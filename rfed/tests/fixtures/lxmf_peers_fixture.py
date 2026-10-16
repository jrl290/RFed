"""Write lxmf_1_1_1_peers.bin: a peers file as LXMF 1.1.1 writes it.

LXMRouter.exit_handler packs a list of LXMPeer.to_bytes() records. This builds
one peer with LXMF's own LXMPeer, on a stand-in for the router that holds only
what to_bytes reads (propagation_entries), and packs it the same way. The
rfed test `peers_file_tests::reads_and_writes_what_lxmf_writes` stores the
same three messages, loads this file and saves it again, byte for byte.

Run with the workspace venv (LXMF 1.1.1):
    .venv/bin/python RFed-rust/rfed/tests/fixtures/lxmf_peers_fixture.py
"""

import hashlib
import os

import LXMF
import RNS.vendor.umsgpack as msgpack
from LXMF.LXMPeer import LXMPeer

assert LXMF.__version__ == "1.1.1", LXMF.__version__


def message(n):
    """The test's message n: for destination 5e5e..., 300 bytes, no stamp."""
    lxmf = bytes([0x5E] * 16) + bytes([n] * 284)
    return hashlib.sha256(lxmf).digest()


class Router:
    def __init__(self, transient_ids):
        # LXMRouter.propagation_entries, in store order.
        self.propagation_entries = {
            tid: [bytes([0x5E] * 16), "", 1760000000.0 + n, 300, [], [], 0]
            for n, tid in enumerate(transient_ids)
        }


ids = [message(n) for n in range(3)]
router = Router(ids)
peer = LXMPeer(router, bytes([0x1D] * 16))
peer.peering_timebase = 1760000000
peer.alive = True
peer.metadata = {LXMF.PN_META_NAME: b"lxmf fixture"}
peer.last_heard = 1760000123.5
peer.peering_key = [bytes([0x5A] * 32), 18]
peer.sync_transfer_rate = 1234.5
peer.propagation_transfer_limit = 256
peer.propagation_sync_limit = 10240
peer.propagation_stamp_cost = 16
peer.propagation_stamp_cost_flexibility = 3
peer.peering_cost = 18
peer.last_sync_attempt = 1760000100.25
peer.add_handled_message(ids[0])
peer.add_unhandled_message(ids[1])
peer.add_unhandled_message(ids[2])

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lxmf_1_1_1_peers.bin")
with open(out, "wb") as f:
    f.write(msgpack.packb([peer.to_bytes()]))
print(out)
