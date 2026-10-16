"""Check that LXMF 1.1.1 reads a `locally_processed` file rfed saved, and
acts on it as on its own: each id is held until 180 days after it was
received, and a message whose id is held is not stored again.

LXMRouter.__init__ reads the file inline (msgpack.unpackb, then a dict check);
this does the same with LXMF's msgpack, then runs LXMF's own
clean_transient_id_caches and lxmf_propagation on a stand-in router holding
what they read.

    .venv/bin/python RFed-rust/rfed/tests/fixtures/lxmf_loads_rfed_locally_processed.py \
        <rfed config dir>/lxmf_propagation/locally_processed [<lxmf_data file>]

With a message file (an LXMF message as rfed's messagestore keeps it, the
32-byte stamp at its end), the message must be refused when its id is held.
"""

import os
import sys
import tempfile
import threading
import time

import LXMF
import RNS
import RNS.vendor.umsgpack as msgpack
from LXMF.LXMRouter import LXMRouter

assert LXMF.__version__ == "1.1.1", LXMF.__version__

path = sys.argv[1]
with open(path, "rb") as f:
    data = f.read()
loaded = msgpack.unpackb(data)
assert type(loaded) == dict, f"LXMRouter would drop it: {type(loaded)}"
assert all(type(k) == bytes and len(k) == 32 for k in loaded), "every key a 32-byte id"
assert all(type(v) == float for v in loaded.values()), "every value a float time"
print(f"{len(loaded)} ids, received {min(loaded.values(), default=0):.0f}..{max(loaded.values(), default=0):.0f}")


class Router:
    pass


router = Router()
router.locally_processed_transient_ids = dict(loaded)
router.locally_delivered_transient_ids = {}
router.processed_transient_ids_lock = threading.Lock()
router.delivered_transient_ids_lock = threading.Lock()
LXMRouter.clean_transient_id_caches(router)
cutoff = time.time() - LXMRouter.MESSAGE_EXPIRY * 6.0
kept = {k for k, v in loaded.items() if v >= cutoff}
assert set(router.locally_processed_transient_ids) == kept, "LXMF keeps what is under 180 days old"
print(f"clean_transient_id_caches kept {len(kept)}")

if len(sys.argv) > 2:
    with open(sys.argv[2], "rb") as f:
        stored = f.read()
    lxmf_data, stamp = stored[:-32], stored[-32:]
    transient_id = RNS.Identity.full_hash(lxmf_data)
    held = router.locally_processed_transient_ids
    assert transient_id in held, "the message's id is held"
    queued = []
    router.delivery_destinations = {}
    router.propagation_node = True
    router.enqueue_peer_distribution = lambda tid, peer: queued.append(tid)

    def propagate(processed):
        router.locally_processed_transient_ids = processed
        router.propagation_entries = {}
        router.messagepath = tempfile.mkdtemp()
        queued.clear()
        return LXMRouter.lxmf_propagation(router, lxmf_data, stamp_value=0, stamp_data=stamp)

    # lxmf_propagation also returns False on any exception, so first the
    # control: with its id not held, the message is stored and queued.
    assert propagate({k: v for k, v in held.items() if k != transient_id}) is True, "stored when not held"
    assert len(os.listdir(router.messagepath)) == 1 and queued == [transient_id], "stored and queued"
    assert propagate(held) is False
    assert os.listdir(router.messagepath) == [] and queued == [], "not stored, not queued"
    print("lxmf_propagation refused the message, and stores it when its id is not held")
print("PASS")
