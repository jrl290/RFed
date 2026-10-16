"""Check that LXMF 1.1.1 loads a peers file rfed saved, and finds in it what
rfed's earlier peers file held.

    .venv/bin/python RFed-rust/rfed/tests/fixtures/lxmf_loads_rfed_peers.py \
        <rfed data dir> <earlier peers file> [<peers file rfed saved>]

The data dir's messagestore is indexed as LXMRouter.enable_propagation does,
and the saved file (by default the data dir's lxmf_propagation/peers) loaded
with LXMF's own LXMPeer.from_bytes, record by record as LXMRouter loads it.
The earlier file is decoded as rfed wrote it before it adopted LXMF's format:
rmp_serde, each record an array of RFED_PEER_FIELDS, bytes as arrays of ints.
Both loaders keep only the ids of stored messages, so for every peer the
handled and unhandled ids must be the same sets, and the fields both files
carry the same values. LXMRouter drops a peer whose identity it cannot
recall; this check has no Reticulum instance and keeps every peer.
"""

import os
import sys
import time

import LXMF
import msgpack
import RNS
import RNS.vendor.umsgpack as umsgpack
from LXMF.LXMPeer import LXMPeer

assert LXMF.__version__ == "1.1.1", LXMF.__version__
RNS.loglevel = RNS.LOG_CRITICAL

RFED_PEER_FIELDS = [
    "destination_hash", "alive", "last_heard", "peering_timebase",
    "propagation_stamp_cost", "propagation_stamp_flexibility", "peering_cost",
    "propagation_transfer_limit", "propagation_sync_limit", "peering_key",
    "metadata", "sync_transfer_rate", "handled_ids", "unhandled_ids",
]

data_dir, earlier_path = sys.argv[1], sys.argv[2]
saved_path = sys.argv[3] if len(sys.argv) > 3 else os.path.join(data_dir, "lxmf_propagation", "peers")
messagepath = os.path.join(data_dir, "lxmf_propagation", "messagestore")


class Router:
    """What LXMPeer.from_bytes and its id bookkeeping read from LXMRouter."""

    def __init__(self):
        self.propagation_entries = {}


router = Router()
started = time.time()
for filename in os.listdir(messagepath):
    components = filename.split("_")
    if len(components) >= 3 and float(components[1]) > 0 and len(components[0]) == 64:
        transient_id = bytes.fromhex(components[0])
        filepath = messagepath + "/" + filename
        with open(filepath, "rb") as file:
            destination_hash = file.read(LXMF.LXMessage.DESTINATION_LENGTH)
        router.propagation_entries[transient_id] = [
            destination_hash, filepath, float(components[1]), os.path.getsize(filepath), [], [], int(components[2]),
        ]
print(f"indexed {len(router.propagation_entries)} messages in {time.time() - started:.1f}s")

started = time.time()
with open(saved_path, "rb") as file:
    serialised_peers = umsgpack.unpackb(file.read())
loaded = {}
while len(serialised_peers) > 0:
    peer = LXMPeer.from_bytes(serialised_peers.pop(), router)
    loaded[peer.destination_hash] = peer
print(f"LXMF loaded {len(loaded)} peers from {os.path.getsize(saved_path)} bytes in {time.time() - started:.1f}s")


def as_bytes(value):
    return None if value is None else bytes(value)


# Every byte of the earlier file is an int of its own: decoded with msgpack's
# C unpacker, as umsgpack would take minutes.
with open(earlier_path, "rb") as file:
    earlier_records = msgpack.unpackb(file.read())
earlier = {}
for record_ints in earlier_records:
    record = dict(zip(RFED_PEER_FIELDS, msgpack.unpackb(bytes(record_ints))))
    earlier[as_bytes(record["destination_hash"])] = record
print(f"rfed's earlier file holds {len(earlier)} peers")

problems = []
if set(loaded) != set(earlier):
    problems.append(f"peers differ: only saved {len(set(loaded) - set(earlier))}, only earlier {len(set(earlier) - set(loaded))}")
pairs = 0
for destination_hash, peer in loaded.items():
    record = earlier.get(destination_hash)
    if record is None:
        continue
    name = RNS.prettyhexrep(destination_hash)
    for kind, now in (("handled", peer.handled_messages), ("unhandled", peer.unhandled_messages)):
        then = {as_bytes(i) for i in record[kind + "_ids"]} & router.propagation_entries.keys()
        pairs += len(now)
        if set(now) != then:
            problems.append(f"{name} {kind}: {len(now)} now, {len(then)} then, {len(set(now) ^ then)} differ")
    metadata = record["metadata"]
    expected = {
        "alive": record["alive"],
        "last_heard": record["last_heard"],
        "peering_timebase": record["peering_timebase"],
        "propagation_stamp_cost": record["propagation_stamp_cost"],
        "propagation_stamp_cost_flexibility": record["propagation_stamp_flexibility"],
        "peering_cost": record["peering_cost"],
        "propagation_transfer_limit": record["propagation_transfer_limit"],
        "propagation_sync_limit": int(record["propagation_sync_limit"])
        if record["propagation_sync_limit"] is not None else record["propagation_transfer_limit"],
        "peering_key": None if record["peering_key"] is None
        else [as_bytes(record["peering_key"][0]), record["peering_key"][1]],
        "metadata": None if metadata is None else umsgpack.unpackb(as_bytes(metadata)),
        "sync_transfer_rate": record["sync_transfer_rate"],
    }
    for field, value in expected.items():
        if getattr(peer, field) != value:
            problems.append(f"{name} {field}: {getattr(peer, field)!r} now, {value!r} then")

print(f"compared {pairs} (message, peer) pairs over {len(loaded)} peers")
for problem in problems:
    print("MISMATCH", problem)
print("PASS" if not problems else f"FAIL: {len(problems)} mismatches")
sys.exit(1 if problems else 0)
