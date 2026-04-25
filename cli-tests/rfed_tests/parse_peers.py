#!/usr/bin/env python3
import msgpack, binascii

with open('rfed_data/lxmf_propagation/peers', 'rb') as f:
    data = f.read()

outer = msgpack.unpackb(data, raw=True)
print(f"outer list len: {len(outer)}")
for i, blob_or_list in enumerate(outer):
    # rmp_serde serialises Vec<u8> as array of ints - convert back to bytes
    if isinstance(blob_or_list, list):
        blob = bytes(blob_or_list)
    elif isinstance(blob_or_list, bytes):
        blob = blob_or_list
    else:
        print(f"Peer {i}: unexpected type {type(blob_or_list)}")
        continue

    peer = msgpack.unpackb(blob, raw=True)
    print(f"\nPeer {i}:")
    # PeerState fields in order:
    fields = ["destination_hash","alive","last_heard","peering_timebase",
              "propagation_stamp_cost","propagation_stamp_flexibility",
              "peering_cost","propagation_transfer_limit","propagation_sync_limit",
              "peering_key","metadata","sync_transfer_rate",
              "handled_ids","unhandled_ids"]
    if isinstance(peer, (list, tuple)):
        for j, field in enumerate(peer):
            name = fields[j] if j < len(fields) else f"field_{j}"
            if isinstance(field, (list, tuple)) and len(field) > 0 and isinstance(field[0], int) and field[0] < 256:
                # Likely Vec<u8> as int array
                h = binascii.hexlify(bytes(field)).decode()[:64]
                print(f"  {name}: {h}")
            elif isinstance(field, (list, tuple)):
                print(f"  {name}: list({len(field)})")
                for item in field[:3]:
                    if isinstance(item, (list, tuple)) and all(isinstance(x, int) for x in item):
                        print(f"     {binascii.hexlify(bytes(item)).decode()[:64]}")
                    elif isinstance(item, bytes):
                        print(f"     {binascii.hexlify(item).decode()[:64]}")
                    else:
                        print(f"     {item}")
                if len(field) > 3:
                    print(f"     ... and {len(field)-3} more")
            elif isinstance(field, bytes):
                print(f"  {name}: {binascii.hexlify(field).decode()[:64]}")
            else:
                print(f"  {name}: {field}")
