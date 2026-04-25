#!/usr/bin/env python3
"""
relay_hash.py — Compute the rfed.notify destination hash for the relay
                identity file WITHOUT starting RNS.

Usage: python3 relay_hash.py [identity_file]
Output: hex hash (32 chars)
"""
import sys
import os
import hashlib

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    sys.stderr.write("cryptography not installed\n")
    sys.exit(1)

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ID = os.path.join(TEST_DIR, "rns_notify_relay", "relay_identity")

identity_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ID

if not os.path.exists(identity_file):
    sys.stderr.write(f"identity file not found: {identity_file}\n")
    sys.exit(2)

with open(identity_file, "rb") as f:
    priv = f.read()

if len(priv) < 64:
    sys.stderr.write(f"identity file too short ({len(priv)} bytes, expected 64)\n")
    sys.exit(1)

# Python RNS stores 64 bytes: first 32 = X25519 private, last 32 = Ed25519 private
x_pub = X25519PrivateKey.from_private_bytes(priv[:32]).public_key().public_bytes_raw()
e_pub = Ed25519PrivateKey.from_private_bytes(priv[32:64]).public_key().public_bytes_raw()
identity_pub = x_pub + e_pub  # 64 bytes

# Destination hash formula (matches Python RNS Destination.hash()):
#   name_hash         = SHA256("rfed.notify")[:10]   (NAME_HASH_LENGTH=80 bits = 10 bytes)
#   identity_hash     = SHA256(identity_pub_64)[:16]  (TRUNCATED_HASHLENGTH=128 bits = 16 bytes)
#   addr_hash_material = name_hash + identity_hash    (26 bytes)
#   dest_hash         = SHA256(addr_hash_material)[:16]
name_hash     = hashlib.sha256("rfed.notify".encode()).digest()[:10]
identity_hash = hashlib.sha256(identity_pub).digest()[:16]
dest_hash     = hashlib.sha256(name_hash + identity_hash).digest()[:16]

print(dest_hash.hex())
