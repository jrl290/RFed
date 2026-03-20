"""
channel_hash.py — RFed channel hash utilities.

Derive deterministic 16-byte Reticulum destination hashes from plain-text
channel names, or generate new private channels with a CSPRNG prefix.

Requirements:
    pip install cryptography

Usage:
    from channel_hash import compute_channel_hash, channel_path, new_private_channel

    # Public channel
    h = compute_channel_hash("public.news.tech")

    # Private channel (new)
    name, h = new_private_channel("team", "ops")
    # name → "a1b2c3d4e5f67890a1b2c3d4e5f67890.team.ops"

    # Run directly to compute a hash:
    #   python channel_hash.py public.news.tech
    #   python channel_hash.py --new team ops
"""

import os
import sys
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def compute_channel_hash(name: str) -> bytes:
    """Return the 16-byte deterministic channel destination hash for *name*.

    Algorithm:
        seed       = SHA-256(name)
        x25519_pub = X25519_public_key(seed)      → 32 bytes
        ed25519_pub = Ed25519_public_key(seed)     → 32 bytes
        bundle     = x25519_pub ‖ ed25519_pub      → 64 bytes
        hash       = SHA-256(bundle)[0:16]         → 16 bytes
    """
    seed = hashlib.sha256(name.encode("utf-8")).digest()

    x_priv = X25519PrivateKey.from_private_bytes(seed)
    x_pub  = x_priv.public_key().public_bytes_raw()

    e_priv = Ed25519PrivateKey.from_private_bytes(seed)
    e_pub  = e_priv.public_key().public_bytes_raw()

    bundle = x_pub + e_pub
    return hashlib.sha256(bundle).digest()[:16]


def channel_path(*segments: str) -> str:
    """Join segments with '.' to form a channel name.

    For public channels, pass "public" as the first segment:
        channel_path("public", "news", "tech")  → "public.news.tech"
    """
    return ".".join(segments)


def new_private_channel(*segments: str) -> tuple[str, bytes]:
    """Generate a new private channel with a cryptographically random prefix.

    Returns (channel_name, channel_hash).  The 32-char hex prefix provides
    128 bits of entropy from os.urandom().  Additional segments are appended:

        name, h = new_private_channel("team", "ops")
        # name → "a1b2c3d4e5f67890a1b2c3d4e5f67890.team.ops"

    With no segments the name is the hex string alone:

        name, h = new_private_channel()
        # name → "a1b2c3d4e5f67890a1b2c3d4e5f67890"

    The caller must persist and distribute the name out-of-band —
    it is the only way to recover the channel's encryption keys.
    """
    prefix = os.urandom(16).hex()
    name = ".".join([prefix] + list(segments)) if segments else prefix
    return name, compute_channel_hash(name)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--new":
        segments = sys.argv[2:]
        name, h = new_private_channel(*segments)
        print(f"name = {name}")
        print(f"hash = {h.hex()}")
    else:
        name = sys.argv[1] if len(sys.argv) > 1 else "public.test"
        h = compute_channel_hash(name)
        print(f"channel_hash({name!r}) = {h.hex()}")
