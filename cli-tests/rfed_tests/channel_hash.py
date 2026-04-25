"""
channel_hash.py — Shared utilities for rfed test clients.

Exports:
  compute_channel_hash(name) → 16-byte channel destination hash
  channel_path(*segments)    → dot-joined channel name string
  channel_encrypt(name, plaintext) → encrypted inner blob (bytes)
  channel_decrypt(name, ciphertext) → decrypted plaintext (bytes)
  AnnounceHandler            → RNS-compatible announce handler class
  load_hashes()              → dict of rfed destination hashes from hashes.env
"""

import os
import hashlib
import shutil
from typing import Optional
import re
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import RNS

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_BASE = os.environ.get("RFED_TEST_RUN_DIR", TEST_DIR)


def sandbox_path(*segments: str) -> str:
    """Path rooted at the per-run sandbox directory."""
    return os.path.join(RUN_BASE, *segments)


def _patch_config_ports(config_file: str) -> None:
    """Replace hardcoded test ports/hosts with per-run environment values.

    Port mapping:
      4244 → RFED_UPLINK_PORT  (Node A / main rfed — test clients connect here)
      4245 → RFED_TEST_PORT_B  (Node B)
      4246 → RFED_TEST_PORT_BP (backup primary)
      4247 → RFED_TEST_PORT_BN (backup node)
    """
    test_host = os.environ.get("RFED_TEST_HOST", "127.0.0.1")
    uplink_port = os.environ.get("RFED_UPLINK_PORT", "4244")
    port_map = {
        "4244": uplink_port,
        "4245": os.environ.get("RFED_TEST_PORT_B",  uplink_port),
        "4246": os.environ.get("RFED_TEST_PORT_BP", uplink_port),
        "4247": os.environ.get("RFED_TEST_PORT_BN", uplink_port),
    }
    with open(config_file) as f:
        content = f.read()
    changed = False

    for old, new in port_map.items():
        patched = re.sub(r'(target_port\s*=\s*)' + old + r'\b', r'\g<1>' + new, content)
        if patched != content:
            content = patched
            changed = True

    patched = re.sub(r'(target_host\s*=\s*)(127\.0\.0\.1|localhost)\b', r'\g<1>' + test_host, content)
    if patched != content:
        content = patched
        changed = True

    patched = re.sub(r'(listen_ip\s*=\s*)127\.0\.0\.1\b', r'\g<1>0.0.0.0', content)
    if patched != content:
        content = patched
        changed = True

    if changed:
        with open(config_file, "w") as f:
            f.write(content)


def ensure_config_dir(name: str, template: Optional[str] = None) -> str:
    """Return a sandboxed config dir, copying a template dir on first use."""
    target = sandbox_path(name)
    source = os.path.join(TEST_DIR, template or name)
    if not os.path.exists(target):
        if os.path.isdir(source):
            shutil.copytree(source, target)
        else:
            os.makedirs(target, exist_ok=True)
        config_file = os.path.join(target, "config")
        # Wipe any pre-baked storage so each test starts from a clean state.
        # The template storage may contain stale known_destinations from old runs.
        stale_storage = os.path.join(target, "storage")
        if os.path.isdir(stale_storage):
            shutil.rmtree(stale_storage)
        if os.path.exists(config_file):
            _patch_config_ports(config_file)
    return target


def compute_channel_hash(name: str) -> bytes:
    """Return the 16-byte deterministic channel destination hash for *name*."""
    seed = hashlib.sha256(name.encode("utf-8")).digest()  # 32 bytes

    x_priv = X25519PrivateKey.from_private_bytes(seed)
    x_pub  = x_priv.public_key().public_bytes_raw()       # 32 bytes

    e_priv = Ed25519PrivateKey.from_private_bytes(seed)
    e_pub  = e_priv.public_key().public_bytes_raw()        # 32 bytes

    bundle = x_pub + e_pub                                 # 64 bytes
    return hashlib.sha256(bundle).digest()[:16]


def channel_path(*segments: str) -> str:
    """Join segments with '.' — first segment should be 'public' for public channels."""
    return ".".join(segments)


def new_private_channel(*segments: str) -> tuple[str, bytes]:
    """Generate a new private channel with a cryptographically random prefix.

    Returns (channel_name, channel_hash).  The 32-char hex prefix provides
    128 bits of entropy.  Additional *segments* are appended with '.':

        name, h = new_private_channel("team", "ops")
        # name → "a1b2c3d4e5f67890a1b2c3d4e5f67890.team.ops"

    The caller must persist and distribute the name out-of-band —
    it is the only way to recover the channel's encryption keys.
    """
    prefix = os.urandom(16).hex()   # 128-bit CSPRNG → 32 hex chars
    name = ".".join([prefix] + list(segments)) if segments else prefix
    return name, compute_channel_hash(name)


def _channel_identity(name: str) -> RNS.Identity:
    """Build an RNS Identity from the channel's deterministic seed.

    The private key bundle is x25519_secret(32) || ed25519_secret(32).
    RNS.Identity.from_bytes() inflates this into a full identity with
    matching public keys and the correct 16-byte truncated hash.
    """
    seed = hashlib.sha256(name.encode("utf-8")).digest()
    x_priv = X25519PrivateKey.from_private_bytes(seed)
    e_priv = Ed25519PrivateKey.from_private_bytes(seed)
    prv_bundle = (
        x_priv.private_bytes_raw()
        + e_priv.private_bytes_raw()
    )
    return RNS.Identity.from_bytes(prv_bundle)


def channel_encrypt(name: str, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* so only parties that know *name* can decrypt.

    Uses the standard RNS Identity.encrypt() scheme (ephemeral ECDH +
    HKDF + AES-CBC-HMAC), keyed to the channel's deterministic keypair.
    The rfed node never learns the channel name and therefore cannot
    derive the keys — the blob is opaque to the server, identical to
    how LXMF propagation nodes handle encrypted messages.
    """
    identity = _channel_identity(name)
    return identity.encrypt(plaintext)


def channel_decrypt(name: str, ciphertext: bytes) -> bytes:
    """Decrypt a blob that was encrypted with :func:`channel_encrypt`.

    Requires knowledge of the channel *name* (and therefore the X25519
    private key).  Returns the original plaintext, or raises ValueError
    if decryption fails (wrong channel name, corrupted data, etc.).
    """
    identity = _channel_identity(name)
    plaintext = identity.decrypt(ciphertext)
    if plaintext is None:
        raise ValueError("channel decryption failed (wrong channel name or corrupted data)")
    return plaintext


class AnnounceHandler:
    """
    RNS-compatible announce handler.

    Pass to RNS.Transport.register_announce_handler().  The *callback* receives:
        (destination_hash, announced_identity, app_data, ann_hash, is_path_response)

    Set receive_path_responses=True (default) so path responses also trigger
    the callback — this allows discovery even when the initial announce was
    sent before this client connected.
    """

    def __init__(self, aspect_filter=None, callback=None, receive_path_responses=True):
        self.aspect_filter = aspect_filter
        self.receive_path_responses = receive_path_responses
        self._callback = callback

    def received_announce(self, destination_hash, announced_identity, app_data,
                          announce_packet_hash, is_path_response):
        if self._callback is not None:
            self._callback(destination_hash, announced_identity, app_data,
                           announce_packet_hash, is_path_response)


def load_hashes() -> dict:
    """
    Read rfed destination hashes from the sandboxed rfed_data/hashes.env.
    Returns a dict with keys: RFED_NODE_HASH, RFED_CHANNEL_HASH,
                              RFED_DELIVERY_HASH, RFED_NOTIFY_HASH
    Values are bytes objects (16 bytes each).
    """
    env_file = sandbox_path("rfed_data", "hashes.env")
    hashes = {}
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    key, val = line.split("=", 1)
                    hashes[key.strip()] = bytes.fromhex(val.strip())
    return hashes


if __name__ == "__main__":
    import sys
    name = sys.argv[1] if len(sys.argv) > 1 else "public.test"
    h = compute_channel_hash(name)
    print(f"channel_hash({name!r}) = {h.hex()}")

