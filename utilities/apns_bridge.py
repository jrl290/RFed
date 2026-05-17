#!/usr/bin/env python3
"""
rfed APNs Push Bridge
=====================

Single-process daemon that connects the rfed notify system to Apple APNs.

Two Reticulum destinations are announced:

  rfed.notify  — Receives encrypted wake packets from rfed nodes (see SPEC §9).
                 These are fire-and-forget msgpack Maps carrying only hashes.

  rfed.apns    — Token registration endpoint for the iOS app.
                 The app sends a plain encrypted RNS packet (no Link required):
                   register:   {"subscriber_hash": bin(16), "apns_token": str(64 hex)}
                   unregister: {"subscriber_hash": bin(16)}

When a wake packet arrives for a registered subscriber, this bridge sends
an APNs HTTP/2 push notification using token-based auth (p8 key / ES256 JWT).
No message content is ever transmitted — only the subscriber hash is passed
to APNs inside the notification's custom data, so the app can trigger the
correct fetch.

Architecture
────────────
  [rfed node] ──rfed.notify wake──▶ [apns_bridge.py] ──APNs HTTP/2──▶ iOS device
  [iOS app]   ──rfed.apns /register──▶ [apns_bridge.py]  (stores token → SQLite)

Registration wire format  (/rfed/apns — plain encrypted packet)
─────────────────────────
  Payload: msgpack Map
    register:   {"subscriber_hash": bin(16), "apns_token": str(64 hex)}
    unregister: {"subscriber_hash": bin(16)}   (no "apns_token" key)

Requirements
───────────
  pip install rns msgpack "httpx[http2]" cryptography

Usage
─────
  cp apns_bridge.conf.example apns_bridge.conf
  # edit apns_bridge.conf
  python3 apns_bridge.py [--config apns_bridge.conf] [--debug]
"""

import argparse
import base64
import configparser
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from typing import Optional

# ── Dependency checks ─────────────────────────────────────────────────────────

try:
    import RNS
except ImportError:
    sys.exit("ERROR: RNS not installed.  Run: pip install rns")

try:
    import msgpack
except ImportError:
    sys.exit("ERROR: msgpack not installed.  Run: pip install msgpack")

try:
    import httpx
except ImportError:
    sys.exit("ERROR: httpx not installed.  Run: pip install 'httpx[http2]'")

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
except ImportError:
    sys.exit("ERROR: cryptography not installed.  Run: pip install cryptography")

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("apns_bridge")

# ── Constants ─────────────────────────────────────────────────────────────────

NOTIFY_APP      = "rfed"
NOTIFY_ASPECT   = "notify"
APNS_REG_APP    = "rfed"
APNS_REG_ASPECT = "apns"

ANNOUNCE_INTERVAL = 600  # seconds between periodic re-announces

# ── SQLite token registry ─────────────────────────────────────────────────────

class TokenDB:
    """Thread-safe subscriber_hash → APNs device token registry."""

    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                subscriber_hash TEXT NOT NULL PRIMARY KEY,
                apns_token      TEXT NOT NULL,
                registered      INTEGER NOT NULL,
                updated         INTEGER NOT NULL
            )
        """)
        self._conn.commit()

    def register(self, subscriber_hash: str, apns_token: str) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute("""
                INSERT INTO tokens (subscriber_hash, apns_token, registered, updated)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(subscriber_hash) DO UPDATE SET
                    apns_token = excluded.apns_token,
                    updated    = excluded.updated
            """, (subscriber_hash, apns_token, now, now))
            self._conn.commit()

    def get_token(self, subscriber_hash: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT apns_token FROM tokens WHERE subscriber_hash = ? LIMIT 1",
                (subscriber_hash,),
            ).fetchone()
        return row[0] if row else None

    def unregister(self, subscriber_hash: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM tokens WHERE subscriber_hash = ?", (subscriber_hash,)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def invalidate_token(self, apns_token: str) -> None:
        """Remove a registration by APNs token (called on BadDeviceToken / 410)."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM tokens WHERE apns_token = ?", (apns_token,)
            )
            self._conn.commit()

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM tokens").fetchone()[0]


# ── APNs JWT (ES256 / p8 key) ─────────────────────────────────────────────────

class ApnsJwt:
    """Generates and caches ES256 JWTs for APNs token-based auth."""

    def __init__(self, key_file: str, key_id: str, team_id: str, token_ttl: int = 3000):
        self._key_id    = key_id
        self._team_id   = team_id
        self._token_ttl = token_ttl  # seconds before regenerating (Apple max: 3600)

        with open(key_file, "rb") as f:
            pem = f.read()
        self._private_key = serialization.load_pem_private_key(
            pem, password=None, backend=default_backend()
        )
        self._cached_token: Optional[str] = None
        self._cached_iat: int = 0

    def get(self) -> str:
        """Return a valid JWT, regenerating if it's older than token_ttl."""
        if self._cached_token and (time.time() - self._cached_iat) < self._token_ttl:
            return self._cached_token
        self._cached_iat   = int(time.time())
        self._cached_token = self._generate(self._cached_iat)
        return self._cached_token

    def _generate(self, iat: int) -> str:
        header  = _b64url(json.dumps({"alg": "ES256", "kid": self._key_id}))
        payload = _b64url(json.dumps({"iss": self._team_id, "iat": iat}))
        signing_input = f"{header}.{payload}".encode()

        der_sig = self._private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        raw_sig = _der_ecdsa_to_raw(der_sig)
        return f"{header}.{payload}.{_b64url(raw_sig)}"


def _b64url(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _der_ecdsa_to_raw(der: bytes) -> bytes:
    """Convert DER-encoded ECDSA signature to fixed-width R‖S (64 bytes)."""
    offset = 0
    assert der[offset] == 0x30, "Expected SEQUENCE tag"
    offset += 1
    seq_len = der[offset]; offset += 1
    if seq_len & 0x80:                           # long-form length (rare)
        offset += seq_len & 0x7f

    def read_int(pos: int):
        assert der[pos] == 0x02, "Expected INTEGER tag"
        pos += 1
        length = der[pos]; pos += 1
        val = der[pos: pos + length]; pos += length
        if len(val) > 32 and val[0] == 0:        # strip DER positive padding
            val = val[1:]
        return val.rjust(32, b"\x00"), pos        # left-pad to 32 bytes

    r, offset = read_int(offset)
    s, _      = read_int(offset)
    return r + s


# ── APNs HTTP/2 sender ────────────────────────────────────────────────────────

class ApnsSender:
    """Sends APNs HTTP/2 push notifications.  Thread-safe via httpx client."""

    PROD_HOST    = "https://api.push.apple.com"
    SANDBOX_HOST = "https://api.sandbox.push.apple.com"

    def __init__(self, cfg: configparser.SectionProxy):
        self._jwt = ApnsJwt(
            key_file  = cfg["key_file"],
            key_id    = cfg["key_id"],
            team_id   = cfg["team_id"],
            token_ttl = int(cfg.get("token_ttl", "3000")),
        )
        self._bundle_id   = cfg["bundle_id"]
        self._sandbox     = cfg.get("sandbox", "false").strip().lower() in ("true", "1", "yes")
        self._push_type   = cfg.get("push_type", "alert")
        self._alert_title = cfg.get("alert_title", "New message")
        self._alert_body  = cfg.get("alert_body",  "You have a new message waiting.")
        self._host        = self.SANDBOX_HOST if self._sandbox else self.PROD_HOST
        # Reuse a single HTTP/2 connection pool across all threads.
        self._client      = httpx.Client(http2=True, timeout=10)

    def send(
        self,
        apns_token:   str,
        receiver_hex: str,
        sender_hex:   Optional[str] = None,
        channel_hex:  Optional[str] = None,
    ) -> tuple[bool, int, Optional[str]]:
        """
        Send a push.  Returns (success, http_code, reason).
        reason is None on success; an APNs error string otherwise.
        """
        url = f"{self._host}/3/device/{apns_token}"
        body = self._payload(receiver_hex, sender_hex, channel_hex)
        headers = {
            "Authorization":  f"bearer {self._jwt.get()}",
            "apns-topic":     self._bundle_id,
            "apns-push-type": self._push_type,
            "apns-priority":  "10",
            "Content-Type":   "application/json",
        }

        try:
            resp = self._client.post(url, content=body.encode(), headers=headers)
        except Exception as exc:
            return False, 0, str(exc)

        if resp.status_code == 200:
            return True, 200, None

        reason = None
        try:
            reason = resp.json().get("reason")
        except Exception:
            pass
        return False, resp.status_code, reason

    def should_invalidate(self, http_code: int, reason: Optional[str]) -> bool:
        """True when APNs says the token is permanently invalid."""
        return http_code == 410 or (http_code == 400 and reason == "BadDeviceToken")

    def _payload(self, receiver: str, sender: Optional[str], channel: Optional[str]) -> str:
        rfed: dict = {"receiver": receiver}
        if sender:  rfed["sender"]  = sender
        if channel: rfed["channel"] = channel
        return json.dumps({
            "aps": {
                "alert":             {"title": self._alert_title, "body": self._alert_body},
                "sound":             "default",
                "mutable-content":   1,
            },
            "rfed": rfed,
        }, separators=(",", ":"))


# ── Bridge ────────────────────────────────────────────────────────────────────

class ApnsBridge:
    def __init__(
        self,
        identity_path: str,
        db:            TokenDB,
        apns:          ApnsSender,
        rns_config:    Optional[str] = None,
        rns_tcp_host:  Optional[str] = None,
        rns_tcp_port:  int = 4242,
    ):
        self._identity_path = identity_path
        self._db            = db
        self._apns          = apns
        self._rns_config    = rns_config
        self._rns_tcp_host  = rns_tcp_host
        self._rns_tcp_port  = rns_tcp_port
        self._notify_count  = 0
        self._push_count    = 0
        self._push_fail     = 0

    def start(self) -> None:
        rns_kwargs: dict = {}
        if self._rns_config:
            rns_kwargs["configdir"] = os.path.expanduser(self._rns_config)
        elif self._rns_tcp_host:
            # Build a dedicated Reticulum configdir next to the identity file so
            # we can inject the TCPClientInterface without touching ~/.reticulum.
            config_dir = os.path.join(
                os.path.dirname(os.path.expanduser(self._identity_path)),
                "reticulum",
            )
            os.makedirs(config_dir, exist_ok=True)
            config_file = os.path.join(config_dir, "config")
            config_text = (
                "[reticulum]\n"
                "  enable_transport = false\n"
                "  share_instance = false\n\n"
                "[interfaces]\n\n"
                "  [[ApnsBridgeTCP]]\n"
                "    type = TCPClientInterface\n"
                "    enabled = yes\n"
                f"    target_host = {self._rns_tcp_host}\n"
                f"    target_port = {self._rns_tcp_port}\n"
            )
            with open(config_file, "w") as fh:
                fh.write(config_text)
            log.info("Using TCP interface → %s:%s (configdir: %s)",
                     self._rns_tcp_host, self._rns_tcp_port, config_dir)
            rns_kwargs["configdir"] = config_dir
        RNS.Reticulum(**rns_kwargs)

        identity = self._load_identity()
        log.info("Bridge identity: %s", RNS.prettyhexrep(identity.hash))

        # ── rfed.notify ──────────────────────────────────────────────────────
        notify_dest = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            NOTIFY_APP, NOTIFY_ASPECT,
        )
        notify_dest.set_packet_callback(self._on_wake_packet)
        notify_dest.set_link_established_callback(self._on_notify_link)
        log.info("rfed.notify  hash: %s", RNS.prettyhexrep(notify_dest.hash))

        # ── rfed.apns (registration) ─────────────────────────────────────────
        # Accepts plain encrypted packets (no Link required) so the iOS app
        # can register without a Link FFI.
        #
        # Packet payload: msgpack Map
        #   register:   {"subscriber_hash": bin(16), "apns_token": str(64 hex)}
        #   unregister: {"subscriber_hash": bin(16)}  (no "apns_token" key)
        apns_dest = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APNS_REG_APP, APNS_REG_ASPECT,
        )
        apns_dest.set_packet_callback(self._on_register_packet)
        apns_dest.set_link_established_callback(self._on_register_link)
        log.info("rfed.apns    hash: %s", RNS.prettyhexrep(apns_dest.hash))
        log.info("Token registry: %d registered", self._db.count())
    def _on_register_link(self, link: RNS.Link) -> None:
        """Allow registration over a Link as well as plain packet."""
        link.set_packet_callback(self._on_register_packet)

        notify_dest.announce()
        apns_dest.announce()
        log.info("Announces sent — bridge is running")

        # ── Periodic re-announce (blocks forever) ────────────────────────────
        while True:
            time.sleep(ANNOUNCE_INTERVAL)
            notify_dest.announce()
            apns_dest.announce()
            log.debug("Periodic announces sent")

    # ── Identity ──────────────────────────────────────────────────────────────

    def _load_identity(self) -> RNS.Identity:
        if os.path.exists(self._identity_path):
            identity = RNS.Identity.from_file(self._identity_path)
            if identity is None:
                raise RuntimeError(f"Failed to load identity from {self._identity_path}")
            log.info("Loaded identity from %s", self._identity_path)
        else:
            os.makedirs(
                os.path.dirname(os.path.abspath(self._identity_path)), exist_ok=True
            )
            identity = RNS.Identity()
            identity.to_file(self._identity_path)
            log.info("Created new identity at %s", self._identity_path)
        return identity

    # ── Wake packet dispatch ──────────────────────────────────────────────────

    def _on_notify_link(self, link: RNS.Link) -> None:
        """rfed may open a Link before sending the wake packet."""
        link.set_packet_callback(self._on_wake_packet)

    def _on_wake_packet(self, message: bytes, packet: RNS.Packet) -> None:
        threading.Thread(target=self._dispatch_wake, args=(message,), daemon=True).start()

    def _dispatch_wake(self, raw: bytes) -> None:
        try:
            receiver_hex, sender_hex, channel_hex = _decode_wake_payload(raw)
        except ValueError as exc:
            log.warning("Wake: %s", exc)
            return
        except Exception as exc:
            log.warning("Wake: bad msgpack: %s", exc)
            return

        self._notify_count += 1
        log.info("NOTIFY #%d received  receiver=%s sender=%s channel=%s",
                 self._notify_count, receiver_hex, sender_hex or "-", channel_hex or "-")

        apns_token = self._db.get_token(receiver_hex)
        if apns_token is None:
            log.info("NOTIFY #%d skipped   receiver=%s (no APNs token registered)",
                     self._notify_count, receiver_hex)
            return

        success, http_code, reason = self._apns.send(
            apns_token, receiver_hex, sender_hex, channel_hex
        )

        if success:
            self._push_count += 1
            log.info("NOTIFY #%d pushed    receiver=%s → APNs OK  (total pushed: %d)",
                     self._notify_count, receiver_hex, self._push_count)
        elif self._apns.should_invalidate(http_code, reason):
            self._push_fail += 1
            self._db.invalidate_token(apns_token)
            log.warning("NOTIFY #%d purged    receiver=%s — stale token (reason=%s)",
                        self._notify_count, receiver_hex, reason)
        else:
            self._push_fail += 1
            log.error("NOTIFY #%d FAILED    receiver=%s — HTTP %d reason=%s  (total failed: %d)",
                      self._notify_count, receiver_hex, http_code, reason, self._push_fail)

    # ── Registration packet handler ───────────────────────────────────────────

    def _on_register_packet(self, message: bytes, packet: RNS.Packet) -> None:
        """
        Plain-packet registration from the iOS app.

        Payload: msgpack Map
          register:   {"subscriber_hash": bin(16), "apns_token": str(64 hex)}
          unregister: {"subscriber_hash": bin(16)}   (no "apns_token" key)
        """
        try:
            sub_hex, apns_token = _decode_registration_payload(message)

            if apns_token is not None:
                # Register / refresh
                self._db.register(sub_hex, apns_token)
                log.info("Register: token stored for %s", sub_hex)
            else:
                # Unregister
                removed = self._db.unregister(sub_hex)
                log.info("Unregister: %s for %s",
                          "removed" if removed else "not found", sub_hex)

        except Exception as exc:
            log.warning("Registration packet: rejected — %s", exc)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _opt_hash_hex(val) -> Optional[str]:
    if isinstance(val, (bytes, bytearray)) and len(val) == 16:
        return val.hex()
    return None


def _decode_wake_payload(raw: bytes) -> tuple[str, Optional[str], Optional[str]]:
    data = msgpack.unpackb(raw, raw=False)
    if not isinstance(data, dict):
        raise ValueError("payload is not a map")

    receiver_bytes = data.get("receiver")
    if not isinstance(receiver_bytes, (bytes, bytearray)) or len(receiver_bytes) != 16:
        raise ValueError("missing valid 'receiver' key")

    return (
        receiver_bytes.hex(),
        _opt_hash_hex(data.get("sender")),
        _opt_hash_hex(data.get("channel")),
    )


def _decode_registration_payload(raw: bytes) -> tuple[str, Optional[str]]:
    payload = msgpack.unpackb(bytes(raw), raw=False)
    if not isinstance(payload, dict):
        raise ValueError("payload must be a msgpack map")

    sub_bytes = payload.get("subscriber_hash")
    if not isinstance(sub_bytes, (bytes, bytearray)) or len(sub_bytes) != 16:
        raise ValueError("subscriber_hash must be 16 bytes")

    apns_token = payload.get("apns_token")
    if apns_token is not None:
        if not isinstance(apns_token, str) or len(apns_token) != 64 \
                or not all(c in "0123456789abcdef" for c in apns_token):
            raise ValueError("apns_token must be 64-char lowercase hex")

    return sub_bytes.hex(), apns_token


# ── CLI entry point ───────────────────────────────────────────────────────────

DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apns_bridge.conf")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="rfed APNs Push Bridge — Reticulum relay + APNs sender"
    )
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG,
        help=f"Path to INI config file (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    cfg = configparser.ConfigParser()
    if not os.path.exists(args.config):
        sys.exit(
            f"Config file not found: {args.config}\n"
            f"Copy apns_bridge.conf.example → apns_bridge.conf and fill in."
        )
    cfg.read(args.config)

    bridge_section = cfg["bridge"] if "bridge" in cfg else {}
    apns_section   = cfg["apns"]   if "apns"   in cfg else {}

    db = TokenDB(
        os.path.expanduser(bridge_section.get("db_path", "~/.rfed-apns/tokens.db"))
    )
    apns = ApnsSender(apns_section)

    rns_tcp_host = bridge_section.get("rns_tcp_host") or None
    rns_tcp_port = int(bridge_section.get("rns_tcp_port", 4242))

    bridge = ApnsBridge(
        identity_path = os.path.expanduser(
            bridge_section.get("identity_path", "~/.rfed-apns/identity")
        ),
        db           = db,
        apns         = apns,
        rns_config   = bridge_section.get("rns_config") or None,
        rns_tcp_host = rns_tcp_host,
        rns_tcp_port = rns_tcp_port,
    )

    try:
        bridge.start()
    except KeyboardInterrupt:
        log.info("Shutting down")


if __name__ == "__main__":
    main()
