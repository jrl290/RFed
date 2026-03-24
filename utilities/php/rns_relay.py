#!/usr/bin/env python3
"""
rfed Notify Relay → APNs Bridge Listener
=========================================

This script acts as the Reticulum ``rfed.notify`` relay node described in the
rfed SPEC §9.5.  It:

  1. Creates a Reticulum identity and announces a ``rfed.notify``
     ``Single``-type destination on the mesh.
  2. Receives incoming encrypted wake packets from rfed nodes.
  3. Decodes the msgpack Map payload (``receiver``, optional ``sender`` /
     ``channel`` hashes).
  4. POSTs the decoded hashes (as JSON) to the PHP bridge's ``/wake``
     endpoint over localhost HTTP.

The PHP bridge is responsible for looking up APNs device tokens and firing
the actual push notifications.  This script never touches APNs credentials.

Usage
-----
    python3 rns_relay.py [--config /path/to/rns_relay.conf]

Configuration file (INI format, see rns_relay.conf.example):
    [relay]
    identity_path = /var/lib/rfed-relay/identity
    bridge_url    = http://127.0.0.1:8080/wake
    bridge_secret = <same value as bridge_secret in config.php>
    rns_config    = ~/.reticulum       # optional, defaults to RNS default

Requirements
------------
    pip install rns msgpack requests

Notes
-----
  * The identity file is created automatically on first run from a freshly
    generated Reticulum identity.  Keep the file safe — it is the relay's
    permanent address on the mesh.
  * The relay announces itself every ANNOUNCE_INTERVAL seconds so rfed nodes
    can route wake packets to it.
  * Run behind a process supervisor (systemd, supervisor, etc.).
"""

import argparse
import configparser
import logging
import os
import sys
import time
import urllib.request
import urllib.error
import json

try:
    import RNS
except ImportError:
    sys.exit("ERROR: RNS not installed.  Run: pip install rns")

try:
    import msgpack
except ImportError:
    sys.exit("ERROR: msgpack not installed.  Run: pip install msgpack")

# ── Constants ─────────────────────────────────────────────────────────────────

APP_NAME          = "rfed"
ASPECT            = "notify"
ANNOUNCE_INTERVAL = 600          # seconds between announces (10 minutes)
DEFAULT_CONFIG    = os.path.join(os.path.dirname(__file__), "rns_relay.conf")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("rns_relay")

# ── Relay ─────────────────────────────────────────────────────────────────────

class NotifyRelay:
    def __init__(self, identity_path: str, bridge_url: str, bridge_secret: str):
        self.identity_path = identity_path
        self.bridge_url    = bridge_url
        self.bridge_secret = bridge_secret
        self.destination   = None

    def start(self, rns_config: str | None = None) -> None:
        """Initialise Reticulum, load/create identity, announce destination."""
        # Reticulum initialises transport in the background.
        rns_kwargs = {}
        if rns_config:
            rns_kwargs["configdir"] = rns_config
        RNS.Reticulum(**rns_kwargs)

        identity = self._load_identity()
        log.info("Relay identity hash: %s", RNS.prettyhexrep(identity.hash))

        self.destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            APP_NAME,
            ASPECT,
        )
        self.destination.set_packet_callback(self._on_packet)
        self.destination.set_link_established_callback(self._on_link)

        log.info(
            "Listening on %s.%s destination: %s",
            APP_NAME, ASPECT,
            RNS.prettyhexrep(self.destination.hash),
        )

        self._announce_loop()

    # ── Private ───────────────────────────────────────────────────────────

    def _load_identity(self) -> RNS.Identity:
        """Load the relay identity from disk, creating it if absent."""
        if os.path.exists(self.identity_path):
            identity = RNS.Identity.from_file(self.identity_path)
            if identity is None:
                raise RuntimeError(
                    f"Failed to load identity from {self.identity_path}"
                )
            log.info("Loaded existing identity from %s", self.identity_path)
        else:
            os.makedirs(os.path.dirname(os.path.abspath(self.identity_path)),
                        exist_ok=True)
            identity = RNS.Identity()
            identity.to_file(self.identity_path)
            log.info("Created new identity at %s", self.identity_path)
        return identity

    def _announce_loop(self) -> None:
        """Announce destination and re-announce periodically.  Blocks forever."""
        self.destination.announce()
        log.info("Initial announce sent")

        while True:
            time.sleep(ANNOUNCE_INTERVAL)
            self.destination.announce()
            log.debug("Periodic announce sent")

    # ── Reticulum callbacks ───────────────────────────────────────────────

    def _on_packet(self, message: bytes, packet: RNS.Packet) -> None:
        """
        Called when rfed sends a direct (non-link) wake packet.

        The payload is a msgpack Map containing:
          "receiver" → bytes(16)  — always present
          "sender"   → bytes(16)  — optional
          "channel"  → bytes(16)  — optional
        """
        self._dispatch_wake(message)

    def _on_link(self, link: RNS.Link) -> None:
        """
        Called when rfed establishes a Link before sending the wake packet.
        Register a packet callback on the link.
        """
        link.set_packet_callback(self._on_link_packet)
        log.debug("Link established from %s", RNS.prettyhexrep(link.hash))

    def _on_link_packet(self, message: bytes, packet: RNS.Packet) -> None:
        self._dispatch_wake(message)

    # ── Wake dispatch ─────────────────────────────────────────────────────

    def _dispatch_wake(self, raw: bytes) -> None:
        """Decode a msgpack wake payload and POST it to the PHP bridge."""
        try:
            data = msgpack.unpackb(raw, raw=False)
        except Exception as exc:
            log.warning("Failed to decode wake payload: %s", exc)
            return

        if not isinstance(data, dict):
            log.warning("Wake payload is not a map (got %s)", type(data).__name__)
            return

        # "receiver" is always required — 16 raw bytes.
        receiver_bytes = data.get("receiver")
        if not isinstance(receiver_bytes, (bytes, bytearray)) or len(receiver_bytes) != 16:
            log.warning("Wake payload missing valid 'receiver' key")
            return

        receiver_hex = receiver_bytes.hex()
        sender_hex   = None
        channel_hex  = None

        sender_bytes  = data.get("sender")
        if isinstance(sender_bytes, (bytes, bytearray)) and len(sender_bytes) == 16:
            sender_hex = sender_bytes.hex()

        channel_bytes = data.get("channel")
        if isinstance(channel_bytes, (bytes, bytearray)) and len(channel_bytes) == 16:
            channel_hex = channel_bytes.hex()

        log.info(
            "Wake received: receiver=%s sender=%s channel=%s",
            receiver_hex, sender_hex or "-", channel_hex or "-",
        )

        self._post_to_bridge(receiver_hex, sender_hex, channel_hex)

    def _post_to_bridge(
        self,
        receiver: str,
        sender: str | None,
        channel: str | None,
    ) -> None:
        """POST the decoded wake payload to the PHP bridge's /wake endpoint."""
        payload: dict = {"receiver": receiver}
        if sender  is not None: payload["sender"]  = sender
        if channel is not None: payload["channel"] = channel

        body = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            self.bridge_url,
            data=body,
            method="POST",
            headers={
                "Content-Type":     "application/json",
                "X-Bridge-Secret":  self.bridge_secret,
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                resp_body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            log.error(
                "Bridge HTTP error %d for receiver %s: %s",
                exc.code, receiver, exc.read().decode("utf-8", errors="replace"),
            )
            return
        except OSError as exc:
            log.error("Bridge connection error for receiver %s: %s", receiver, exc)
            return

        if status == 200:
            log.info("Bridge accepted wake for receiver %s: %s", receiver, resp_body)
        else:
            log.warning(
                "Bridge returned %d for receiver %s: %s", status, receiver, resp_body
            )


# ── CLI ───────────────────────────────────────────────────────────────────────

def load_config(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if os.path.exists(path):
        cfg.read(path)
    return cfg


def main() -> None:
    parser = argparse.ArgumentParser(description="rfed → APNs notify relay listener")
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG,
        help=f"Path to INI config file (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    cfg = load_config(args.config)
    relay_cfg = cfg["relay"] if "relay" in cfg else {}

    identity_path = relay_cfg.get(
        "identity_path",
        os.path.expanduser("~/.rfed-relay/identity"),
    )
    bridge_url = relay_cfg.get("bridge_url", "http://127.0.0.1:8080/wake")
    bridge_secret = relay_cfg.get("bridge_secret", "")
    rns_config = relay_cfg.get("rns_config") or None
    if rns_config:
        rns_config = os.path.expanduser(rns_config)

    if not bridge_secret:
        log.warning(
            "bridge_secret is empty — /wake endpoint is unprotected! "
            "Set bridge_secret in %s", args.config,
        )

    relay = NotifyRelay(identity_path, bridge_url, bridge_secret)
    try:
        relay.start(rns_config)
    except KeyboardInterrupt:
        log.info("Shutting down")


if __name__ == "__main__":
    main()
