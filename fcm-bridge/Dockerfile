# syntax=docker/dockerfile:1
# The binary is built by GitHub Actions (musl, fully static).
FROM scratch

COPY fcm_bridge /fcm_bridge

# The bridge's license (MIT) and the Reticulum License, which covers the
# Reticulum-rust code built into the binary. CI copies both into the context
# next to the binary.
COPY LICENSE LICENSE-RETICULUM /licenses/

# Config, bridge identity, SQLite DB, and Firebase service-account JSON all
# live in /data so the container can be run with one persisted volume mount.
VOLUME ["/data"]

ENTRYPOINT ["/fcm_bridge", "--config", "/data/fcm_bridge.conf"]