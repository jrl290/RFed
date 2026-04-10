# syntax=docker/dockerfile:1
# ── Stage 1: copy the pre-built binary from the build context ─────────────────
# The binary is built by GitHub Actions (musl, fully static).
# Run: docker build --build-arg BINARY=./apns_bridge -t apns_bridge .
#
# For multi-platform or local builds, see the GitHub Actions workflow.
FROM scratch

# The static musl binary — no libc, no ssl, no certs needed.
# webpki-roots bundles Mozilla root certs into the binary itself.
COPY apns_bridge /apns_bridge

# Config, identity, and token DB are all in /data (mount a named volume here).
VOLUME ["/data"]

ENTRYPOINT ["/apns_bridge", "--config", "/data/apns_bridge.conf"]
