# syntax=docker/dockerfile:1
# Pre-built static musl binary copied in by CI — see build-rfed.yml
FROM scratch
COPY rfed /rfed
VOLUME ["/data"]
ENTRYPOINT ["/rfed", "--config", "/data"]
