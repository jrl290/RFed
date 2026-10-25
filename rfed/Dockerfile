# syntax=docker/dockerfile:1
# Pre-built static musl binary copied in by CI — see build-rfed.yml
FROM scratch
COPY rfed /rfed

# RFed's license (MIT) and the Reticulum License, which covers the LXMF port in
# rfed/src/lxmf_propagation.rs and the Reticulum-rust and LXMF-rust code built
# into the binary. CI copies both into the context next to the binary.
COPY LICENSE LICENSE-RETICULUM /licenses/

VOLUME ["/data"]
ENTRYPOINT ["/rfed", "--config", "/data"]
