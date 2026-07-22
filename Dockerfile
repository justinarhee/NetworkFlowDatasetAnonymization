# syntax=docker/dockerfile:1

ARG DEBIAN_IMAGE=debian:bookworm-slim

FROM ${DEBIAN_IMAGE}

LABEL org.opencontainers.image.title="Flow Dataset Anonymization Prototype"
LABEL org.opencontainers.image.description="Debian runtime with nfdump, nfanon, nfcapd, and nfpcapd"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        file \
        gawk \
        nfdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

CMD ["/bin/bash"]
