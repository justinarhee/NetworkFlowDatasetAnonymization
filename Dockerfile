# syntax=docker/dockerfile:1

ARG DEBIAN_IMAGE=debian:bookworm-slim

FROM ${DEBIAN_IMAGE} AS nfgen-builder

ARG NFDUMP_VERSION=1.7.3

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        bison \
        build-essential \
        ca-certificates \
        flex \
        git \
        libbz2-dev \
        liblz4-dev \
        libtool \
        libzstd-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "v${NFDUMP_VERSION}" \
        https://github.com/phaag/nfdump.git /src/nfdump

WORKDIR /src/nfdump

RUN ./autogen.sh \
    && ./configure --disable-dependency-tracking \
    && make -j"$(nproc)" -C src/lib \
    && make -j"$(nproc)" -C src/test nfgen \
    && gcc -o /tmp/nfgen \
        src/test/nfgen.o \
        src/lib/.libs/libnfdump.a \
        -lpthread -latomic -lresolv -lzstd -lbz2 \
    && strip /tmp/nfgen

FROM ${DEBIAN_IMAGE}

LABEL org.opencontainers.image.title="Flow Dataset Anonymization Prototype"
LABEL org.opencontainers.image.description="Debian runtime with nfdump, nfanon, nfcapd, and nfgen"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        file \
        gawk \
        nfdump \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nfgen-builder /tmp/nfgen /usr/local/bin/nfgen

WORKDIR /work

CMD ["/bin/bash"]
