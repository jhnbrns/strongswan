FROM debian:stretch

COPY cloud-vpn-protobuf*.deb /
RUN echo "deb http://deb.debian.org/debian stretch-backports main contrib non-free" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y  build-essential      \
                        apt-utils            \
                        libcurl4-openssl-dev \
                        wget                 \
                        patch                \
                        rsync                \
                        autoconf             \
                        libtool              \
                        pkg-config           \
                        gettext              \
                        libgmp-dev           \
                        gperf                \
                        libhiredis-dev=0.14.0-3~bpo9+1 \
                        bison                \
                        flex                 \
                        libevent-dev         \
                        libjansson-dev       \
                        systemd              \
                        libsystemd-dev       \
                        libssl-dev           \
                        libgcrypt11-dev      \
                        libpam0g-dev         \
                        libiptc-dev          \
                        libprotobuf-dev      \
                        libprotobuf-c-dev    \
                        protobuf-compiler    \
                        protobuf-c-compiler  && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN apt-get -y install /cloud-vpn-protobuf*.deb
