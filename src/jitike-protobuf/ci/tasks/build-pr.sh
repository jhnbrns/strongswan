#!/bin/sh
#
set -ex

# Enable backports to get hiredis14
#echo "deb http://deb.debian.org/debian stretch-backports main contrib non-free" >> /etc/apt/sources.list

pwd
apt-get update

# Install dependencies required for building strongswan
apt-get install -y  build-essential      \
                    libcurl4-openssl-dev \
                    git                  \
                    wget                 \
                    checkinstall         \
                    patch                \
                    autoconf             \
                    libtool              \
                    pkg-config           \
                    gettext              \
                    libgmp-dev           \
                    gperf                \
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
                    libprotobuf-c-dev    \
                    protobuf-compiler    \
                    protobuf-c-compiler

cd ./cloud-vpn-protobuf-pr/ && make hiredis build
cd -
