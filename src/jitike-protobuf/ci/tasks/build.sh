#!/bin/sh
#
set -ex

# .FIXME: This is defined in pipeline.yml, but for developer builds we need it
# defined here as well. Seems like that should be fixed.
CLOUD_VPN_PROTOBUF_VERSION=0.1.0

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

cd ./cloud-vpn-protobuf/ && make hiredis build
cd -

# Verify if the ${BASE_PATH}/../version/version file exists, and if not (a local developer build) generate one
mkdir -p ./version
if [ ! -f "./version/version" ] ; then
  echo "${CLOUD_VPN_PROTOBUF_VERSION}-rc.$(date '+%s')" > "./version/version"
fi

# Make sure artifacts directory exists
mkdir -p ./artifacts

# Assuming success, we need to rename the file appropriately
mkdir -p /opt/src/cloud-vpn-protobuf/esp
mkdir -p /opt/src/cloud-vpn-protobuf/ike
cd ./cloud-vpn-protobuf && make deb
# .NOTE: This isn't super ideal, but it allows the docker-image-resource to utilize the Dockerfile
# along with the artifact (.deb file) we generate.
cp Dockerfile ../artifacts
