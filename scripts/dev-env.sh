#!/bin/bash

# Copyright (c) 2018 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

VPP_CFG_DIR="/etc/vpp"
AGENT_CFG_DIR="/tmp/vpp-agent"

RESPONDER_CFG_DIR="/etc"
INITIATOR_CFG_DIR="/tmp/initiator"

vpp_conf() {
  sudo mkdir -p $VPP_CFG_DIR
  sudo bash -c "cat << EOF > $VPP_CFG_DIR/vpp.conf
unix {
  nodaemon
  cli-listen 0.0.0.0:5002
  cli-no-pager
}
plugins {
  plugin dpdk_plugin.so {
    disable
  }
}
punt {
  socket /etc/vpp/punt.sock
}
EOF"
}

grpc_conf() {
  sudo mkdir -p $AGENT_CFG_DIR
  sudo bash -c "cat << EOF > $AGENT_CFG_DIR/grpc.conf
# GRPC endpoint defines IP address and port (if tcp type) or unix domain socket file (if unix type).
endpoint: 127.0.0.1:9111

# If unix domain socket file is used for GRPC communication, permissions to the file can be set here.
# Permission value uses standard three-or-four number linux binary reference.
permission: 000

# If socket file exists in defined path, it is not removed by default, GRPC plugin tries to use it.
# Set the force removal flag to 'true' ensures that the socket file will be always re-created
force-socket-removal: false

# Available socket types: tcp, tcp4, tcp6, unix, unixpacket. If not set, defaults to tcp.
network: tcp

# Maximum message size in bytes for inbound mesages. If not set, GRPC uses the default 4MB.
max-msg-size: 4096

# Limit of server streams to each server transport.
max-concurrent-streams: 0
EOF"
}

responder_conf() {
  sudo mkdir -p $RESPONDER_CFG_DIR
  sudo bash -c "cat << EOF > $RESPONDER_CFG_DIR/ipsec.conf
config setup
  strictcrlpolicy=no

conn responder
  mobike=no
  auto=add

  type=tunnel
  keyexchange=ikev2
  ike=aes256-sha1-modp2048
  esp=aes192-sha1

# local:
  left=172.16.0.2
  leftauth=psk

  leftsubnet=10.10.10.0/24
  rightsubnet=10.10.20.0/24

# remote: (roadwarrior)
  rightauth=psk

EOF"
  sudo bash -c "cat << EOF > $RESPONDER_CFG_DIR/ipsec.secrets
: PSK 'Vpp123'
EOF"
}

initiator_conf() {
  sudo mkdir -p $INITIATOR_CFG_DIR
  sudo bash -c "cat << EOF > $INITIATOR_CFG_DIR/ipsec.conf
config setup
  strictcrlpolicy=no

conn initiator
  mobike=no
  auto=add

  type=tunnel
  keyexchange=ikev2
  ike=aes256-sha1-modp2048
  esp=aes192-sha1

# local:
  leftauth=psk

# remote: (gateway)
  right=172.16.0.2
  rightauth=psk

  leftsubnet=10.10.20.0/24
  rightsubnet=10.10.10.0/24

EOF"
  sudo bash -c "cat << EOF > $INITIATOR_CFG_DIR/strongswan.conf
charon {
  load_modular = yes
  plugins {
    include strongswan.d/charon/*.conf
    attr {
      dns = 8.8.8.8, 8.8.4.4
    }
  }
  filelog {
    charon {
      path=/var/log/charon.log
      time_format = %b %e %T
      ike_name = yes
      append = no
      default = 4
      flush_line = yes
    }
  }
}
include strongswan.d/*.conf
EOF"
  sudo bash -c "cat << EOF > $INITIATOR_CFG_DIR/ipsec.secrets
: PSK 'Vpp123'
EOF"
}

start() {
  responder_conf
  initiator_conf
  grpc_conf
  vpp_conf

  echo "info: starting docker containers"
  (sudo docker run --name responder --hostname responder -d --net=host --privileged -it -e INITIAL_LOGLVL=debug -e ETCD_CONFIG=DISABLED -e KAFKA_CONFIG=DISABLED -v $VPP_CFG_DIR:/etc/vpp -v $AGENT_CFG_DIR:/opt/vpp-agent/dev ligato/vpp-agent:pantheon-dev && sudo docker run --name initiator --hostname initiator -d --privileged -v $INITIATOR_CFG_DIR:/conf -v $INITIATOR_CFG_DIR:/etc/ipsec.d philplckthun/strongswan) &> /dev/null
  if [ $? -ne 0 ]; then
    echo "error: starting docker containers"
    exit 1
  fi

  echo "info: waiting for serivces"
  sleep 2

  echo "info: configuring network"
  (sudo ip link add wan0 type veth peer name wan1 && sudo ip link set netns $(sudo docker inspect --format '{{.State.Pid}}' initiator) dev wan1 && sudo docker exec initiator ip addr add 172.16.0.1/24 dev wan1 && sudo docker exec initiator ip link set wan1 up && sudo docker exec initiator iptables -t nat -F && sudo docker exec initiator ip addr add 10.10.20.1/24 dev lo && sudo docker exec initiator ip route add 10.10.10.0/24 dev wan1 src 10.10.20.1 && grpc_demo_setup) &> /dev/null
  if [ $? -ne 0 ]; then
    echo "error: configuring network"
    exit 1
  fi

  echo "info: starting ipsec"
  sudo ipsec start &> /dev/null

  echo "info: waiting for strongswan"
  sleep 6
  sudo docker exec initiator ipsec up initiator
}

stop() {
  sudo docker stop initiator &> /dev/null
  sudo docker container rm initiator &> /dev/null

  sudo docker stop responder &> /dev/null
  sudo docker container rm responder &> /dev/null

  sudo ipsec stop &> /dev/null
}

enter_initiator() {
  sudo docker exec -it initiator /bin/bash
}

enter_responder() {
  sudo docker exec -it responder vppctl -s 0:5002
}

case "$1" in
  initiator)
        enter_initiator
        ;;
  responder)
        enter_responder
        ;;
  restart)
        stop
        start
        ;;
  start)
        start
        ;;
  stop)
        stop
        ;;
  *)
        echo $"Usage: $0 {start|stop|restart|initiator|responder}"
        exit 1
esac

exit 0

