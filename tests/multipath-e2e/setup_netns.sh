#!/bin/bash
set -euo pipefail

# Create network namespaces
ip netns add ns_client
ip netns add ns_server

# Path 1: low latency
ip link add veth0 type veth peer name veth1
ip link set veth0 netns ns_client
ip link set veth1 netns ns_server
ip netns exec ns_client ip addr add 10.0.1.1/24 dev veth0
ip netns exec ns_server ip addr add 10.0.1.2/24 dev veth1
ip netns exec ns_client ip link set veth0 up
ip netns exec ns_server ip link set veth1 up
# 5ms RTT
ip netns exec ns_client tc qdisc add dev veth0 root netem delay 2.5ms

# Path 2: higher latency
ip link add veth2 type veth peer name veth3
ip link set veth2 netns ns_client
ip link set veth3 netns ns_server
ip netns exec ns_client ip addr add 10.0.2.1/24 dev veth2
ip netns exec ns_server ip addr add 10.0.2.2/24 dev veth3
ip netns exec ns_client ip link set veth2 up
ip netns exec ns_server ip link set veth3 up
# 50ms RTT
ip netns exec ns_client tc qdisc add dev veth2 root netem delay 25ms

echo "netns setup complete"
