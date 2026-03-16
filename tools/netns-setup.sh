#!/bin/bash
# Create 3-namespace multipath test topology.
#
#  [mp-client]         [mp-router]         [mp-server]
#   c-eth0 <--veth--> r-eth0  r-eth2 <--veth--> s-eth0
#   10.0.1.1           10.0.1.254  10.0.3.254    10.0.3.1
#
#   c-eth1 <--veth--> r-eth1  r-eth3 <--veth--> s-eth1
#   10.0.2.1           10.0.2.254  10.0.4.254    10.0.4.1
#
# Both paths converge on server 10.0.3.1:4433 (single socket).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Teardown first for idempotency
bash "$SCRIPT_DIR/netns-teardown.sh"

# Create namespaces
ip netns add mp-client
ip netns add mp-router
ip netns add mp-server

# --- Path 1: client ↔ router ---
ip link add c-eth0 type veth peer name r-eth0
ip link set c-eth0 netns mp-client
ip link set r-eth0 netns mp-router
ip netns exec mp-client ip addr add 10.0.1.1/24 dev c-eth0
ip netns exec mp-router ip addr add 10.0.1.254/24 dev r-eth0
ip netns exec mp-client ip link set c-eth0 up
ip netns exec mp-router ip link set r-eth0 up

# --- Path 2: client ↔ router ---
ip link add c-eth1 type veth peer name r-eth1
ip link set c-eth1 netns mp-client
ip link set r-eth1 netns mp-router
ip netns exec mp-client ip addr add 10.0.2.1/24 dev c-eth1
ip netns exec mp-router ip addr add 10.0.2.254/24 dev r-eth1
ip netns exec mp-client ip link set c-eth1 up
ip netns exec mp-router ip link set r-eth1 up

# --- Path 1: router ↔ server ---
ip link add r-eth2 type veth peer name s-eth0
ip link set r-eth2 netns mp-router
ip link set s-eth0 netns mp-server
ip netns exec mp-router ip addr add 10.0.3.254/24 dev r-eth2
ip netns exec mp-server ip addr add 10.0.3.1/24 dev s-eth0
ip netns exec mp-router ip link set r-eth2 up
ip netns exec mp-server ip link set s-eth0 up

# --- Path 2: router ↔ server ---
ip link add r-eth3 type veth peer name s-eth1
ip link set r-eth3 netns mp-router
ip link set s-eth1 netns mp-server
ip netns exec mp-router ip addr add 10.0.4.254/24 dev r-eth3
ip netns exec mp-server ip addr add 10.0.4.1/24 dev s-eth1
ip netns exec mp-router ip link set r-eth3 up
ip netns exec mp-server ip link set s-eth1 up

# --- Loopback (needed for some tools) ---
for ns in mp-client mp-router mp-server; do
    ip netns exec "$ns" ip link set lo up
done

# --- Enable IP forwarding on router ---
ip netns exec mp-router sysctl -w net.ipv4.ip_forward=1 >/dev/null

# --- Client routing ---
ip netns exec mp-client ip route add 10.0.3.0/24 via 10.0.1.254
ip netns exec mp-client ip route add 10.0.4.0/24 via 10.0.2.254

# --- Server routing ---
ip netns exec mp-server ip route add 10.0.1.0/24 via 10.0.3.254
ip netns exec mp-server ip route add 10.0.2.0/24 via 10.0.4.254

echo "netns setup complete (mp-client, mp-router, mp-server)"
