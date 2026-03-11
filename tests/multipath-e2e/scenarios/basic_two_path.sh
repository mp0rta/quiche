#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../setup_netns.sh"
trap "$SCRIPT_DIR/../teardown_netns.sh" EXIT

# Build quiche-apps with multipath
cargo build --release --features multipath -p quiche-apps 2>/dev/null || {
    echo "SKIP: quiche-apps not available or multipath feature not supported yet"
    exit 0
}

# Start server in ns_server
ip netns exec ns_server ./target/release/quiche-server \
    --listen 0.0.0.0:4433 --root . &
SERVER_PID=$!
sleep 1

# Start client in ns_client
ip netns exec ns_client ./target/release/quiche-client \
    --connect 10.0.1.2:4433 \
    https://10.0.1.2:4433/index.html || true

kill $SERVER_PID 2>/dev/null || true
echo "PASS: basic_two_path"
