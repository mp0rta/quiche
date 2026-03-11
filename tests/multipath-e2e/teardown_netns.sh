#!/bin/bash
set -euo pipefail
ip netns del ns_client 2>/dev/null || true
ip netns del ns_server 2>/dev/null || true
echo "netns cleanup complete"
