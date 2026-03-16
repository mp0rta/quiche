#!/bin/bash
# Teardown multipath test network namespaces (idempotent).
set -euo pipefail
for ns in mp-client mp-router mp-server; do
    ip netns del "$ns" 2>/dev/null || true
done
echo "netns teardown complete"
