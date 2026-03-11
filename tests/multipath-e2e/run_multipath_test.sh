#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Multipath QUIC E2E Tests ==="

for scenario in "$SCRIPT_DIR"/scenarios/*.sh; do
    echo "Running: $(basename "$scenario")"
    if bash "$scenario"; then
        echo "  PASS"
    else
        echo "  FAIL"
        exit 1
    fi
done

echo "=== All tests passed ==="
