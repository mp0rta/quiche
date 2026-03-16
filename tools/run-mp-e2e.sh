#!/bin/bash
# Convenience wrapper: setup netns → build → run E2E tests → teardown.
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

sudo "$SCRIPT_DIR/netns-setup.sh"
trap 'sudo "$SCRIPT_DIR/netns-teardown.sh"' EXIT

cd "$REPO_ROOT"
cargo build --features multipath
sudo -E cargo test --features multipath -p quiche --test multipath_e2e -- --ignored "$@"
