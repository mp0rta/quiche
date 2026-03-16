#!/bin/bash
# Convenience wrapper: setup netns → build → run E2E tests → teardown.
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Detect active Rust toolchain for sudo environment.
TOOLCHAIN="$(rustup show active-toolchain 2>/dev/null | awk '{print $1}')"

sudo "$SCRIPT_DIR/netns-setup.sh"
trap 'sudo "$SCRIPT_DIR/netns-teardown.sh"' EXIT

cd "$REPO_ROOT"
cargo build --features multipath
# Tests share a single port (4433) in the same netns, so they must run serially.
sudo env "PATH=$PATH" "RUSTUP_TOOLCHAIN=${TOOLCHAIN}" \
    cargo test --features multipath -p quiche --test multipath_e2e -- --ignored --test-threads=1 "$@"
