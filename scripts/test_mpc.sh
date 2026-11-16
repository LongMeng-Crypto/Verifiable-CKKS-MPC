#!/usr/bin/env bash
set -euo pipefail
task_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$task_root"
bash scripts/bootstrap_backend.sh
export CARGO_HOME="$task_root/.cargo-cache"
export CARGO_TARGET_DIR="$task_root/target/probe"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-4}"
export RUST_TEST_THREADS=1
cargo test --locked --release -j 1 -p vmpckks
if [[ ${1:-} == --upstream ]]; then
    CARGO_TARGET_DIR="$task_root/target/upstream" cargo test --locked --release -j 1 \
        --manifest-path vendor/Plonky3/Cargo.toml \
        -p p3-goldilocks -p p3-sha256 -p p3-sha256-air -p p3-symmetric \
        -p p3-merkle-tree -p p3-challenger -p p3-fri -p p3-security \
        -p p3-uni-stark -p p3-batch-stark -p p3-lookup --lib --tests
fi
