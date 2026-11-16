#!/usr/bin/env bash
set -euo pipefail
task_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$task_root"
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    cat <<'EOF'
Usage: bash scripts/benchmark.sh [OUTPUT_DIR] [N] [REPETITIONS] [WARMUPS] [sha|pk|both]
Defaults: timestamped output, N4096, 10 repetitions, 1 warmup, both variants.
Current V1 periodic/fused and V2 fused/digit8, each at B8/Q100 and B16/Q75.
Eight Rayon workers, native prover/verifier, fresh masks, separate KG/ENC/DEC metrics.
EOF
    exit 0
fi
[[ $# -le 5 ]] || { echo 'Too many arguments.' >&2; exit 2; }
output=${1:-"artifacts/benchmark-$(date -u +%Y%m%dT%H%M%SZ)"}
[[ ! -e "$output" ]] || { echo "Output already exists: $output" >&2; exit 1; }
[[ -z ${CARGO_ENCODED_RUSTFLAGS:-} ]] || { echo 'Unset CARGO_ENCODED_RUSTFLAGS.' >&2; exit 1; }
bash scripts/bootstrap_backend.sh
export CARGO_HOME="$task_root/.cargo-cache"
export CARGO_TARGET_DIR="$task_root/target/probe-native"
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"
export RUSTFLAGS='-C target-cpu=native'
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-8}"
export RUST_TEST_THREADS=1
cargo build --locked --release -j 1 -p vmpckks --bin vmpckks-prover-bench --bin vmpckks
mkdir -p -- "$output"
"$CARGO_TARGET_DIR/release/vmpckks-prover-bench" --out "$output" --n "${2:-4096}" \
    --repetitions "${3:-10}" --warmups "${4:-1}" --variant "${5:-both}" \
    2> >(tee "$output/driver.log" >&2)
echo "Results: $output/comparison.md"
