#!/usr/bin/env bash
set -euo pipefail
[[ $# -le 4 ]] || { echo 'Expected OUTPUT_DIR N REPETITIONS WARMUPS.' >&2; exit 2; }
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    echo 'Usage: bash scripts/benchmark_best.sh [OUTPUT_DIR] [N] [REPETITIONS] [WARMUPS]'
    exit 0
fi
exec bash "$(dirname -- "${BASH_SOURCE[0]}")/benchmark.sh" \
    "${1:-artifacts/v1-v2-$(date -u +%Y%m%dT%H%M%SZ)}" "${2:-4096}" "${3:-3}" "${4:-1}" both
