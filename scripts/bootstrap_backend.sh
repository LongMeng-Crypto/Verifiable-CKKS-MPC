#!/usr/bin/env bash
set -euo pipefail
task_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$task_root"
revision=$(cat dependencies/plonky3-revision.txt)
if [[ ! -d vendor/Plonky3 ]]; then
    mkdir -p vendor/Plonky3
    git -C vendor/Plonky3 init --quiet
    git -C vendor/Plonky3 remote add origin https://github.com/Plonky3/Plonky3.git
    git -C vendor/Plonky3 fetch --depth 1 origin "$revision"
    git -C vendor/Plonky3 checkout --detach FETCH_HEAD
fi
[[ $(git -C vendor/Plonky3 rev-parse HEAD) == "$revision" ]] || {
    echo 'Plonky3 revision mismatch; existing checkout left untouched.' >&2
    exit 1
}
git -C vendor/Plonky3 diff --cached --quiet
combined_patch=$(mktemp)
trap 'rm -f "$combined_patch"' EXIT
cat dependencies/plonky3-verifier-cache.patch dependencies/plonky3-public-data.patch \
    dependencies/plonky3-periodic-batch.patch dependencies/plonky3-parallel-salts.patch > "$combined_patch"
if git -C vendor/Plonky3 diff --quiet; then
    git -C vendor/Plonky3 apply --check "$combined_patch"
    git -C vendor/Plonky3 apply "$combined_patch"
fi
git -C vendor/Plonky3 diff --binary --full-index --no-ext-diff --no-color \
    --no-renames --unified=3 --src-prefix=a/ --dst-prefix=b/ | cmp - "$combined_patch"
if [[ ! -f vendor/Plonky3/Cargo.lock ]]; then
    cp dependencies/plonky3-Cargo.lock vendor/Plonky3/Cargo.lock
fi
cmp dependencies/plonky3-Cargo.lock vendor/Plonky3/Cargo.lock
echo "Pinned Plonky3: $revision with four reviewed patches"
