#!/usr/bin/env bash
# Measure incremental `cargo check` and `cargo build` after touching a leaf crate and the
# core crate. Fails if a step exceeds its limit (seconds). PLAN.md targets: 5 s / 15 s.
set -euo pipefail
cd "$(dirname "$0")/.."
CHECK_LIMIT=${CHECK_LIMIT:-5}
BUILD_LIMIT=${BUILD_LIMIT:-15}
export SQLX_OFFLINE=true

cargo build --workspace --quiet
cargo check --workspace --quiet

measure() {
  local start end
  start=$(date +%s.%N)
  "$@" >/dev/null 2>&1
  end=$(date +%s.%N)
  echo "$end - $start" | bc
}

fail=0
for file in crates/api/src/lib.rs crates/mta/src/lib.rs; do
  touch "$file"
  t=$(measure cargo check --workspace)
  echo "check after touching $file: ${t}s (limit ${CHECK_LIMIT}s)"
  (( $(echo "$t > $CHECK_LIMIT" | bc) )) && fail=1
  touch "$file"
  t=$(measure cargo build --workspace)
  echo "build after touching $file: ${t}s (limit ${BUILD_LIMIT}s)"
  (( $(echo "$t > $BUILD_LIMIT" | bc) )) && fail=1
done
exit $fail
