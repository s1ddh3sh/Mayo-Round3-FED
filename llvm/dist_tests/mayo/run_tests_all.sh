#!/usr/bin/env bash
#
# run_tests_all.sh — build and run the full Unicorn paired-sweep pipeline
# for EVERY MAYO function listed in mayo.json.
#
# For each function in mayo.json, in order:
#   1. ./mayo_build.sh test_mayo/<function>   (build the correct + faulty ELFs)
#   2. ./dist_tests/mayo/run_tests_unicorn.sh <function> --seeds 0,1,2,3
#
# Like run_tests_unicorn.sh, this script must be run from the repo root
# (mayo.json and mayo_build.sh are repo-root-relative).
#
# Usage:
#   ./dist_tests/mayo/run_tests_all.sh
#
# A single function's failure (build or test) does not stop the sweep --
# it is recorded and reported in the summary at the end, and the script
# exits non-zero if anything failed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."   # llvm/: test_mayo/ and build/ are relative to it
CONFIG_JSON="../mayo.json" # MAYO-C root
MAYO_BUILD="${SCRIPT_DIR}/mayo_build.sh"
RUN_UNICORN="${SCRIPT_DIR}/run_combined_unicorn.sh"
SEEDS="0,1,2,3"

if [[ ! -f "$CONFIG_JSON" ]]; then
    echo "[!] ${CONFIG_JSON} not found -- expected at the MAYO-C root" >&2
    exit 1
fi

if [[ ! -x "$MAYO_BUILD" ]]; then
    echo "[!] ${MAYO_BUILD} not found or not executable -- expected at the MAYO-C root" >&2
    exit 1
fi

if [[ ! -x "$RUN_UNICORN" ]]; then
    echo "[!] required script not found or not executable: ${RUN_UNICORN}" >&2
    exit 1
fi

mapfile -t FUNCS < <(python3 -c "
import json, sys
with open('${CONFIG_JSON}') as f:
    print('\n'.join(json.load(f).keys()))
")

if [[ "${#FUNCS[@]}" -eq 0 ]]; then
    echo "[!] no functions found in ${CONFIG_JSON}" >&2
    exit 1
fi

echo "[i] found ${#FUNCS[@]} function(s) in ${CONFIG_JSON}"

FAILED=()
for func in "${FUNCS[@]}"; do
    echo
    echo "############################################"
    echo "# ${func}"
    echo "############################################"

    echo
    echo "=== [build] ${MAYO_BUILD} test_mayo/${func} ==="
    if ! "$MAYO_BUILD" "test_mayo/${func}"; then
        echo "[!] FAILED (build): ${func}" >&2
        FAILED+=("${func} (build)")
        continue
    fi

    echo
    echo "=== [test] ${RUN_UNICORN} ${func} --seeds ${SEEDS} ==="
    if ! "$RUN_UNICORN" "$func" --seeds "$SEEDS"; then
        echo "[!] FAILED (test): ${func}" >&2
        FAILED+=("${func} (test)")
        continue
    fi

    echo "[i] OK: ${func}"
done

echo
echo "=== Summary: $((${#FUNCS[@]} - ${#FAILED[@]}))/${#FUNCS[@]} function(s) completed successfully ==="
if [[ "${#FAILED[@]}" -gt 0 ]]; then
    echo "Failed:" >&2
    printf '  %s\n' "${FAILED[@]}" >&2
    exit 1
fi
