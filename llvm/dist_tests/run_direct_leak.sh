#!/usr/bin/env bash
#
# run_direct_leak.sh -- run the direct-leak test (dist_tests/direct_leak.py:
# do the output positions a fault changes now hold the secret-buf, or else
# an eph_secret, at the same index?) for
#
#   1. one function:          ./dist_tests/run_direct_leak.sh mayo <func>
#   2. every function of mayo.json:
#                             ./dist_tests/run_direct_leak.sh [mayo]
#
# Run from anywhere: the script cds to llvm/ (test_mayo/, build/test_mayo/
# are relative to it); mayo.json is read from the MAYO-C root.
#
# Options (after the positional arguments):
#   --traces N   existing trace pairs to use per faulty ELF, taken round-robin
#                over its collected directories (0 = all). Default 16.
#   --csv PATH   summary CSV, one row per faulty ELF, in generic_tests_plot.py's
#                schema. Default ../direct_leak_report.csv (the MAYO-C root,
#                where generic_tests_plot.py reads it). Not overwritten: the
#                rows of each function tested are replaced in place (or
#                appended if new); other functions' rows are kept.
#   --elf-timeout SECS   per faulty ELF: no verdict within SECS -> recorded as
#                "timeout" and the next ELF is tested. Default 120 (0 = none).
#   --func-timeout SECS  per function: the whole function is killed after SECS,
#                reported as timed out and skipped; the ELFs it finished keep
#                their CSV rows. Default 1800 (0 = none).
#
# Before testing a function, any ELF missing for a .ll under
# test_mayo/<func>/ is built with dist_tests/mayo/mayo_build.sh test_mayo/<func>.
#
# Each faulty ELF's verdict is also written to
#   test_mayo/<func>/<faulty_stem>/direct_leak_result.txt
# A function that fails (no correct ELF, not in the json, ...) is reported
# and skipped; the script exits non-zero if any function failed.

set -uo pipefail

SCHEME="mayo"
FUNC=""
TRACES=16
CSV="../direct_leak_report.csv"
ELF_TIMEOUT=120
FUNC_TIMEOUT=1800

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --traces) TRACES="$2"; shift 2 ;;
        --csv) CSV="$2"; shift 2 ;;
        --elf-timeout) ELF_TIMEOUT="$2"; shift 2 ;;
        --func-timeout) FUNC_TIMEOUT="$2"; shift 2 ;;
        -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
        --*) echo "[!] unrecognized option: $1" >&2; exit 1 ;;
        *) POSITIONAL+=("$1"); shift ;;
    esac
done
if [[ ${#POSITIONAL[@]} -ge 1 && "${POSITIONAL[0]}" != "mayo" ]]; then
    echo "[!] unknown scheme '${POSITIONAL[0]}' (this repo has mayo only)" >&2
    exit 1
fi
[[ ${#POSITIONAL[@]} -ge 2 ]] && FUNC="${POSITIONAL[1]}"
if [[ ${#POSITIONAL[@]} -gt 2 ]]; then
    echo "Usage: $0 [mayo [<func>]] [--traces N] [--csv PATH] [--elf-timeout SECS] [--func-timeout SECS]" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_PY="${SCRIPT_DIR}/direct_leak.py"
MAYO_BUILD="${SCRIPT_DIR}/mayo/mayo_build.sh"
CONFIG_JSON="../mayo.json"
# A relative --csv is relative to the caller's cwd, so resolve it before the cd.
[[ "$CSV" != /* ]] && CSV="$(realpath -m "$CSV")"
cd "${SCRIPT_DIR}/.."   # llvm/

# Build the function's ELFs if any are missing: every .ll under
# test_mayo/<func>/ should have its ELF at build/test_mayo/<func>/ (same
# relative path, .elf). If one is missing, mayo_build.sh is run on that
# function directory, which compiles every .ll in it. Returns non-zero if
# the build fails.
ensure_elfs() {
    local func="$1" dir="test_mayo/$1" missing=0 ll
    if [[ ! -d "$dir" ]]; then
        echo "[!] ${dir} not found: nothing to build" >&2
        return 1
    fi
    while IFS= read -r -d '' ll; do
        if [[ ! -f "build/${ll%.ll}.elf" ]]; then
            missing=$((missing + 1))
        fi
    done < <(find -L "$dir" -type f -name '*.ll' -print0)
    [[ "$missing" -eq 0 && -f "${dir}/qemu_witness.json" ]] && return 0
    echo "[i] ${missing} ELF(s) or the witness missing for ${func}: running mayo_build.sh ${dir}"
    "$MAYO_BUILD" "$dir"
}

# Function keys of mayo.json, one per line.
functions_of() {
    python3 - "$CONFIG_JSON" <<'PYEOF'
import json, sys
for name in json.load(open(sys.argv[1])):
    print(name)
PYEOF
}

if [[ -n "$FUNC" ]]; then
    FUNCS=("$FUNC")
else
    [[ -f "$CONFIG_JSON" ]] || { echo "[!] ${CONFIG_JSON} not found" >&2; exit 1; }
    mapfile -t FUNCS < <(functions_of)
fi

FAILED=()
TIMED_OUT=()
N_RUN=0
echo ""
echo "################ ${SCHEME}: ${#FUNCS[@]} function(s) ################"
for func in "${FUNCS[@]}"; do
    echo ""
    echo "=== direct-leak test: ${SCHEME} / ${func} ==="
    if ! ensure_elfs "$func"; then
        echo "[!] build failed for ${SCHEME}/${func}; testing whatever ELFs exist" >&2
    fi
    # timeout 0 = no limit (coreutils semantics).
    timeout --signal=TERM --kill-after=10 "$FUNC_TIMEOUT" \
        python3 -u "$TEST_PY" --scheme "$SCHEME" --func "$func" \
            --traces "$TRACES" --csv "$CSV" --elf-timeout "$ELF_TIMEOUT"
    status=$?
    if [[ $status -eq 0 ]]; then
        N_RUN=$((N_RUN + 1))
    elif [[ $status -eq 124 || $status -eq 137 ]]; then
        echo "[!] TIMED OUT after ${FUNC_TIMEOUT}s: ${SCHEME}/${func} -- skipped, moving on to the next function" >&2
        TIMED_OUT+=("${SCHEME}/${func}")
    else
        FAILED+=("${SCHEME}/${func}")
    fi
done

echo ""
echo "=== direct-leak test complete: ${N_RUN} function(s) run, ${#TIMED_OUT[@]} timed out, ${#FAILED[@]} failed ==="
if [[ -s "$CSV" ]]; then
    python3 - "$CSV" <<'PYEOF'
import csv, sys, collections
rows = list(csv.DictReader(open(sys.argv[1])))
by = collections.defaultdict(collections.Counter)
for r in rows:
    by[r["scheme"]][r["detected"]] += 1
for scheme, c in by.items():
    print(f"[i] {scheme}: {c['yes']} detected / {sum(c.values())} faulty ELF(s) "
          f"(no {c['no']}, timeout {c['timeout']}, skipped {c['skip']}, "
          f"error {c['error']})")
PYEOF
    echo "[i] summary CSV (all functions in it, not only this run): ${CSV}"
fi
for f in "${TIMED_OUT[@]}"; do
    echo "[!] timed out: $f" >&2
done
for f in "${FAILED[@]}"; do
    echo "[!] failed: $f" >&2
done
[[ ${#FAILED[@]} -eq 0 ]]
