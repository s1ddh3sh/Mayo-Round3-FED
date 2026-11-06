#!/usr/bin/env bash
#
# run_tests_all.sh — build and run the full Unicorn paired-sweep pipeline
# for EVERY MAYO function listed in mayo.json.
#
# For each function in mayo.json:
#   1. dist_tests/mayo/mayo_build.sh test_mayo/<function>   (build the correct + faulty ELFs)
#   2. dist_tests/mayo/run_combined_unicorn.sh <function> --seeds 0,1,2,3
#
# Each function's build+test is INDEPENDENT of every other function, so the
# functions are run in parallel across a bounded pool of worker jobs. Each
# function's full output is streamed to its own log file (so parallel output
# does not interleave), and a one-line PASS/FAIL is printed per function once
# all of them have finished.
#
# Run from anywhere: the script cds to llvm/ (test_mayo/, build/ are relative
# to it); mayo.json is read from the MAYO-C root.
#
# Usage:
#   ./dist_tests/mayo/run_tests_all.sh [-j N] [func ...]
#
#   -j N        number of functions to process in parallel
#               (default: number of CPUs, $(nproc))
#   func ...    optional explicit list of functions to run (keys of
#               mayo.json); if omitted, every key in mayo.json is run.
#
# Timing: each function's wall time (build + test) is upserted into
# dist_tests/mayo/timing_mayo.csv (function,status,seconds -- re-runs update
# rows in place), and this scheme's average into the cross-scheme
# dist_tests/timing_schemes_summary.csv (one row per scheme plus a pooled
# ALL row), via dist_tests/common/upsert_timing.py.
#
# A single function's failure (build or test) does not stop the sweep --
# it is recorded and reported in the summary at the end, and the script
# exits non-zero if anything failed. Logs are kept only for failed
# functions (copied to <log dir>.failed/).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."   # llvm/: test_mayo/ and build/ are relative to it
CONFIG_JSON="../mayo.json" # MAYO-C root
MAYO_BUILD="${SCRIPT_DIR}/mayo_build.sh"
RUN_UNICORN="${SCRIPT_DIR}/run_combined_unicorn.sh"
SEEDS="0,1,2,3"

SCHEME="mayo"
UPSERT_PY="${SCRIPT_DIR}/../common/upsert_timing.py"
PERFUNC_CSV="${SCRIPT_DIR}/timing_${SCHEME}.csv"        # per-function timings
SUMMARY_CSV="${SCRIPT_DIR}/../timing_schemes_summary.csv"  # avg over all schemes

JOBS="$(nproc 2>/dev/null || echo 4)"

# ---- arg parse: -j N, then an optional explicit function list -------------
EXPLICIT_FUNCS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -j|--jobs) JOBS="$2"; shift 2 ;;
        -j*)       JOBS="${1#-j}"; shift ;;
        --)        shift; EXPLICIT_FUNCS+=("$@"); break ;;
        -*)        echo "[!] unrecognized argument: $1" >&2; exit 1 ;;
        *)         EXPLICIT_FUNCS+=("$1"); shift ;;
    esac
done

if ! [[ "$JOBS" =~ ^[0-9]+$ && "$JOBS" -ge 1 ]]; then
    echo "[!] -j must be a positive integer (got: ${JOBS})" >&2
    exit 1
fi

if [[ ! -f "$CONFIG_JSON" ]]; then
    echo "[!] ${CONFIG_JSON} not found -- expected at the MAYO-C root" >&2
    exit 1
fi
if [[ ! -x "$MAYO_BUILD" ]]; then
    echo "[!] ${MAYO_BUILD} not found or not executable" >&2
    exit 1
fi
if [[ ! -x "$RUN_UNICORN" ]]; then
    echo "[!] required script not found or not executable: ${RUN_UNICORN}" >&2
    exit 1
fi

mapfile -t ALL_FUNCS < <(python3 -c "
import json
with open('${CONFIG_JSON}') as f:
    print('\n'.join(json.load(f).keys()))
")

if [[ "${#EXPLICIT_FUNCS[@]}" -gt 0 ]]; then
    # Only keys of mayo.json: run_combined_unicorn.sh reads its secret-buf
    # etc. from there, so any other name would just fail later.
    FUNCS=()
    for func in "${EXPLICIT_FUNCS[@]}"; do
        if printf '%s\n' "${ALL_FUNCS[@]}" | grep -qxF -- "$func"; then
            FUNCS+=("$func")
        else
            echo "[!] '${func}' is not a key of ${CONFIG_JSON}; skipped" >&2
        fi
    done
else
    FUNCS=("${ALL_FUNCS[@]}")
fi

if [[ "${#FUNCS[@]}" -eq 0 ]]; then
    echo "[!] no functions to run" >&2
    exit 1
fi

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mayo_run_all.XXXXXX")"
trap 'rm -rf "$LOG_DIR"' EXIT

echo "[i] ${#FUNCS[@]} function(s) to run, up to ${JOBS} in parallel"
echo "[i] per-function logs: ${LOG_DIR}/<func>.log"

# ---- one function: build then test, capturing status and wall-clock time ---
run_one() {
    local func="$1"
    local log="${LOG_DIR}/${func}.log"
    local rc="ok" start end
    start="$(date +%s.%N)"
    {
        echo "############################################"
        echo "# ${func}"
        echo "############################################"
        echo
        echo "=== [build] ${MAYO_BUILD} test_mayo/${func} ==="
        if ! "$MAYO_BUILD" "test_mayo/${func}"; then
            echo "[!] FAILED (build): ${func}"
            rc="build"
        elif echo && echo "=== [test] ${RUN_UNICORN} ${func} --seeds ${SEEDS} ===" \
             && ! "$RUN_UNICORN" "$func" --seeds "$SEEDS"; then
            echo "[!] FAILED (test): ${func}"
            rc="test"
        else
            echo "[i] OK: ${func}"
        fi
    } >"$log" 2>&1
    end="$(date +%s.%N)"
    echo "$rc" > "${LOG_DIR}/${func}.status"
    awk -v s="$start" -v e="$end" 'BEGIN { printf "%.3f\n", e - s }' > "${LOG_DIR}/${func}.time"
}

# ---- bounded parallel dispatch --------------------------------------------
active=0
for func in "${FUNCS[@]}"; do
    run_one "$func" &
    active=$((active + 1))
    if (( active >= JOBS )); then
        wait -n 2>/dev/null || wait
        active=$((active - 1))
    fi
done
wait

# ---- collect & report ------------------------------------------------------
FAILED=()
TIME_SUM=0
TIME_N=0
PF_STREAM="${LOG_DIR}/perfunc_rows"
: > "$PF_STREAM"
for func in "${FUNCS[@]}"; do
    st="$(cat "${LOG_DIR}/${func}.status" 2>/dev/null || echo "missing")"
    t="$(cat "${LOG_DIR}/${func}.time" 2>/dev/null || echo "")"
    if [[ -n "$t" ]]; then
        TIME_SUM="$(awk -v a="$TIME_SUM" -v b="$t" 'BEGIN { printf "%.3f", a + b }')"
        TIME_N=$((TIME_N + 1))
        tstr="$(awk -v b="$t" 'BEGIN { printf "%8.1fs", b }')"
    else
        tstr="       ?s"
    fi
    printf '%s %s %s\n' "$func" "$st" "${t:-0}" >> "$PF_STREAM"
    case "$st" in
        ok)    echo "[PASS] ${tstr}  ${func}" ;;
        build) echo "[FAIL] ${tstr}  ${func} (build)"; FAILED+=("${func} (build)") ;;
        test)  echo "[FAIL] ${tstr}  ${func} (test)";  FAILED+=("${func} (test)") ;;
        *)     echo "[FAIL] ${tstr}  ${func} (no status -- see ${LOG_DIR}/${func}.log)"; FAILED+=("${func} (crashed)") ;;
    esac
done

# ---- timing CSVs -----------------------------------------------------------
if [[ -f "$UPSERT_PY" ]]; then
    python3 "$UPSERT_PY" perfunc --csv "$PERFUNC_CSV" --scheme "$SCHEME" < "$PF_STREAM" \
        && echo "[i] per-function timings -> ${PERFUNC_CSV}"
    python3 "$UPSERT_PY" summary --csv "$SUMMARY_CSV" --scheme "$SCHEME" \
        --n "$TIME_N" --sum "$TIME_SUM" \
        && echo "[i] cross-scheme summary -> ${SUMMARY_CSV}"
else
    echo "[!] timing CSV helper not found: ${UPSERT_PY} (CSVs not written)" >&2
fi

echo
if [[ "$TIME_N" -gt 0 ]]; then
    awk -v s="$TIME_SUM" -v n="$TIME_N" \
        'BEGIN { printf "=== Timing: avg %.1fs/function over %d function(s) (sum of per-function wall time: %.1fs) ===\n", s / n, n, s }'
fi
echo "=== Summary: $((${#FUNCS[@]} - ${#FAILED[@]}))/${#FUNCS[@]} function(s) completed successfully ==="
if [[ "${#FAILED[@]}" -gt 0 ]]; then
    echo "Failed:" >&2
    printf '  %s\n' "${FAILED[@]}" >&2
    # Keep the logs of failed runs so they can be inspected.
    KEEP_DIR="${LOG_DIR}.failed"
    mkdir -p "$KEEP_DIR"
    for item in "${FAILED[@]}"; do
        f="${item%% *}"
        cp "${LOG_DIR}/${f}.log" "${KEEP_DIR}/" 2>/dev/null || true
    done
    echo "[i] failed-run logs copied to: ${KEEP_DIR}" >&2
    exit 1
fi
