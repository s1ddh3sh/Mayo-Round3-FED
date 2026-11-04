#!/usr/bin/env bash
#
# run_tests_all.sh — build and run the full Unicorn paired-sweep pipeline
# for every MAYO function listed in mayo.json (or only the ones given),
# several functions at a time.
#
# For each function:
#   1. mayo_build.sh test_mayo/<function>        (build the correct + faulty ELFs)
#   2. run_combined_unicorn.sh <function> --seeds 0,1,2,3
#
# Functions are independent (each writes only test_mayo/<function>/ and
# build/test_mayo/<function>/), so up to -j of them run in parallel. Each
# function's output goes to build/run_tests_all_logs/<function>.log; this
# script prints one line per function as it finishes, then the summary.
#
# Timing: each function's line gives its build and test time, its number of
# faulty ELFs and the average time per faulty ELF (functions differ a lot in
# how many faults they have, so the total alone does not compare). The end
# summary gives the average over all functions and the overall average per
# faulty ELF. All of it is also written to build/run_tests_all_logs/timings.csv
# (one row per function of this run; overwritten each run).
#
# Run from anywhere: the script cds to llvm/. mayo.json is read from the
# MAYO-C root.
#
# Usage:
#   ./dist_tests/mayo/run_tests_all.sh [-j N] [function ...]
#
#   -j N        functions run at once (default: number of CPUs)
#   function    only these mayo.json keys (default: all of them)
#
# A single function's failure (build or test) does not stop the sweep --
# it is recorded and reported in the summary at the end, and the script
# exits non-zero if anything failed.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."   # llvm/: test_mayo/ and build/ are relative to it
CONFIG_JSON="../mayo.json" # MAYO-C root
MAYO_BUILD="${SCRIPT_DIR}/mayo_build.sh"
RUN_UNICORN="${SCRIPT_DIR}/run_combined_unicorn.sh"
SEEDS="0,1,2,3"
LOG_DIR="build/run_tests_all_logs"
TIMINGS_CSV="${LOG_DIR}/timings.csv"
JOBS="$(nproc)"

REQUESTED=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -j) JOBS="$2"; shift 2 ;;
        -j*) JOBS="${1#-j}"; shift ;;
        -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
        -*) echo "[!] unrecognized option: $1" >&2; exit 1 ;;
        *) REQUESTED+=("$1"); shift ;;
    esac
done
if ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
    echo "[!] -j needs a positive integer, got '${JOBS}'" >&2
    exit 1
fi

if [[ ! -f "$CONFIG_JSON" ]]; then
    echo "[!] ${CONFIG_JSON} not found -- expected at the MAYO-C root" >&2
    exit 1
fi

for req in "$MAYO_BUILD" "$RUN_UNICORN"; do
    if [[ ! -x "$req" ]]; then
        echo "[!] required script not found or not executable: ${req}" >&2
        exit 1
    fi
done

mapfile -t ALL_FUNCS < <(python3 -c "
import json, sys
with open('${CONFIG_JSON}') as f:
    print('\n'.join(json.load(f).keys()))
")

if [[ ${#REQUESTED[@]} -gt 0 ]]; then
    FUNCS=()
    for func in "${REQUESTED[@]}"; do
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

mkdir -p "$LOG_DIR"
echo "[i] ${#FUNCS[@]} function(s), up to ${JOBS} at a time; logs in ${LOG_DIR}/"

# Seconds (3 decimals) since the EPOCHREALTIME stamp $1.
elapsed() {
    awk -v a="$1" -v b="$EPOCHREALTIME" 'BEGIN { printf "%.3f", b - a }'
}

# One function: build, then test. Output goes to its log, and
# "<build_s> <test_s>" to <log>.time (test_s is 0 if the build failed); the
# exit status says which step failed (0 ok, 1 build, 2 test).
run_one() {
    local func="$1" log="${LOG_DIR}/$1.log" tfile="${LOG_DIR}/$1.time"
    local t0 tb="0" tt="0" status=0
    t0=$EPOCHREALTIME
    {
        echo "=== [build] ${MAYO_BUILD} test_mayo/${func} ==="
        "$MAYO_BUILD" "test_mayo/${func}"
    } > "$log" 2>&1 || status=1
    tb="$(elapsed "$t0")"
    if [[ $status -eq 0 ]]; then
        t0=$EPOCHREALTIME
        {
            echo
            echo "=== [test] ${RUN_UNICORN} ${func} --seeds ${SEEDS} ==="
            "$RUN_UNICORN" "$func" --seeds "$SEEDS"
        } >> "$log" 2>&1 || status=2
        tt="$(elapsed "$t0")"
    fi
    echo "$tb $tt" > "$tfile"
    return $status
}

# Faulty ELFs of a function (same set run_combined_unicorn.sh tests).
count_faulty_elfs() {
    local dir="build/test_mayo/$1"
    [[ -d "$dir" ]] || { echo 0; return; }
    find "$dir" -type f -name '*.elf' -not -path '*/full_mayo_gated/*' \
        -not -name "$1.elf" | wc -l
}

# Kill the running functions too if the sweep itself is interrupted.
trap 'echo; echo "[!] interrupted -- stopping running functions" >&2; kill $(jobs -p) 2>/dev/null; wait; exit 130' INT TERM

declare -A PID_FUNC=()
FAILED=()
N_DONE=0
T0=$EPOCHREALTIME
echo "function,status,build_s,test_s,total_s,faulty_elfs,avg_s_per_faulty_elf" > "$TIMINGS_CSV"

# Reap one finished function and report it.
reap_one() {
    local pid status func
    wait -n -p pid
    status=$?
    func="${PID_FUNC[$pid]}"
    unset "PID_FUNC[$pid]"
    N_DONE=$((N_DONE + 1))

    local tb=0 tt=0 n_elf total per_elf timing word
    read -r tb tt < "${LOG_DIR}/${func}.time" 2>/dev/null || true
    n_elf="$(count_faulty_elfs "$func")"
    total="$(awk -v a="$tb" -v b="$tt" 'BEGIN { printf "%.1f", a + b }')"
    per_elf="$(awk -v t="$tt" -v n="$n_elf" 'BEGIN { if (n > 0) printf "%.1f", t / n; else printf "-" }')"
    timing="$(awk -v t="$total" -v b="$tb" -v x="$tt" -v n="$n_elf" -v p="$per_elf" \
        'BEGIN { printf "%ss (build %.1fs, test %.1fs; %d faulty ELF(s), %ss each)", t, b, x, n, p }')"

    case "$status" in
        0) word=ok;    echo "[${N_DONE}/${#FUNCS[@]}] OK            ${func}  ${timing}" ;;
        1) word=build; echo "[${N_DONE}/${#FUNCS[@]}] FAILED build  ${func}  ${timing} -- see ${LOG_DIR}/${func}.log" >&2
           FAILED+=("${func} (build)") ;;
        *) word=test;  echo "[${N_DONE}/${#FUNCS[@]}] FAILED test   ${func}  ${timing} -- see ${LOG_DIR}/${func}.log" >&2
           FAILED+=("${func} (test)") ;;
    esac
    echo "${func},${word},${tb},${tt},${total},${n_elf},${per_elf}" >> "$TIMINGS_CSV"
}

for func in "${FUNCS[@]}"; do
    while [[ ${#PID_FUNC[@]} -ge $JOBS ]]; do
        reap_one
    done
    run_one "$func" &
    PID_FUNC[$!]="$func"
done
while [[ ${#PID_FUNC[@]} -gt 0 ]]; do
    reap_one
done

echo
echo "=== Summary: $((${#FUNCS[@]} - ${#FAILED[@]}))/${#FUNCS[@]} function(s) completed successfully in $(printf '%.1f' "$(elapsed "$T0")")s wall time (-j ${JOBS}) ==="
# Averages over the successful functions only: a failed build/test stops
# early and would pull the averages down.
awk -F, 'NR > 1 && $2 == "ok" {
        n++; build += $3; test += $4; total += $5; elfs += $6
    }
    END {
        if (!n) { print "[i] no successful function to average"; exit }
        printf "[i] average per function (%d ok): %.1fs (build %.1fs, test %.1fs)\n",
               n, total / n, build / n, test / n
        if (elfs) printf "[i] average per faulty ELF (%d ELFs): %.1fs of test time\n",
                         elfs, test / elfs
    }' "$TIMINGS_CSV"
echo "[i] per-function timings: ${TIMINGS_CSV}"
if [[ "${#FAILED[@]}" -gt 0 ]]; then
    echo "Failed:" >&2
    printf '  %s\n' "${FAILED[@]}" >&2
    exit 1
fi
