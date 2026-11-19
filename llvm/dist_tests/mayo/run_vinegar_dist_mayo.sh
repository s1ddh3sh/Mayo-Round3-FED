#!/usr/bin/env bash
#
# run_vinegar_dist_mayo.sh — run vinegar_dist_mayo.py's secret-dependence
# distribution test for a MAYO function, once per faulty gated ELF found under
# build/test_mayo/<func_name>, against that function's correct gated ELF.
#
# The observation point is ALWAYS the signing entry
# pqmayo_MAYO_1_ref_mayo_sign_signature (whose vinegar is captured), regardless
# of <func_name>: the faulty ELF's injected fault may live anywhere in the call
# tree (sign itself, shake256, compute_M_and_VPV, ...), but the target we read
# -- the vinegar V -- is the same. <func_name> only selects which
# full_mayo_gated/ ELF pair to test.
#
# With NO <func_name>, every function's faulty ELFs are tested in one shared
# pool of up to N parallel probes (-j / --jobs, default: nproc). Each probe is
# an independent process writing only its own result dir, so this is safe.
# Functions whose gated ELFs are missing are reported and skipped; the override
# flags apply uniformly to all of them.
#
# ELF layout assumed (default --elf-dir is build/test_mayo/<func_name>):
#   <elf-dir>/full_mayo_gated/gated_<func_name>.elf  -- the correct build
#   <elf-dir>/**/full_mayo_gated/*.elf               -- every other gated .elf
#                                  (searched recursively) is a faulty variant,
#                                  tested one at a time against the correct build.
#
# The gated .ll are expected to ALREADY EXIST under test_mayo/<func_name>/
# (produced by the fault-injection pipeline). This driver only ensures the
# ELFs are compiled from them: if the correct gated ELF is missing under the
# default --elf-dir, it runs mayo_build.sh on the source tree. Pass --no-build
# to disable, or --elf-dir to point at a prebuilt tree (single-func only).
#
# For each faulty ELF, the test's stdout/report are stored in the equivalent
# subdirectory under test_mayo/<func_name>/, e.g.:
#   build/test_mayo/<func>/loopOrFuncSkip/full_mayo_gated/gated_<func>_fnSkip_compute_A_line45.elf
#     -> test_mayo/<func>/loopOrFuncSkip/full_mayo_gated/gated_<func>_fnSkip_compute_A_line45/vinegar_dist_result.txt
#        .../vinegar_dist_report.json
#
# Usage:
#   ./run_vinegar_dist_mayo.sh [<func_name>] [--elf-dir DIR] [--n-seeds N] [--seed N] [--no-build] [-j N] [--timeout S]
#
# Examples:
#   ./run_vinegar_dist_mayo.sh pqmayo_MAYO_1_ref_mayo_sign_signature
#   ./run_vinegar_dist_mayo.sh                      # every function in mayo.json
#   ./run_vinegar_dist_mayo.sh --n-seeds 64 -j 12   # all, parallel, with override

set -uo pipefail

PROBE_FUNC="pqmayo_MAYO_1_ref_mayo_sign_signature"
GATED_DIR="full_mayo_gated"

# Anchor every path to this script's location so the driver works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROBE_PY="${SCRIPT_DIR}/vinegar_dist_mayo.py"
MAYO_BUILD="${SCRIPT_DIR}/mayo_build.sh"
CONFIG_JSON="mayo.json"

# func_name is optional: a leading non-"--" argument is the function; otherwise
# every mayo.json key is run.
FUNC_NAME=""
if [[ $# -gt 0 && "$1" != --* ]]; then
    FUNC_NAME="$1"; shift
fi

ELF_DIR_OVERRIDE=""
N_SEEDS=""
SEED=""
NO_BUILD=0
JOBS="$(nproc 2>/dev/null || echo 1)"
TIMEOUT=300

while [[ $# -gt 0 ]]; do
    case "$1" in
        --elf-dir) ELF_DIR_OVERRIDE="$2"; shift 2 ;;
        --n-seeds) N_SEEDS="$2"; shift 2 ;;
        --seed) SEED="$2"; shift 2 ;;
        --no-build) NO_BUILD=1; shift ;;
        -j|--jobs) JOBS="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "[!] unrecognized argument: $1" >&2; exit 1 ;;
    esac
done

if ! [[ "$JOBS" =~ ^[0-9]+$ ]] || [[ "$JOBS" -lt 1 ]]; then
    echo "[!] --jobs must be a positive integer (got: ${JOBS})" >&2; exit 1
fi
if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
    echo "[!] --timeout must be a non-negative integer (seconds; 0 disables), got: ${TIMEOUT}" >&2; exit 1
fi

# All relative paths are repo-root relative (matching mayo_build.sh's own
# build/test_mayo/... convention), so run from the repo root.
cd "$REPO_ROOT"
[[ -f "$PROBE_PY" ]] || { echo "[!] required script not found: $PROBE_PY" >&2; exit 1; }

EXTRA_ARGS=(--func "$PROBE_FUNC")
[[ -n "$N_SEEDS" ]] && EXTRA_ARGS+=(--n-seeds "$N_SEEDS")
[[ -n "$SEED" ]] && EXTRA_ARGS+=(--seed "$SEED")

# Per-probe wall-clock cap: a hung emulation is killed (SIGTERM, then SIGKILL
# after 10s) and recorded as a timeout, so one bad ELF can't stall the pool.
# --timeout 0 disables it.
TIMEOUT_CMD=()
if [[ "$TIMEOUT" -gt 0 ]]; then
    if command -v timeout >/dev/null 2>&1; then
        TIMEOUT_CMD=(timeout -k 10 "${TIMEOUT}s")
    else
        echo "[!] 'timeout' not found on PATH; running without a per-probe cap" >&2
    fi
fi

# ---------------------------------------------------------------------------
# plan_one_func <func_name> — resolve the function's correct gated ELF (building
# it if missing) and enumerate its faulty gated ELFs, appending one job per
# faulty ELF to the global JOB_* queue. Builds happen here, serially, before any
# parallel probe starts. Returns non-zero (without exiting) on a recoverable
# error so the caller can record the function as skipped and move on.
# ---------------------------------------------------------------------------
plan_one_func() {
    local func_name="$1"
    local src_dir="test_mayo/${func_name}"
    local out_dir="test_mayo/${func_name}"
    local elf_dir elf_dir_default=1
    if [[ -n "$ELF_DIR_OVERRIDE" ]]; then
        elf_dir="$ELF_DIR_OVERRIDE"; elf_dir_default=0
    else
        elf_dir="build/test_mayo/${func_name}"
    fi

    local correct_elf="${elf_dir}/${GATED_DIR}/gated_${func_name}.elf"

    # Build the gated ELFs on demand (gated .ll must already exist; fuseback is
    # NOT run here).
    if [[ ! -f "$correct_elf" && "$NO_BUILD" -eq 0 && "$elf_dir_default" -eq 1 ]]; then
        if [[ ! -d "${src_dir}/${GATED_DIR}" ]]; then
            echo "[!] ${func_name}: no gated ELFs under ${elf_dir} and no gated source IR under ${src_dir}/${GATED_DIR}/ -- skipping" >&2
            return 1
        fi
        [[ -x "$MAYO_BUILD" ]] || { echo "[!] mayo_build.sh not found/executable: $MAYO_BUILD" >&2; return 1; }
        echo "[i] ${func_name}: gated ELFs not found; building ONLY the ${GATED_DIR}/ IR under ${src_dir} (not the per-function .ll) ..."
        local _gdir _built=0
        while IFS= read -r _gdir; do
            echo "[i]   building ${_gdir}"
            "$MAYO_BUILD" "$_gdir" || { echo "[!] ${func_name}: build failed for ${_gdir} -- skipping" >&2; return 1; }
            _built=$((_built + 1))
        done < <(find "$src_dir" -type d -name "${GATED_DIR}" | sort)
        [[ "$_built" -gt 0 ]] || { echo "[!] ${func_name}: no ${GATED_DIR}/ dirs found under ${src_dir} -- skipping" >&2; return 1; }
    fi

    [[ -d "$elf_dir" ]] || { echo "[!] ${func_name}: elf dir not found: $elf_dir -- skipping" >&2; return 1; }
    [[ -f "$correct_elf" ]] || { echo "[!] ${func_name}: correct elf not found: $correct_elf -- skipping" >&2; return 1; }

    local faulty_elfs=()
    while IFS= read -r -d '' f; do
        faulty_elfs+=("$f")
    done < <(find "$elf_dir" -type f -name '*.elf' -path "*/${GATED_DIR}/*" -not -samefile "$correct_elf" -print0 | sort -z)

    if [[ ${#faulty_elfs[@]} -eq 0 ]]; then
        echo "[!] ${func_name}: no faulty gated ELFs found under $elf_dir -- skipping" >&2
        return 1
    fi

    echo "[plan] ${func_name}: observation point ${PROBE_FUNC}, ${#faulty_elfs[@]} faulty ELF(s) under ${elf_dir}"

    FUNC_NJOBS["$func_name"]=${#faulty_elfs[@]}
    local faulty_elf rel result_dir
    for faulty_elf in "${faulty_elfs[@]}"; do
        rel="${faulty_elf#${elf_dir}/}"; rel="${rel%.elf}"
        result_dir="${out_dir}/${rel}"
        JOB_FUNC+=("$func_name")
        JOB_CORRECT+=("$correct_elf")
        JOB_FAULTY+=("$faulty_elf")
        JOB_RESULT_DIR+=("$result_dir")
        JOB_REL+=("$rel")
    done
    return 0
}

# ---------------------------------------------------------------------------
# run_one_job <idx> — one independent probe: the correct ELF vs one faulty ELF.
# Reads only immutable ELFs and writes solely into its own per-faulty-ELF result
# dir, so any number may run concurrently. Records its exit code into RC_DIR for
# the ordered summary pass (parallel jobs can't safely share an array).
# ---------------------------------------------------------------------------
run_one_job() {
    local idx="$1"
    local func_name="${JOB_FUNC[$idx]}"
    local correct_elf="${JOB_CORRECT[$idx]}"
    local faulty_elf="${JOB_FAULTY[$idx]}"
    local result_dir="${JOB_RESULT_DIR[$idx]}"
    local rel="${JOB_REL[$idx]}"
    local status
    mkdir -p "$result_dir"
    echo "[start] ${func_name} / ${rel}"
    # Output is redirected (not tee'd) so concurrent probes don't interleave on
    # the console; the full log still lands in the result file as before.
    # TIMEOUT_CMD (possibly empty) caps the probe's wall-clock time.
    if "${TIMEOUT_CMD[@]}" python3 "$PROBE_PY" \
        --correct-elf "$correct_elf" \
        --faulty-elf "$faulty_elf" \
        --report "${result_dir}/vinegar_dist_report.json" \
        "${EXTRA_ARGS[@]}" \
        > "${result_dir}/vinegar_dist_result.txt" 2>&1; then
        status=0
    else
        status=$?
    fi
    # exit 1 = collapse detected (valid verdict), 0 = no collapse, 2 = emu error,
    # 124/137 = killed by the per-probe timeout.
    echo "$status" > "${RC_DIR}/${idx}.rc"
    echo "[done ] ${func_name} / ${rel} (rc=${status})"
}

# ---------------------------------------------------------------------------
# Single function, or every function directory under test_mayo/ (round3 has no
# mayo.json, so the function list is the set of test_mayo/<func>/ directories).
# ---------------------------------------------------------------------------
if [[ -n "$FUNC_NAME" ]]; then
    FUNCS=("$FUNC_NAME")
else
    [[ -d test_mayo ]] || { echo "[!] test_mayo/ not found (run from llvm/)" >&2; exit 1; }
    FUNCS=()
    while IFS= read -r d; do
        FUNCS+=("$(basename "$d")")
    done < <(find test_mayo -mindepth 1 -maxdepth 1 -type d | sort)
    echo "[i] no func_name given: running all ${#FUNCS[@]} function(s) under test_mayo/"
fi

# Plan pass (serial): resolve the correct ELF and build what's missing for every
# function, collecting one job per (function, faulty ELF) into the global queue.
declare -a JOB_FUNC=() JOB_CORRECT=() JOB_FAULTY=() JOB_RESULT_DIR=() JOB_REL=()
declare -A FUNC_NJOBS=()
SKIPPED=()
for func in "${FUNCS[@]}"; do
    plan_one_func "$func" || SKIPPED+=("$func")
done

TOTAL_JOBS=${#JOB_FAULTY[@]}
if [[ "$TOTAL_JOBS" -eq 0 ]]; then
    echo "[!] nothing to run: no faulty ELFs found for any requested function" >&2
    for f in "${SKIPPED[@]}"; do echo "[!] skipped: $f" >&2; done
    exit 1
fi

echo ""
echo "########## vinegar_dist_mayo: ${TOTAL_JOBS} probe(s) across $(( ${#FUNCS[@]} - ${#SKIPPED[@]} )) function(s), up to ${JOBS} in parallel ##########"
if [[ ${#TIMEOUT_CMD[@]} -gt 0 ]]; then
    echo "[i] per-probe timeout: ${TIMEOUT}s (SIGKILL +10s); pass --timeout 0 to disable"
fi

RC_DIR="$(mktemp -d "${TMPDIR:-/tmp}/mayo_vinegar_rc.XXXXXX")"
trap 'rm -rf "$RC_DIR"' EXIT

# Bounded job pool: launch up to JOBS probes at once, throttling with `wait -n`.
# Same pattern as run_combined_unicorn.sh / run_tests_all.sh.
active=0
for (( idx = 0; idx < TOTAL_JOBS; idx++ )); do
    run_one_job "$idx" &
    active=$((active + 1))
    if (( active >= JOBS )); then
        wait -n 2>/dev/null || wait
        active=$((active - 1))
    fi
done
wait

# ---------------------------------------------------------------------------
# Ordered summary pass: read back each job's recorded exit code and tally per
# function and overall.
# ---------------------------------------------------------------------------
declare -A FN_DETECTED=() FN_FAILS=()
TOTAL_DETECTED=0
TOTAL_FAILS=0
for (( idx = 0; idx < TOTAL_JOBS; idx++ )); do
    func="${JOB_FUNC[$idx]}"
    status="$(cat "${RC_DIR}/${idx}.rc" 2>/dev/null || echo 2)"
    if [[ "$status" -eq 1 ]]; then
        FN_DETECTED["$func"]=$(( ${FN_DETECTED["$func"]:-0} + 1 ))
        TOTAL_DETECTED=$((TOTAL_DETECTED + 1))
    elif [[ "$status" -ne 0 ]]; then
        FN_FAILS["$func"]=$(( ${FN_FAILS["$func"]:-0} + 1 ))
        TOTAL_FAILS=$((TOTAL_FAILS + 1))
        if [[ "$status" -eq 124 || "$status" -eq 137 ]]; then
            echo "[!] TIMEOUT (>${TIMEOUT}s) for ${JOB_FAULTY[$idx]}" >&2
        else
            echo "[!] test failed (exit ${status}) for ${JOB_FAULTY[$idx]}" >&2
        fi
    fi
done

echo ""
echo "=========================================================================="
echo "=== vinegar_dist_mayo: per-function summary ==="
for func in "${FUNCS[@]}"; do
    [[ -n "${FUNC_NJOBS["$func"]:-}" ]] || continue
    line="[i] ${func}: ${FN_DETECTED["$func"]:-0}/${FUNC_NJOBS["$func"]} ELF(s) flagged a secret-dependence collapse"
    [[ -n "${FN_FAILS["$func"]:-}" ]] && line="${line}, ${FN_FAILS["$func"]} errored"
    echo "$line"
done

echo ""
echo "=========================================================================="
echo "=== vinegar_dist_mayo: ${#FUNCS[@]} function(s), ${#SKIPPED[@]} skipped, ${TOTAL_JOBS} probe(s) ==="
echo "[i] total ELF(s) flagged a secret-dependence collapse: ${TOTAL_DETECTED}"
echo "[i] per-faulty-ELF results under: test_mayo/<func>/<faulty_elf_relpath>/vinegar_dist_result.txt"
for f in "${SKIPPED[@]}"; do
    echo "[!] skipped: $f" >&2
done

if [[ "$TOTAL_FAILS" -gt 0 ]]; then
    echo "[!] ${TOTAL_FAILS} faulty ELF(s) errored out (emulation failure, not just verdict)" >&2
    exit 2
fi
