#!/usr/bin/env bash
#
# run_tests_unicorn.sh — Unicorn-backed variant of run_tests.sh: the full
# paired-sweep pipeline for one MAYO function, with calibration and
# collection run IN-PROCESS via the Unicorn Cortex-M4 emulator
# (dist_tests/common/unicorn_runner.py) instead of qemu-system-arm +
# gdb-multiarch. No qemu-system-arm/gdb-multiarch install is required to
# run this script.
#
#   1. calibrate_unicorn.py         (once for the function)
# For every faulty ELF found alongside the correct one:
#   2. collect_dist_unicorn.sh      (the paired secret sweep)
# Then, once for the whole function (each internally loops over every
# faulty ELF's collected sweep) -- these steps only read already-collected
# JSON from disk and have no QEMU/gdb dependency at all, so they are
# unchanged from run_tests.sh:
#   3. run_ineffective_paired.sh
#   4. run_correction_paired.sh
#
# Usage:
#   ./run_tests_unicorn.sh <func_name> [--secret-buf NAME] [--secret-pos POS] \
#       [--elf-dir DIR] [--fixed-scalars name1,name2,...] [--seed N] \
#       [--seeds p0,p1,...] [--eph-draws J] [--out-buf NAME] [--field-mod N]
#
# --eph-draws J: for a function with an "eph_secret" (mayo.json), J
# ephemeral draws r_0..r_{J-1}, independent of the public seeds; every
# public seed is swept with every draw, and the ineffective test requires
# its outcome to be the same on all J draws. Default 4; ignored (J = 1)
# without an eph_secret. Draw j > 0 goes to <dist dir>_eph<j>/.
#
# --seeds p0,p1,...: public-background seeds for the CORRECTION test
# (exists alpha != 0, s: for all p, y1 = y2 xor alpha; needs >= 2). One
# sweep is collected per seed: the first seed (also used for the
# ineffective test) goes to dist_paired/, every other seed p to
# dist_paired_seed<p>/. Without --seeds, only --seed is swept.
#
# Only <func_name> is required. --secret-buf/--fixed-scalars are looked
# up automatically from <repo_root>/mayo.json (keyed by func_name); an
# explicit --secret-buf/--fixed-scalars flag overrides that lookup.
# --field-mod, if not given, is left unset so it flows through to
# collect_dist_unicorn.sh/.py as "not passed", which then defaults to 16
# (MAYO_FIELD_MOD -- GF(16), a fixed constant, see distributions_unicorn.py
# and dist_tests/mayo/collect_dist.sh's own hardcoded FIELD_MOD=16).
# --secret-pos defaults to 0.
#
# Run from anywhere: the script cds to llvm/ (all paths below are relative
# to it) and reads the per-function config from the MAYO-C root mayo.json.
# If the correct ELF is missing, dist_tests/mayo/mayo_build.sh is run first.
#
# ELF layout assumed (default --elf-dir is build/test_mayo/<func_name>):
#   <elf-dir>/<func_name>.elf   -- the correct build
#   <elf-dir>/*.elf             -- every other .elf is a faulty variant,
#                                  tested one at a time, EXCEPT anything
#                                  under a full_mayo_gated/ directory
#                                  (whole-program builds; skipped here)
#
# Example:
#   ./run_tests_unicorn.sh mat_add
#   ./run_tests_unicorn.sh mat_add --secret-buf in --secret-pos 0
#   ./run_tests_unicorn.sh mat_mul --secret-buf O --secret-pos 0 --fixed-scalars m_vec_limbs

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <func_name> [--secret-buf NAME] [--secret-pos POS] [--elf-dir DIR] [--fixed-scalars n1,n2,...] [--seed N] [--seeds p0,p1,...] [--out-buf NAME] [--field-mod N]" >&2
    exit 1
fi

FUNC_NAME="$1"; shift
OUT_DIR="test_mayo/${FUNC_NAME}"
SETUP_DIR="dist_tests/mayo/setup"
WITNESS="${OUT_DIR}/qemu_witness.json"
ACTIVE_LENGTHS="${OUT_DIR}/active_lengths.json"
SECRET_POS=0
ELF_DIR="build/test_mayo/${FUNC_NAME}"
FIXED_SCALARS_OVERRIDE=""
SECRET_BUF_OVERRIDE=""
SEED=0
SEEDS="0,1,2,3"
OUT_BUF_OVERRIDE=""
FIELD_MOD=""
EPH_DRAWS=4

while [[ $# -gt 0 ]]; do
    case "$1" in
        --secret-buf) SECRET_BUF_OVERRIDE="$2"; shift 2 ;;
        --secret-pos) SECRET_POS="$2"; shift 2 ;;
        --elf-dir) ELF_DIR="$2"; shift 2 ;;
        --fixed-scalars) FIXED_SCALARS_OVERRIDE="$2"; shift 2 ;;
        --seed) SEED="$2"; shift 2 ;;
        --seeds) SEEDS="$2"; shift 2 ;;
        --out-buf) OUT_BUF_OVERRIDE="$2"; shift 2 ;;
        --field-mod) FIELD_MOD="$2"; shift 2 ;;
        --eph-draws) EPH_DRAWS="$2"; shift 2 ;;
        *) echo "[!] unrecognized argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$SECRET_POS" ]]; then
    echo "[!] --secret-pos POS is required" >&2
    exit 1
fi

SEED_LIST=("$SEED")
if [[ -n "$SEEDS" ]]; then
    read -r -a SEED_LIST <<< "${SEEDS//,/ }"
    SEED="${SEED_LIST[0]}"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."

# ---------------------------------------------------------------------------
# Resolve secret-buf/fixed-scalars: explicit flag wins, else look up
# mayo.json[func_name] (the MAYO-C root, one level above llvm/).
# ---------------------------------------------------------------------------
CONFIG_JSON="../mayo.json"
read -r JSON_SECRET_BUF JSON_FIXED_SCALARS JSON_EPH_SECRET <<< "$(python3 - "$CONFIG_JSON" "$FUNC_NAME" <<'PYEOF'
import json, sys
path, func = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        config = json.load(f)
except FileNotFoundError:
    config = {}
entry = config.get(func) or {}
# ONE line, space-joined: `read -r VAR1 VAR2 <<< "$(...)"` below only
# reads the FIRST line of its here-string, splitting it on whitespace --
# two separate print() calls would silently leave JSON_FIXED_SCALARS
# empty on every function that actually has a "fixed-scalars" entry
# (neither secret-buf nor fixed-scalars ever contains whitespace, so
# this is a safe, unambiguous join).
print((entry.get("secret-buf") or "__NONE__") + " " + (entry.get("fixed-scalars") or "__NONE__") + " " + (entry.get("eph_secret") or "__NONE__"))
PYEOF
)"
[[ "$JSON_SECRET_BUF" == "__NONE__" ]] && JSON_SECRET_BUF=""
[[ "$JSON_FIXED_SCALARS" == "__NONE__" ]] && JSON_FIXED_SCALARS=""
[[ "$JSON_EPH_SECRET" == "__NONE__" ]] && JSON_EPH_SECRET=""
EPH_SECRET="$JSON_EPH_SECRET"
[[ -z "$EPH_SECRET" ]] && EPH_DRAWS=1

if [[ -n "$SECRET_BUF_OVERRIDE" ]]; then
    SECRET_BUF="$SECRET_BUF_OVERRIDE"
elif [[ -n "$JSON_SECRET_BUF" ]]; then
    SECRET_BUF="$JSON_SECRET_BUF"
    echo "[i] secret-buf auto-resolved from ${CONFIG_JSON}: '${SECRET_BUF}'"
else
    echo "[!] no secret-buf for '${FUNC_NAME}': not found in ${CONFIG_JSON} and no --secret-buf given" >&2
    exit 1
fi

if [[ -n "$FIXED_SCALARS_OVERRIDE" ]]; then
    FIXED_SCALARS="$FIXED_SCALARS_OVERRIDE"
else
    FIXED_SCALARS="$JSON_FIXED_SCALARS"
fi

for req in collect_dist_unicorn.sh run_ineffective_paired.sh run_correction_paired.sh; do
    if [[ ! -x "${SCRIPT_DIR}/${req}" ]]; then
        echo "[!] required script not found or not executable: ${SCRIPT_DIR}/${req}" >&2
        echo "    (chmod +x it, or place it alongside run_tests_unicorn.sh)" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Discover the faulty ELF set up front, so the plan is printed before any
# work starts, and so [2/3]/[3/3] (which discover the same set internally)
# are guaranteed to see the same directory contents this script acted on.
# ---------------------------------------------------------------------------

CORRECT_ELF="${ELF_DIR}/${FUNC_NAME}.elf"
if [[ ! -f "$CORRECT_ELF" || ! -f "$WITNESS" ]]; then
    echo "[i] ${CORRECT_ELF} or ${WITNESS} missing -- building test_mayo/${FUNC_NAME} first"
    "${SCRIPT_DIR}/mayo_build.sh" "test_mayo/${FUNC_NAME}"
fi
[[ -d "$ELF_DIR" ]] || { echo "[!] elf dir not found: $ELF_DIR" >&2; exit 1; }

# mayo.json may name a buffer by its parameter or by the call-site buffer
# the driver bound it to (e.g. mat_add's "Ox" is parameter b); the witness
# layout is keyed by parameter, so map secret-buf / eph_secret onto it.
resolve_layout_name() {
    python3 - "$WITNESS" "$1" <<'PYEOF'
import json, sys
layout = json.load(open(sys.argv[1]))["layout"]
name = sys.argv[2]
hits = [k for k, s in layout.items() if s.get("alloca") == name]
print(name if name in layout or len(hits) != 1 else hits[0])
PYEOF
}
for var in SECRET_BUF EPH_SECRET; do
    [[ -z "${!var}" ]] && continue
    resolved="$(resolve_layout_name "${!var}")"
    if [[ "$resolved" != "${!var}" ]]; then
        echo "[i] ${var,,}: '${!var}' is parameter '${resolved}' of ${FUNC_NAME}"
        printf -v "$var" '%s' "$resolved"
    fi
done

# Fail now, not after every sweep has been collected, if a name still does
# not match the layout (e.g. a call-site expression name that is neither a
# parameter nor the driver buffer it was traced to).
if ! python3 - "$WITNESS" "$SECRET_BUF" "$EPH_SECRET" <<'PYEOF'
import json, sys
layout = json.load(open(sys.argv[1]))["layout"]
bad = [n for n in sys.argv[2:] if n and n not in layout]
if bad:
    aliases = {k: s["alloca"] for k, s in layout.items() if "alloca" in s}
    print(f"[!] {bad} not in the witness layout: name a parameter "
          f"{list(layout)} (or the driver buffer it is bound to: {aliases}) "
          f"in mayo.json", file=sys.stderr)
    sys.exit(1)
PYEOF
then
    exit 1
fi
[[ -f "$CORRECT_ELF" ]] || { echo "[!] correct elf not found: $CORRECT_ELF" >&2; exit 1; }

# Faulty builds are not necessarily immediate children of the correct
# ELF -- they can be nested several directories deep -- so this must be a
# recursive search, not a flat glob. full_mayo_gated/ ELFs are skipped.
FAULTY_ELFS=()
while IFS= read -r -d '' f; do
    FAULTY_ELFS+=("$f")
done < <(find "$ELF_DIR" -type f -name '*.elf' -not -path '*/full_mayo_gated/*' -not -samefile "$CORRECT_ELF" -print0 | sort -z)

if [[ ${#FAULTY_ELFS[@]} -eq 0 ]]; then
    echo "[!] no faulty ELFs found under $ELF_DIR (besides $CORRECT_ELF)" >&2
    exit 1
fi

echo "[i] function:     ${FUNC_NAME} [unicorn backend -- no qemu-system-arm/gdb-multiarch required]"
echo "[i] secret buf:    ${SECRET_BUF} (pos ${SECRET_POS}), field-mod ${FIELD_MOD:-16 (GF(16) default)}"
echo "[i] eph secret:    ${EPH_SECRET:-<none>} (${EPH_DRAWS} draw(s), each run with every public seed)"
echo "[i] correct elf:   ${CORRECT_ELF}"
echo "[i] faulty elfs:   ${#FAULTY_ELFS[@]} found under ${ELF_DIR}"
for f in "${FAULTY_ELFS[@]}"; do
    echo "                    - ${f#${ELF_DIR}/}"
done

# ---------------------------------------------------------------------------
# [1/3] collect_dist_unicorn.sh, once per faulty ELF
# ---------------------------------------------------------------------------
echo "=== calibrate (unicorn): ${FUNC_NAME} ==="
python3 "${SETUP_DIR}/calibrate_unicorn.py" \
    --witness "$WITNESS" --elf "$CORRECT_ELF" \
    --field-mod 16 --machine mps2-an386 \
    --out "$ACTIVE_LENGTHS" --fixed-scalars "$FIXED_SCALARS"

echo ""
echo "########## [1/3] collect_dist_unicorn.sh (${#FAULTY_ELFS[@]} faulty ELF(s)) ##########"
for faulty_elf in "${FAULTY_ELFS[@]}"; do
    echo ""
    echo "--- collect_dist (unicorn): ${FUNC_NAME} / $(basename "$faulty_elf") ---"
    for i in "${!SEED_LIST[@]}"; do
        p="${SEED_LIST[$i]}"
        for ((j = 0; j < EPH_DRAWS; j++)); do
            # dist_paired[_seed<p>][_eph<j>] -- must match the grid that
            # run_ineffective_paired.sh / run_correction_paired.sh read.
            dname="dist_paired"
            [[ $i -gt 0 ]] && dname="dist_paired_seed${p}"
            [[ $j -gt 0 ]] && dname="${dname}_eph${j}"
            COLLECT_ARGS=(
                "$FUNC_NAME" "$CORRECT_ELF" "$faulty_elf" "$SECRET_BUF"
                --secret-pos "$SECRET_POS"
                --fixed-scalars "$FIXED_SCALARS"
                --eph-secret "$EPH_SECRET" --eph-index "$j"
                --seed "$p"
                --dist-dir-name "$dname"
            )
            if [[ -n "$FIELD_MOD" ]]; then
                COLLECT_ARGS+=(--field-mod "$FIELD_MOD")
            fi
            echo "    [seed p=${p}, eph draw r=${j}]"
            "${SCRIPT_DIR}/collect_dist_unicorn.sh" "${COLLECT_ARGS[@]}"
        done
    done
done

# ---------------------------------------------------------------------------
# [2/3] and [3/3] each loop internally over every faulty ELF's dist_paired
# dir, so they're called once per function, not once per faulty ELF.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Output buffers to analyse. Collection already stores EVERY output in each
# trial JSON, so steps [2/3]/[3/3] simply run once per output buffer.
#   - --out-buf given            -> just that buffer
#   - exactly one role:output    -> it (result folders unchanged)
#   - two or more role:output    -> each of them; results go to
#       <faulty_stem>_<out_name>/ (dist_paired/ data stays shared in
#       <faulty_stem>/), so outputs never overwrite each other.
# ---------------------------------------------------------------------------
mapfile -t WITNESS_OUTPUTS < <(python3 - "$WITNESS" <<'PYEOF'
import json, sys
layout = json.load(open(sys.argv[1]))["layout"]
for n, spec in layout.items():
    if spec.get("role") == "output":
        print(n)
PYEOF
)
if [[ -n "$OUT_BUF_OVERRIDE" ]]; then
    OUT_BUFS=("$OUT_BUF_OVERRIDE")
else
    OUT_BUFS=("${WITNESS_OUTPUTS[@]}")
fi
MULTI_OUT=0
[[ ${#WITNESS_OUTPUTS[@]} -ge 2 ]] && MULTI_OUT=1
[[ ${#OUT_BUFS[@]} -eq 0 ]] && OUT_BUFS=("")   # let the sub-scripts report the error

for OUT_BUF_CUR in "${OUT_BUFS[@]}"; do
    RUN_ARGS=("$FUNC_NAME" "$SECRET_BUF" --elf-dir "$ELF_DIR")
    if [[ -n "$OUT_BUF_CUR" ]]; then
        RUN_ARGS+=(--out-buf "$OUT_BUF_CUR")
    fi
    RUN_ARGS+=(--eph-draws "$EPH_DRAWS")
    if [[ "$MULTI_OUT" -eq 1 ]]; then
        RUN_ARGS+=(--result-suffix "_${OUT_BUF_CUR}")
        echo ""
        echo "################ output buffer: ${OUT_BUF_CUR} (results -> <faulty_stem>_${OUT_BUF_CUR}/) ################"
    fi

    echo ""
    echo "########## [2/3] run_ineffective_paired.sh ##########"
    INEFF_ARGS=("${RUN_ARGS[@]}")
    CORR_ARGS=("${RUN_ARGS[@]}")
    if [[ -n "$SEEDS" ]]; then
        INEFF_ARGS+=(--seeds "$SEEDS")
        CORR_ARGS+=(--seeds "$SEEDS")
    fi
    "${SCRIPT_DIR}/run_ineffective_paired.sh" "${INEFF_ARGS[@]}"

    echo ""
    echo "########## [3/3] run_correction_paired.sh ##########"
    "${SCRIPT_DIR}/run_correction_paired.sh" "${CORR_ARGS[@]}"
done

echo ""
echo "=== pipeline complete (unicorn): ${FUNC_NAME} (${#FAULTY_ELFS[@]} faulty ELF(s)) ==="
echo "[i] per-faulty-ELF results under: test_mayo/${FUNC_NAME}/<faulty_elf_stem>[_<out>]/{ineffective,correction}_paired_result.txt"
