#!/usr/bin/env bash
#
# run_ineffective_paired.sh — run the paired ineffective-dependence test
# (ineffective_mayo.py) for a single MAYO function, against every
# already-collected single-background secret sweep for that function --
# one sweep per faulty ELF variant found alongside the correct ELF.
#
# Usage:
#   ./run_ineffective_paired.sh <func_name> <secret_buf> \
#       [--out-buf NAME] [--elf-dir DIR] [--seeds p0,p1,...] [--eph-draws J]
#
# NAMESPACE NOTE (_pre suffix):
#   For in-place functions -- those whose layout marks a buffer
#   "role": "output" with "also_input": true -- the collector captures a
#   pre-call snapshot of that buffer under the slot name "<buf>_pre".
#   That slot name exists only in the collected JSON records; it is NOT a
#   layout key, so it will never appear in qemu_witness.json or (usually)
#   in active_lengths.json. This script therefore resolves a "_pre"
#   secret-buf by first trying the literal name, then falling back to the
#   base buffer name for the purposes of the length lookup.
#
# ELF layout assumed (default --elf-dir is build/test_mayo/<func_name>):
#   <elf-dir>/<func_name>.elf   -- the correct build
#   <elf-dir>/*.elf             -- every other .elf is a faulty variant
#
# Assumes trials already exist for each faulty ELF:
#   test_mayo/<func_name>/qemu_witness.json
#   test_mayo/<func_name>/active_lengths.json
#   test_mayo/<func_name>/<faulty_elf_stem>/dist_paired/{correct,faulty}_sv*.json
#
# Example:
#   ./run_ineffective_paired.sh mat_add in
#   ./run_ineffective_paired.sh EF A_pre        # in-place function

set -euo pipefail

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <func_name> <secret_buf> [--out-buf NAME] [--elf-dir DIR]" >&2
    exit 1
fi

FUNC_NAME="$1"; shift
SECRET_BUF="$1"; shift

# Base (layout-namespace) name of the secret buffer: "A_pre" -> "A".
# Identical to SECRET_BUF when no _pre suffix is present.
SECRET_BUF_BASE="${SECRET_BUF%_pre}"

OUT_BUF_OVERRIDE=""
SEEDS=""
EPH_DRAWS=1       # ephemeral draws r_j per public seed (1: no eph input)
RESULT_SUFFIX=""   # appended to the per-fault RESULT folder only (multi-output functions)
ELF_DIR="build/test_mayo/${FUNC_NAME}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-buf)
            if [[ $# -lt 2 ]]; then
                echo "[!] --out-buf requires a value" >&2
                exit 1
            fi
            OUT_BUF_OVERRIDE="$2"
            shift 2
            ;;
        --seeds)
            SEEDS="$2"
            shift 2
            ;;
        --eph-draws)
            EPH_DRAWS="$2"
            shift 2
            ;;
        --result-suffix)
            RESULT_SUFFIX="$2"
            shift 2
            ;;
        --elf-dir)
            if [[ $# -lt 2 ]]; then
                echo "[!] --elf-dir requires a value" >&2
                exit 1
            fi
            ELF_DIR="$2"
            shift 2
            ;;
        *)
            echo "[!] unrecognized argument: $1" >&2
            exit 1
            ;;
    esac
done

WORD_SIZE=1

TEST_DIR="dist_tests/mayo"
OUT_DIR="test_mayo/${FUNC_NAME}"

WITNESS="${OUT_DIR}/qemu_witness.json"
ACTIVE_LENGTHS="${OUT_DIR}/active_lengths.json"

if [[ ! -f "$WITNESS" ]]; then
    echo "[!] witness not found: $WITNESS" >&2
    exit 1
fi
if [[ ! -f "$ACTIVE_LENGTHS" ]]; then
    echo "[!] active_lengths.json not found: $ACTIVE_LENGTHS" >&2
    echo "    (run calibrate.py first)" >&2
    exit 1
fi
if [[ ! -d "$ELF_DIR" ]]; then
    echo "[!] elf dir not found: $ELF_DIR" >&2
    exit 1
fi

CORRECT_ELF="${ELF_DIR}/${FUNC_NAME}.elf"
if [[ ! -f "$CORRECT_ELF" ]]; then
    echo "[!] correct elf not found: $CORRECT_ELF" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Derive --out-buf from the witness (unless overridden) and --active-len
# from active_lengths.json[secret_buf]. These are per-function, not
# per-faulty-ELF, so derived once up front and reused for every sweep.
#
# SAFETY: if secret_buf was never calibrated, falling back to the witness's
# FULL declared length can be enormous and make the position loop appear
# to hang -- it isn't hung, it's just iterating over far more positions
# than intended. Cap the fallback explicitly.
# ---------------------------------------------------------------------------

MAX_SAFE_FALLBACK_LEN=4096

derive_out_buf() {
    python3 - "$WITNESS" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    layout = json.load(f)["layout"]
outs = [name for name, spec in layout.items() if spec.get("role") == "output"]
if not outs:
    print("[!] no role:output entry found in witness layout", file=sys.stderr)
    sys.exit(1)
if len(outs) > 1:
    print(f"[!] multiple output-role entries found: {outs}; defaulting to "
          f"the first ({outs[0]}). Pass --out-buf NAME to pick a different one.",
          file=sys.stderr)
print(outs[0])
PYEOF
}

validate_out_buf() {
    python3 - "$WITNESS" "$OUT_BUF_OVERRIDE" <<'PYEOF'
import json, sys
witness_path, requested = sys.argv[1], sys.argv[2]

# A "_pre" slot is the pre-call snapshot of an in-place buffer. It is by
# construction byte-identical between the correct and faulty runs (same
# inputs, captured before either build has done anything), so
# Delta = correct XOR faulty would be identically zero at every position
# and the test would report a clean result no matter how leaky the
# function actually is. Refuse it outright rather than silently
# producing a meaningless all-clean report.
if requested.endswith("_pre"):
    print(f"[!] --out-buf '{requested}' is a pre-call snapshot slot; it is "
          f"identical in the correct and faulty runs, so the XOR delta "
          f"would be identically zero. Use "
          f"--out-buf '{requested[:-4]}' (the post-call buffer) instead.",
          file=sys.stderr)
    sys.exit(1)

with open(witness_path) as f:
    layout = json.load(f)["layout"]
if requested not in layout:
    print(f"[!] --out-buf '{requested}' not found in witness layout "
          f"(available: {sorted(layout.keys())})", file=sys.stderr)
    sys.exit(1)
if layout[requested].get("role") != "output":
    print(f"[!] --out-buf '{requested}' has role="
          f"'{layout[requested].get('role')}', not 'output'", file=sys.stderr)
    sys.exit(1)
PYEOF
}

derive_active_len() {
    python3 - "$ACTIVE_LENGTHS" "$SECRET_BUF" "$SECRET_BUF_BASE" "$WITNESS" "$MAX_SAFE_FALLBACK_LEN" <<'PYEOF'
import json, sys

active_path   = sys.argv[1]
secret_buf    = sys.argv[2]
secret_base   = sys.argv[3]
witness_path  = sys.argv[4]
max_fallback  = int(sys.argv[5])

# Try the literal name first (calibrate.py may have recorded the _pre slot
# explicitly), then the layout-namespace base name.
candidates = [secret_buf]
if secret_base != secret_buf:
    candidates.append(secret_base)


def note_fallback(resolved):
    if resolved != secret_buf:
        print(f"[i] secret-buf '{secret_buf}' is a capture-slot name with no "
              f"layout entry; resolved its length via the base buffer "
              f"'{resolved}'.", file=sys.stderr)


with open(active_path) as f:
    active_lengths = json.load(f)

for name in candidates:
    if name in active_lengths:
        note_fallback(name)
        print(active_lengths[name])
        sys.exit(0)

with open(witness_path) as f:
    layout = json.load(f)["layout"]

for name in candidates:
    if name not in layout:
        continue

    spec = layout[name]

    # If we only got here by stripping a _pre suffix, the base buffer had
    # better actually be an in-place buffer -- otherwise no pre-call
    # snapshot would have been captured and the sweep files will not
    # contain this slot at all.
    if name != secret_buf:
        is_inplace = spec.get("also_input") is True or spec.get("role") == "input"
        if not is_inplace:
            print(f"[!] '{secret_buf}' resolves to layout entry '{name}', but "
                  f"'{name}' is role='{spec.get('role')}' without "
                  f"also_input:true -- no pre-call snapshot is captured for "
                  f"it, so the collected records are unlikely to contain "
                  f"'{secret_buf}'.", file=sys.stderr)

    note_fallback(name)

    full_len = spec["length"]
    if full_len > max_fallback:
        print(
            f"[!] secret-buf '{secret_buf}' was never calibrated and its "
            f"full declared length ({full_len}) exceeds the safety cap "
            f"({max_fallback}); capping --active-len to {max_fallback}. "
            f"Pass a smaller/calibrated secret-buf, or raise "
            f"MAX_SAFE_FALLBACK_LEN in this script if this is intentional.",
            file=sys.stderr,
        )
        full_len = max_fallback
    print(full_len)
    sys.exit(0)

tried = " / ".join(f"'{c}'" for c in candidates)
print(f"[!] secret-buf {tried} not found in active_lengths.json or witness "
      f"(active_lengths keys: {sorted(active_lengths.keys())}; "
      f"layout keys: {sorted(layout.keys())})", file=sys.stderr)
sys.exit(1)
PYEOF
}

if [[ -n "$OUT_BUF_OVERRIDE" ]]; then
    validate_out_buf
    OUT_BUF="$OUT_BUF_OVERRIDE"
else
    OUT_BUF="$(derive_out_buf)"
fi
ACTIVE_LEN="$(derive_active_len)"

echo "[i] derived --out-buf=${OUT_BUF} --active-len=${ACTIVE_LEN}"

# The delta is measured on OUT_BUF. If the secret sweep and the output
# resolve to the same underlying in-place buffer, that is expected and
# fine (that is what an in-place function looks like) -- but say so, so
# the reader of the log knows the sweep and the measurement share storage.
if [[ "$SECRET_BUF" != "$SECRET_BUF_BASE" && "$SECRET_BUF_BASE" == "$OUT_BUF" ]]; then
    echo "[i] in-place function: sweeping '${SECRET_BUF}' (pre-call snapshot) " \
         "and measuring the delta on '${OUT_BUF}' (post-call), same buffer."
fi

# ---------------------------------------------------------------------------
# rel_stem: path of an ELF relative to a base dir, minus .elf. Must match
# collect_dist.sh's derivation exactly, since it's used to look up the
# dist_paired dir that script already populated.
# ---------------------------------------------------------------------------

rel_stem() {
    python3 - "$1" "$2" <<'PYEOF'
import os, sys
elf, base = sys.argv[1], sys.argv[2]
rel = os.path.relpath(os.path.abspath(elf), os.path.abspath(base))
if rel.endswith(".elf"):
    rel = rel[:-4]
print(rel)
PYEOF
}

# ---------------------------------------------------------------------------
# Discover every faulty ELF anywhere under ELF_DIR (faulty builds are not
# necessarily immediate children of the correct ELF -- can be nested
# several directories deep), and run the paired ineffective test against
# each one's dist_paired dir.
# ---------------------------------------------------------------------------

FAULTY_ELFS=()
while IFS= read -r -d '' f; do
    FAULTY_ELFS+=("$f")
done < <(find "$ELF_DIR" -type f -name '*.elf' -not -path '*/full_mayo_gated/*' -not -samefile "$CORRECT_ELF" -print0 | sort -z)

if [[ ${#FAULTY_ELFS[@]} -eq 0 ]]; then
    echo "[!] no faulty ELFs found under $ELF_DIR (besides $CORRECT_ELF)" >&2
    exit 1
fi
echo "[i] found ${#FAULTY_ELFS[@]} faulty ELF(s) under ${ELF_DIR}"

OVERALL_STATUS=0
for faulty_elf in "${FAULTY_ELFS[@]}"; do
    faulty_stem="$(rel_stem "$faulty_elf" "$ELF_DIR")"
    DIST_PAIRED_DIR="${OUT_DIR}/${faulty_stem}/dist_paired"

    # Grid of sweeps, seed-major: public seed p_k x ephemeral draw r_j.
    # dist_paired[_seed<p>][_eph<j>]: first seed has no _seed suffix, draw
    # 0 has no _eph suffix (functions without an eph input use J = 1).
    read -r -a SEED_LIST <<< "${SEEDS//,/ }"
    [[ ${#SEED_LIST[@]} -eq 0 ]] && SEED_LIST=(0)
    DIST_DIRS=()
    for i in "${!SEED_LIST[@]}"; do
        base="dist_paired"
        [[ $i -gt 0 ]] && base="dist_paired_seed${SEED_LIST[$i]}"
        for ((j = 0; j < EPH_DRAWS; j++)); do
            d="$base"
            [[ $j -gt 0 ]] && d="${base}_eph${j}"
            DIST_DIRS+=("${OUT_DIR}/${faulty_stem}/${d}")
        done
    done
    if [[ -z "$SEEDS" ]]; then
        echo "[!] no --seeds given: only one public seed" >&2
    fi
    missing=0
    for d in "${DIST_DIRS[@]}"; do
        ls "${d}"/correct_sv*.json >/dev/null 2>&1 || { echo "[!] no swept secret-value files in $d" >&2; missing=1; }
    done
    n_sv=$(ls "${DIST_PAIRED_DIR}"/correct_sv*.json 2>/dev/null | wc -l)
    [[ "$missing" -eq 1 ]] && n_sv=0
    if [[ "$n_sv" -eq 0 ]]; then
        echo "[!] skipping ${faulty_stem}: no swept secret-value files found in $DIST_PAIRED_DIR" >&2
        echo "    (run collect_dist.sh for this faulty elf first)" >&2
        OVERALL_STATUS=1
        continue
    fi
    echo "[i] ${n_sv} correct_sv*.json files present in ${DIST_PAIRED_DIR}"

    INEFFECTIVE_PAIRED_OUT="${OUT_DIR}/${faulty_stem}${RESULT_SUFFIX}/ineffective_paired_result.txt"
    mkdir -p "$(dirname "$INEFFECTIVE_PAIRED_OUT")"

    echo "=== ineffective (paired) test: ${FUNC_NAME} / ${faulty_stem} ==="
    python3 -u "${TEST_DIR}/ineffective_mayo.py" \
        --dist-dir "${DIST_DIRS[@]}" \
        --eph-draws "$EPH_DRAWS" \
        --out-buf "$OUT_BUF" \
        --active-len "$ACTIVE_LEN" \
        --out-word-size "$WORD_SIZE" \
        2>&1 | tee "$INEFFECTIVE_PAIRED_OUT"

    echo "=== done: ${FUNC_NAME} / ${faulty_stem} ==="
    echo "[i] ineffective (paired) test -> ${INEFFECTIVE_PAIRED_OUT}"
    echo ""
done

exit $OVERALL_STATUS