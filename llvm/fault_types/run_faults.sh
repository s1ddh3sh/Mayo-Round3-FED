#!/usr/bin/env bash
#
# run_faults.sh
#
# Usage:
#   ./run_faults.sh                # Runs for all .json files in the taint results
#   ./run_faults.sh add_f mat_add  # Runs for the given functions / json files
#
# For each entry in each JSON file:
#   - type == "CallInst"                  -> ./loop_fn_Fault <ir_file> 1 <fn> <line_no>
#   - type == "BinOp"/"StoreInst"/"LoadInst" -> ./binOp_load_store_Fault <ir_file> <fn> <line_no>
#   - anything else                       -> skipped (with a warning)
#
# Every run writes the correct trace ../test_mayo/<fn>/<fn>.ll and the faulty
# variant(s) under ../test_mayo/<fn>/{loopOrFuncSkip,binOpFault,loadStoreSkip}/.
# Function inputs default to zero; mayo.json (repo root) says which arguments
# are secret / outputs.
#
# Requires: jq

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required but not installed." >&2
  exit 1
fi

cd "$(dirname "$0")"

# Relative to build/, where the generators run.
IR_FILE="../../llvmgen_and_taintProp/no_struct/mayo1.ll"
DEFAULT_DIR="../llvmgen_and_taintProp/taintResults"

if [ ! -f "${IR_FILE#../}" ]; then
  echo "Error: IR file not found: ${IR_FILE#../}" >&2
  echo "       (run llvmgen in llvm/llvmgen_and_taintProp/build first)" >&2
  exit 1
fi

# Resolve all json file paths to absolute *before* we cd into build,
# since relative paths on the command line are relative to the caller's cwd.
declare -a JSON_FILES=()

# If no arguments are provided, process all .json files in DEFAULT_DIR
if [ $# -eq 0 ]; then
  if [ ! -d "$DEFAULT_DIR" ]; then
    echo "Error: Default directory '$DEFAULT_DIR' does not exist." >&2
    exit 1
  fi

  shopt -s nullglob
  all_json=("$DEFAULT_DIR"/*.json)
  shopt -u nullglob

  if [ ${#all_json[@]} -eq 0 ]; then
    echo "Error: No .json files found in '$DEFAULT_DIR'." >&2
    exit 1
  fi

  for file in "${all_json[@]}"; do
    JSON_FILES+=("$(realpath "$file")")
  done
else
  # Process positional arguments
  for input in "$@"; do
    target_file="$input"

    # If the input isn't an existing file, try resolving it via the default path
    if [ ! -f "$target_file" ]; then
      # Append .json extension if it's missing
      if [[ "$target_file" != *.json ]]; then
        target_file="${target_file}.json"
      fi
      # Prefix with the default directory
      target_file="${DEFAULT_DIR}/${target_file}"
    fi

    # Final check to ensure the resolved file actually exists
    if [ ! -f "$target_file" ]; then
      echo "Warning: file not found, skipping: $input (resolved to $target_file)" >&2
      continue
    fi

    JSON_FILES+=("$(realpath "$target_file")")
  done
fi

if [ ${#JSON_FILES[@]} -eq 0 ]; then
  echo "Error: no valid JSON files given or found." >&2
  exit 1
fi

mkdir -p build && cd build
if [ ! -f Makefile ]; then
  cmake .. -DCMAKE_BUILD_TYPE=Release
fi
make -j"$(nproc)"

# A failing run must not stop the sweep: record it and move on. Failures are
# listed at the end and written to FAIL_LOG.
FAIL_LOG="$(pwd)/run_faults_failures.log"
declare -a FAILURES=()
TOTAL_RUNS=0

run_fault() {
  local desc="$1"; shift
  TOTAL_RUNS=$((TOTAL_RUNS + 1))
  echo "  [run] $*"
  local status=0
  set +e
  "$@"
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    FAILURES+=("$desc | exit $status | $*")
    echo "  [FAILED] $desc (exit $status) -- continuing with the next entry" >&2
  fi
}

for jsonfile in "${JSON_FILES[@]}"; do
  filename="$(basename "$jsonfile" .json)"

  echo "=== Processing $filename ($jsonfile) ==="

  # Get all top-level keys (line numbers) in the JSON object
  mapfile -t keys < <(jq -r 'keys[]' "$jsonfile")

  for line_no in "${keys[@]}"; do
    type=$(jq -r --arg k "$line_no" '.[$k].type' "$jsonfile")

    case "$type" in
      CallInst)
        callee=$(jq -r --arg k "$line_no" '.[$k].callee' "$jsonfile")
        if [ -z "$callee" ] || [ "$callee" = "null" ]; then
          echo "  [skip] line $line_no: CallInst with no resolvable callee (indirect call)" >&2
          continue
        fi
        run_fault "$filename line $line_no (CallInst -> $callee)" \
          ./loop_fn_Fault "$IR_FILE" 1 "$filename" "$line_no"
        ;;

      BinOp | StoreInst | LoadInst)
        run_fault "$filename line $line_no ($type)" \
          ./binOp_load_store_Fault "$IR_FILE" "$filename" "$line_no"
        ;;

      *)
        echo "  [skip] line $line_no: type=$type has no matching fault binary" >&2
        ;;
    esac
  done
done

echo ""
echo "=== run_faults.sh done: $TOTAL_RUNS run(s), ${#FAILURES[@]} failure(s) ==="
{
  echo "# run_faults.sh $(date '+%F %T') -- ${#FAILURES[@]} failure(s) over $TOTAL_RUNS run(s)"
  for f in "${FAILURES[@]}"; do
    echo "$f"
  done
} > "$FAIL_LOG"
if [ ${#FAILURES[@]} -gt 0 ]; then
  echo "Failures (entry | reason | command):"
  for f in "${FAILURES[@]}"; do
    echo "  - $f"
  done
  echo "Written to $FAIL_LOG"
  exit 1
fi
