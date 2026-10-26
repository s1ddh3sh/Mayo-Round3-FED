#!/usr/bin/env bash

set -euo pipefail

BASE_LL="../../llvmgen_and_taintProp/no_struct/mayo1.ll"
RESULTS_DIR="../../test_mayo"
FUSEBACK="./fuse_back"

mkdir -p build && cd build

if [ ! -x "$FUSEBACK" ]; then
    echo "Error: $FUSEBACK not found or not executable."
    exit 1
fi

for func_dir in "$RESULTS_DIR"/*; do
    [ -d "$func_dir" ] || continue

    func_name=$(basename "$func_dir")
    echo "==============================="
    echo "Function: $func_name"
    echo "==============================="

    find "$func_dir" -type f -name "*.ll" | while read -r llfile; do
        echo "Processing: $llfile"
        "$FUSEBACK" "$BASE_LL" "$llfile" "$func_name"
    done
done

echo "Done."