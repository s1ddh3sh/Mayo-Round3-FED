#!/usr/bin/env bash
#
# mayo_build.sh — compile every .ll file under a MAYO function's test
# directory into an ELF, then extract its qemu_witness.json.
#
# Usage:
#   ./mayo_build.sh <directory>   # build just this one function directory
#   ./mayo_build.sh               # build EVERY directory under test_mayo/
#
# Examples:
#   ./mayo_build.sh test_mayo/mul_add_m_upper_triangular_mat_x_mat
#   ./mayo_build.sh
#
# Paths are relative to llvm/ (the script cds there itself); ELFs go to
# llvm/build/test_mayo/<function>/. The IR comes from LLVM 20, so llc-20 is
# used unless LLC is set. Link inputs (startup/HAL lib, linker script) are
# in dist_tests/obj/.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LLC="${LLC:-$(command -v llc-20 || command -v llc)}"
OBJ_DIR="dist_tests/obj"

build_one_dir() {
    (
        set -euo pipefail
        TARGET_DIR="$1"

        if [ ! -d "$TARGET_DIR" ]; then
            echo "[!] Directory '$TARGET_DIR' not found." >&2
            exit 1
        fi

        LL_FILES=()
        while IFS= read -r -d '' f; do
            LL_FILES+=("$f")
        done < <(find "$TARGET_DIR" -type f -name "*.ll" -print0)

        if [ "${#LL_FILES[@]}" -eq 0 ]; then
            echo "[!] No .ll files found under '$TARGET_DIR'." >&2
            exit 1
        fi
        TOP_BUILD_DIR="build/${TARGET_DIR}"
        if [ -d "$TOP_BUILD_DIR" ]; then
            echo "[i] removing stale build directory: $TOP_BUILD_DIR"
            rm -rf "$TOP_BUILD_DIR"
        fi
        for INPUT in "${LL_FILES[@]}"; do
            echo "=========================================="
            echo "Processing: $INPUT"
            echo "=========================================="

            FILENAME=$(basename "$INPUT" .ll)
            INPUT_DIR=$(dirname "$INPUT")

            # Mirror the source folder structure inside the build directory
            if [ "$INPUT_DIR" = "." ]; then
                BUILD_DIR="build"
            else
                BUILD_DIR="build/$INPUT_DIR"
            fi

            mkdir -p "$BUILD_DIR"

            # Compile LLVM IR to object file
            "$LLC" \
              -march=arm \
              -mcpu=cortex-m4 \
              -mattr=+thumb2,+vfp4d16 \
              -float-abi=hard \
              -filetype=obj \
              "$INPUT" \
              -o "${BUILD_DIR}/${FILENAME}.o"

            # Link object file into ELF
            arm-none-eabi-gcc \
                "${BUILD_DIR}/${FILENAME}.o" \
                "${OBJ_DIR}/common/assert_stub.o" \
                -L"${OBJ_DIR}" \
                -lpqm4hal \
                --specs=nosys.specs \
                -Wl,--wrap=_sbrk \
                -Wl,--wrap=_open \
                -Wl,--wrap=_close \
                -Wl,--wrap=_isatty \
                -Wl,--wrap=_kill \
                -Wl,--wrap=_lseek \
                -Wl,--wrap=_read \
                -Wl,--wrap=_write \
                -Wl,--wrap=_fstat \
                -Wl,--wrap=_getpid \
                -Wl,--no-warn-rwx-segments \
                -ffreestanding \
                -T "${OBJ_DIR}/ldscript.ld" \
                -mcpu=cortex-m4 \
                -mthumb \
                -mfloat-abi=hard \
                -mfpu=fpv4-sp-d16 \
                -o "${BUILD_DIR}/${FILENAME}.elf"

            echo "${BUILD_DIR}/${FILENAME}.elf generated."
            echo "Run QEMU with:"
            echo "qemu-system-arm \\"
            echo "    -M mps2-an386 \\"
            echo "    -kernel \"${BUILD_DIR}/${FILENAME}.elf\" \\"
            echo "    -nographic \\"
            echo "    -semihosting \\"
            echo "    -S \\"
            echo "    -gdb tcp::1234"
            echo ""
        done

        # Extract target folder name and construct the target .ll path
        FOLDER_NAME=$(basename "$(realpath "$TARGET_DIR")")
        LL_FILE="${TARGET_DIR}/${FOLDER_NAME}.ll"

        if [ ! -f "$LL_FILE" ]; then
            echo "[!] Expected top-level .ll '$LL_FILE' not found (directory " \
                 "name must match its own correct-build .ll file) -- skipping " \
                 "witness extraction for $TARGET_DIR." >&2
            exit 1
        fi

        echo "Extracting qemu inputs for: $LL_FILE"
        python3 dist_tests/mayo/setup/extract_qemu_witness.py "$LL_FILE"
    )
}

usage() {
    echo "Usage: $0 [directory]" >&2
    echo "  $0 test_mayo/mul_add_m_upper_triangular_mat_x_mat   # build just this one function" >&2
    echo "  $0                                                     # build every folder under test_mayo/" >&2
}

main() {
    if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
        usage
        exit 0
    fi

    if [ -n "${1:-}" ]; then
        # Accept the directory relative to the caller's cwd or to llvm/.
        local target="$1"
        if [ -d "$target" ]; then
            target="$(realpath --relative-to="$ROOT_DIR" "$target")"
        fi
        cd "$ROOT_DIR"
        build_one_dir "$target"
        exit $?
    fi

    cd "$ROOT_DIR"

    if [ ! -d test_mayo ]; then
        echo "Error: test_mayo/ not found (run from the repo root, or pass" >&2
        echo "an explicit directory as before)." >&2
        exit 1
    fi

    DIRS=()
    for d in test_mayo/*/; do
        [ -d "$d" ] && DIRS+=("${d%/}")
    done

    if [ "${#DIRS[@]}" -eq 0 ]; then
        echo "Error: no subdirectories found under test_mayo/." >&2
        exit 1
    fi

    echo "[i] found ${#DIRS[@]} function directories under test_mayo/"

    FAILED=()
    for dir in "${DIRS[@]}"; do
        echo
        echo "############################################"
        echo "# Building function directory: $dir"
        echo "############################################"
        if build_one_dir "$dir"; then
            echo "[i] OK: $dir"
        else
            echo "[!] FAILED: $dir" >&2
            FAILED+=("$dir")
        fi
    done

    echo
    echo "=== Summary: $((${#DIRS[@]} - ${#FAILED[@]}))/${#DIRS[@]} directories built successfully ==="
    if [ "${#FAILED[@]}" -gt 0 ]; then
        echo "Failed directories:" >&2
        printf '  %s\n' "${FAILED[@]}" >&2
        exit 1
    fi
}

main "$@"