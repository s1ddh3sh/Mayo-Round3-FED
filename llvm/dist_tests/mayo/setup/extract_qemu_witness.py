#!/usr/bin/env python3
"""
extract_qemu_witness.py — derive a layout-only qemu_witness.json for a
function-under-test directly from its generated main()-driver .ll file
and its mayo.json entry (no per-function testcase file: inputs default to
zero, mayo.json says which parameters are outputs).
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple


# Standard primitive size map in bytes
TYPE_SIZES = {
    "i8": 1,
    "i16": 2,
    "i32": 4,
    "i64": 8,
    "ptr": 8,
}

NAME_TOKEN_RE = re.compile(r'[a-z0-9]+')

# A pointer arg's backing alloca is flagged as a likely reused/placeholder
# buffer -- not one actually sized for this argument -- when it is both
# (a) unrelated by name to the argument key it's bound to, and (b) more
# than this many times larger than every OTHER pointer buffer in the same
# call. Both conditions together avoid flagging legitimately big buffers
# (llvmbmc variable names routinely don't match the source argument name,
# so name mismatch alone is too weak a signal; sheer size alone is too,
# since some functions genuinely need one big buffer among small ones).
OVERSIZE_RATIO = 5

# Matches the START of any alloca statement we care about: %name = alloca
# What follows -- an array type "[N x TYPE]" (possibly nested, e.g. a
# matrix's "[M x [N x i8]]"), or a bare scalar type like "i32" (e.g.
# `%siglen = alloca i32, ...` for a `size_t *siglen` out-param) -- is
# parsed separately below, since a single regex can't handle both an
# arbitrary nesting depth and the "no brackets at all" scalar case.
ALLOCA_START_RE = re.compile(r'%(?P<name>\w+)\s*=\s*alloca\s+')


def _find_matching_bracket(text: str, open_idx: int) -> int:
    """text[open_idx] must be '['. Returns the index of its matching ']'."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == '[':
            depth += 1
        elif text[i] == ']':
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced '[' in alloca type")


def _parse_array_type(type_text: str):
    """
    type_text is the content INSIDE one outer [...], e.g. "1184 x i8" or
    "3 x [256 x i16]" (a nested/matrix array: 3 rows of 256 i16 each).
    Recurses through nested array dimensions and returns
    (total_element_count, base_type_str) with the dimensions multiplied
    out -- e.g. "3 x [256 x i16]" -> (768, "i16").
    """
    m = re.match(r'\s*(\d+)\s*x\s*(.*)$', type_text, re.DOTALL)
    if not m:
        raise ValueError(f"cannot parse array type: {type_text!r}")
    count = int(m.group(1))
    rest = m.group(2).strip()
    if rest.startswith('['):
        end = _find_matching_bracket(rest, 0)
        inner_count, inner_base = _parse_array_type(rest[1:end])
        return count * inner_count, inner_base
    return count, rest


def extract_allocas(ll_text: str) -> Tuple[Dict[str, int], set]:
    """Returns (sizes, scalar_ptr_names):

      sizes: {var_name: raw alloca total byte size}, in first-appearance
        order.
      scalar_ptr_names: the subset of `sizes` keys that came from the
        SCALAR alloca form rather than an array -- i.e. a POINTER argument
        whose traced root was itself a scalar local (e.g. a `size_t *smlen`
        out-parameter). derive_layout marks such an argument
        "type": "scalar_ptr" plus an "init_value" of 0 (the driver zero-fills it).

    Handles three alloca shapes, all requiring !llvmbmc.var on the same
    statement to be picked up at all:
      - array:        %buf = alloca [1184 x i8], ..., !llvmbmc.var !N
      - nested array:  %mat = alloca [3 x [256 x i16]], ..., !llvmbmc.var !N
      - scalar:        %siglen = alloca i32, ..., !llvmbmc.var !N
    """
    allocas = {}
    scalar_ptr_names = set()
    for m in ALLOCA_START_RE.finditer(ll_text):
        var_name = m.group("name")
        pos = m.end()

        line_end = ll_text.find('\n', pos)
        if line_end == -1:
            line_end = len(ll_text)

        after_alloca = ll_text[pos:line_end]
        stripped = after_alloca.lstrip()
        leading_ws = len(after_alloca) - len(stripped)

        if stripped.startswith('['):
            # Array form (possibly nested) -- bracket-match to find the
            # true end of the type, which may extend past this line only
            # in pathological formatting; in practice always same-line.
            open_idx = pos + leading_ws
            try:
                close_idx = _find_matching_bracket(ll_text, open_idx)
            except ValueError:
                continue
            stmt_tail_end = ll_text.find('\n', close_idx)
            if stmt_tail_end == -1:
                stmt_tail_end = len(ll_text)
            if '!llvmbmc.var' not in ll_text[close_idx:stmt_tail_end]:
                continue
            type_text = ll_text[open_idx + 1:close_idx]
            try:
                count, base_type = _parse_array_type(type_text)
            except ValueError:
                continue
            elem_size = TYPE_SIZES.get(base_type, 1)
            allocas[var_name] = count * elem_size
        else:
            # Scalar form: no brackets at all -- `alloca i32, align 16,
            # !llvmbmc.var !N`. The type is the first token; whatever
            # follows (align, !llvmbmc.var, ...) is on the same line.
            if '!llvmbmc.var' not in after_alloca:
                continue
            type_m = re.match(r'([%\w.]+)', stripped)
            if not type_m:
                continue
            base_type = type_m.group(1)
            allocas[var_name] = TYPE_SIZES.get(base_type, 1)
            scalar_ptr_names.add(var_name)

    return allocas, scalar_ptr_names


def find_main_body(ll_text: str) -> str:
    """Extract the brace-balanced body of `define ... @main(...) { ... }`."""
    m = re.search(r'define[^\n]*@main\s*\([^)]*\)[^\{]*\{', ll_text)
    if not m:
        raise ValueError("Could not find @main definition in .ll file")
    start = m.end()
    depth, i = 1, m.end()
    while i < len(ll_text) and depth > 0:
        if ll_text[i] == '{':
            depth += 1
        elif ll_text[i] == '}':
            depth -= 1
        i += 1
    return ll_text[start:i - 1]


def find_fut_call(main_body: str, fn_name: str) -> List[Tuple[str, str]]:
    """
    Locate `call [fastcc] <ty> @<fn_name>(...)` inside main() and parse
    its argument list. Tolerates extra pointer attributes like `nonnull`.
    """
    call_re = re.compile(
        r'call\s+(?:fastcc\s+)?[\w%]+\s+@' + re.escape(fn_name) +
        r'\s*\((?P<args>.*?)\)',
        re.DOTALL,
    )
    m = call_re.search(main_body)
    if not m:
        raise ValueError(f"Could not find call to @{fn_name} inside main()")

    args: List[Tuple[str, str]] = []
    for raw in m.group("args").split(","):
        raw = raw.strip()
        if not raw:
            continue

        # Updated regex to match optional parameter attributes like `nonnull`, `nocapture`
        pm = re.search(r'ptr\s+(?:[\w\s]+\s+)?%(?P<ptr>\w+)', raw)
        if pm:
            args.append(("ptr", pm.group("ptr")))
            continue

        im = re.search(r'i\d+\s+(?P<imm>-?\d+)', raw)
        if im:
            args.append(("imm", im.group("imm")))
            continue
        rm = re.search(r'i(?P<bits>\d+)\s+%(?P<reg>\w+)', raw)
        if rm:
            args.append(("reg", rm.group("reg")))
            continue
        raise ValueError(f"Unrecognized call argument form: '{raw}'")
    return args

def find_arg_anchor(ll_text: str, reg_name: str) -> Tuple[str, int]:
    """
    Given a register name like 'a_val', find the defining:

        %a_val = load volatile i8, ptr @__mbc_arg_add_f_a, align 1

    and return (anchor_global_name, byte_width).
    """
    pattern = re.compile(
        r'%' + re.escape(reg_name) +
        r'\s*=\s*load\s+volatile\s+i(?P<bits>\d+),\s*ptr\s+@(?P<anchor>[\w.]+)'
    )
    m = pattern.search(ll_text)
    if not m:
        raise ValueError(
            f"Could not find 'load volatile ... @__mbc_arg_*' defining "
            f"register %{reg_name}; scalar-input anchor pattern not found."
        )
    bits = int(m.group("bits"))
    if bits % 8 != 0:
        raise ValueError(f"Unsupported scalar bit width {bits} for %{reg_name}")
    return m.group("anchor"), bits // 8


def find_ret_anchor(ll_text: str, fn_name: str) -> Tuple[str, int]:
    anchor_name = f"__mbc_ret_anchor_{fn_name}"
    pattern = re.compile(
        r'store\s+volatile\s+i(?P<bits>\d+)[^\n]*?@' + re.escape(anchor_name)
    )
    m = pattern.search(ll_text)
    if not m:
        raise ValueError(
            f"Expected a 'store volatile ... @{anchor_name}' anchor write "
            f"in main() for scalar-output function '{fn_name}', found none."
        )
    return anchor_name, max(1, int(m.group("bits")) // 8)

def find_global_init(ll_text: str, anchor_name: str) -> int:
    m = re.search(
        r'@' + re.escape(anchor_name) +
        r'\s*=\s*(?:dso_local\s+)?global\s+i\d+\s+(-?\d+)',
        ll_text
    )
    if not m:
        return 0
    return int(m.group(1))

def _name_tokens(name: str) -> set:
    return set(NAME_TOKEN_RE.findall(name.lower()))


def warn_if_placeholder_buffer(key, var_name, length, key_to_arg, allocas, output_keys):
    """Best-effort sanity check for a pointer arg's backing alloca: flags
    the case where qemu_witness.json would report a wildly oversized,
    name-unrelated buffer as this key's "length" because the harness
    generator reused some OTHER buffer (e.g. a worst-case/leftover
    scratch array) for this argument slot instead of one actually sized
    for it -- see mul_add_mat_x_m_mat's 'bs_mat' bound to a 148824-byte
    '%sk' (secret-key-sized) scratch buffer for a real-world example.
    Both conditions below must hold, since neither alone is a reliable
    signal: llvmbmc variable names routinely don't match the source
    argument name, and some functions legitimately need one big pointer
    buffer among otherwise-small ones.

    Output buffers are exempt, both as the flagged key and as a sibling:
    an output's size legitimately reflects the size of its RESULT (e.g.
    an expansion function's output dwarfing its seed input), which has
    nothing to do with whether its backing alloca was sized correctly --
    and letting a huge legitimate output buffer stand in as a "sibling"
    would mask a genuinely oversized INPUT right next to it.
    """
    if key in output_keys:
        return
    sibling_lengths = [
        allocas[sib_var] for sib_key, (sib_kind, sib_var) in key_to_arg.items()
        if sib_kind == "ptr" and sib_key != key and sib_key not in output_keys
        and sib_var in allocas
    ]
    if not sibling_lengths:
        return
    name_mismatch = not (_name_tokens(key) & _name_tokens(var_name))
    oversized = length > OVERSIZE_RATIO * max(sibling_lengths)
    if name_mismatch and oversized:
        print(
            f"[!] '{key}' is backed by %{var_name} ({length} bytes), which "
            f"shares no name tokens with '{key}' and is >{OVERSIZE_RATIO}x "
            f"larger than this call's other pointer buffer(s) "
            f"({sorted(sibling_lengths)}). This looks like a reused/"
            f"placeholder buffer (e.g. a worst-case scratch array) rather "
            f"than one actually sized for '{key}' -- the reported length "
            f"is likely a large OVER-estimate of what the function really "
            f"touches, and probing/calibrating up to it may read or write "
            f"past the buffer's real usable region. Verify against the "
            f"function's actual access pattern (and consider hand-"
            f"correcting qemu_witness.json) before trusting this length."
        )


# mayo.json lives at the MAYO-C repo root; this file is
# <root>/llvm/dist_tests/mayo/setup/extract_qemu_witness.py.
DEFAULT_CONFIG = Path(__file__).resolve().parents[4] / "mayo.json"


def find_fut_params(ll_text: str, fn_name: str) -> List[Tuple[str, str]]:
    """
    Parse the FUT's own `define ... @<fn_name>(<params>)` line into
    [(type, name), ...] in declaration order, e.g.
        define dso_local fastcc void @mat_add(ptr noundef nonnull %a, ...
    -> [("ptr", "a"), ...]. These are the C parameter names (clang keeps
    them), which name the witness layout entries and match the
    __mbc_arg_<fn>_<param> scalar anchors.
    """
    m = re.search(
        r'^define[^\n]*@' + re.escape(fn_name) + r'\(',
        ll_text, re.MULTILINE,
    )
    if not m:
        raise ValueError(f"Could not find the definition of @{fn_name}")
    # Split the parameter list on top-level commas only: attributes such
    # as range(i32 80, 881) carry their own commas and parentheses.
    pieces, depth, cur = [], 0, ""
    for ch in ll_text[m.end():]:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            if depth == 0:
                break
            depth -= 1
        if ch == "," and depth == 0:
            pieces.append(cur)
            cur = ""
        else:
            cur += ch
    pieces.append(cur)
    params: List[Tuple[str, str]] = []
    for i, raw in enumerate(p.strip() for p in pieces):
        if not raw:
            continue
        ty = raw.split()[0]
        nm = re.search(r'%([\w.]+)\s*$', raw)
        name = nm.group(1) if nm and not nm.group(1).isdigit() else f"arg{i}"
        params.append((ty, name))
    return params


def load_func_config(config_path: Path, fn_name: str) -> Dict[str, object]:
    with open(config_path) as f:
        config = json.load(f)
    if fn_name not in config:
        raise ValueError(f"'{fn_name}' has no entry in {config_path}")
    return config[fn_name]


def derive_layout(ll_text: str, fn_name: str, entry: Dict[str, object]) -> Dict[str, dict]:
    """
    Build the witness layout from the FUT's parameters and the driver's
    call in main(). Inputs default to zero (the driver zero-fills every
    buffer), so there are no per-function testcases: which buffers are
    outputs comes from mayo.json's "output" (a parameter name, a list of
    them, or "ret" for the scalar return value).

    Every pointer entry records the driver alloca it is bound to under
    "alloca": the driver names buffers after their traced call-site root
    (e.g. mat_add's b is %Ox), so mayo.json may name a buffer either way
    -- see resolve_name().
    """
    allocas, scalar_ptr_names = extract_allocas(ll_text)
    call_args = find_fut_call(find_main_body(ll_text), fn_name)
    params = find_fut_params(ll_text, fn_name)

    if len(params) != len(call_args):
        raise ValueError(
            f"Mismatch: @{fn_name} has {len(params)} params "
            f"{[n for _, n in params]}, but main() calls it with "
            f"{len(call_args)} arguments {call_args}."
        )

    raw_output = entry.get("output")
    if raw_output is None:
        raise ValueError(f"mayo.json entry for '{fn_name}' has no 'output' key")
    output_keys = raw_output if isinstance(raw_output, list) else [raw_output]
    if not output_keys:
        raise ValueError(f"mayo.json entry for '{fn_name}' has an empty 'output'")

    key_to_arg = {name: arg for (_, name), arg in zip(params, call_args)}

    layout = {}
    ptr_keys = set()

    for key, (kind, val) in key_to_arg.items():
        if kind == "ptr":
            var_name = val
            if var_name not in allocas:
                raise ValueError(
                    f"Call argument %{var_name} (param '{key}') has no "
                    f"matching alloca with !llvmbmc.var in main()"
                )
            length = allocas[var_name]
            layout[key] = {"role": "input", "length": length, "alloca": var_name}
            ptr_keys.add(key)
            warn_if_placeholder_buffer(key, var_name, length, key_to_arg, allocas, output_keys)

            if var_name in scalar_ptr_names:
                # A POINTER to a single scalar (e.g. `size_t *siglen`), not
                # a byte buffer. Distinct from the anchor-based "scalar"
                # type used for register arguments: it has no anchor, its
                # address only exists at runtime via the real pointer
                # argument. The driver zero-initializes it.
                layout[key]["type"] = "scalar_ptr"
                layout[key]["init_value"] = 0

        elif kind == "reg":
            anchor_name, byte_width = find_arg_anchor(ll_text, val)
            layout[key] = {
                "role": "input",
                "type": "scalar",
                "anchor": anchor_name,
                "length": byte_width,
                "init_value": find_global_init(ll_text, anchor_name),
            }

        elif kind == "imm":
            print(
                f"[!] param '{key}' is a bare immediate ({val}); not "
                f"patchable. Check the harness generator emitted an anchor "
                f"for this argument."
            )

    if output_keys == ["ret"]:
        anchor, byte_width = find_ret_anchor(ll_text, fn_name)
        layout["ret"] = {
            "role": "output",
            "length": byte_width,
            "type": "scalar",
            "anchor": anchor,
        }
    else:
        # Mark EVERY declared output key as role="output" -- this is the
        # part that must loop over output_keys; building layout itself
        # must not.
        for output_key in output_keys:
            resolved = resolve_name(layout, output_key)
            if resolved not in ptr_keys:
                raise ValueError(
                    f"'output' key '{output_key}' does not map to a "
                    f"pointer argument of @{fn_name} "
                    f"(params: {[n for _, n in params]})."
                )
            layout[resolved]["role"] = "output"

    return layout


def resolve_name(layout: Dict[str, dict], name: str) -> str:
    """
    Map a mayo.json buffer name to its layout key: a parameter name is
    used as-is; otherwise it may be the driver alloca a single pointer
    parameter is bound to (round-2 style call-site names such as mat_add's
    "Ox"). Returns `name` unchanged if neither matches, so callers report
    the missing key themselves.
    """
    if name in layout:
        return name
    hits = [k for k, s in layout.items() if s.get("alloca") == name]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise ValueError(f"'{name}' is the alloca of several params {hits}; "
                         f"name the parameter in mayo.json instead")
    return name


def build_qemu_witness(fn_name: str, layout: Dict[str, dict]) -> Dict[str, object]:
    return {"function": fn_name, "layout": layout}


def main():
    ap = argparse.ArgumentParser(
        description="Derive layout-only qemu_witness.json from .ll file."
    )
    ap.add_argument("ll_file", type=Path, help="path to <function_name>.ll")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG,
                    help="per-function config (default: %(default)s)")
    args = ap.parse_args()

    ll_path = args.ll_file
    if not ll_path.exists():
        print(f"[!] .ll file not found: {ll_path}", file=sys.stderr)
        sys.exit(1)
    if ll_path.suffix != ".ll":
        print(f"[!] expected a .ll file, got: {ll_path}", file=sys.stderr)
        sys.exit(1)

    fn_name = ll_path.stem

    if not args.config.exists():
        print(f"[!] config not found: {args.config}", file=sys.stderr)
        sys.exit(1)

    ll_text = ll_path.read_text()
    entry = load_func_config(args.config, fn_name)

    layout = derive_layout(ll_text, fn_name, entry)
    witness = build_qemu_witness(fn_name, layout)

    out_dir = Path("test_mayo") / fn_name
    print(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "qemu_witness.json"
    with open(out_path, "w") as f:
        json.dump(witness, f, indent=2)
        f.write("\n")

    print(f"[+] wrote {out_path}")
    print(json.dumps(witness, indent=2))


if __name__ == "__main__":
    main()
