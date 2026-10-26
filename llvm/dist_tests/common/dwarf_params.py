#!/usr/bin/env python3
"""dwarf_params.py — resolve a function's formal-parameter pointer-ness
from DWARF debug info, WITHOUT needing a live gdb frame.

Why this exists
----------------
driver_dist.py (the gdb-batch-mode driver) resolves each pointer-typed
witness layout entry's runtime address by breaking at the FUT's raw
entry and reading gdb's live DWARF-based frame/block ("which local
variables are formal parameters, and which of those are pointer-typed,
in declaration order"). The Unicorn-based in-process runner
(unicorn_runner.py) does the same job differently: it stops the CPU at
the FUT's raw, PRE-PROLOGUE entry address, at which point AAPCS
guarantees argument words are still exactly in r0-r3 (first four
32-bit-or-smaller arguments) and on the incoming stack (the rest), in
declaration order -- no prologue instruction has executed yet to spill
or move them. That means all the runner actually needs from DWARF is,
for the FUT's formal parameter list IN DECLARATION ORDER, which
parameters are pointer-typed (True) vs not (False) -- not their
eventual storage location. This module answers exactly that, nothing
more.
"""

from elftools.elf.elffile import ELFFile

POINTER_TAGS = ("DW_TAG_pointer_type", "DW_TAG_array_type")
TRANSPARENT_TAGS = (
    "DW_TAG_typedef",
    "DW_TAG_const_type",
    "DW_TAG_volatile_type",
    "DW_TAG_restrict_type",
)


def _resolve_die_type(die, cu):
    """Walk a DIE's DW_AT_type chain through typedef/const/volatile/restrict
    wrappers until it lands on a pointer/array type (True), a "real" type
    like a base/structure/enum type (False), or the chain runs out with no
    DW_AT_type at all (void -- and a pointer DIE with a missing DW_AT_type
    is itself still a pointer, i.e. True; it's only "no DW_AT_type at all
    ON THE ORIGINAL PARAMETER DIE" that would mean a bare `void` parameter,
    which never happens for a real formal parameter)."""
    current = die
    while current is not None:
        if current.tag in POINTER_TAGS:
            return True
        if current.tag in TRANSPARENT_TAGS:
            if "DW_AT_type" not in current.attributes:
                # e.g. `typedef void foo;` -- treat as non-pointer, not a
                # pointer chain (this is not the pointer-DIE-with-no-target
                # case handled above).
                return False
            try:
                current = current.get_DIE_from_attribute("DW_AT_type")
            except Exception:
                return False
            continue
        # Base type, structure, union, enum, subroutine_type, ... -- not a
        # pointer.
        return False
    return False


def _param_is_pointer(param_die, cu):
    if "DW_AT_type" not in param_die.attributes:
        # A formal parameter with literally no type attribute is
        # vanishingly rare (would mean K&R-style untyped params in a
        # debug-info-emitting compiler); treat conservatively as
        # non-pointer.
        return False
    try:
        type_die = param_die.get_DIE_from_attribute("DW_AT_type")
    except Exception:
        return False
    return _resolve_die_type(type_die, cu)


def _find_subprogram_dies(cu, func_name):
    """All DW_TAG_subprogram DIEs in this CU named func_name, searched
    recursively (subprograms are usually direct children of the CU DIE,
    but nested/lexical-block placement is defensively handled too)."""
    found = []

    def walk(die):
        if die.tag == "DW_TAG_subprogram":
            name_attr = die.attributes.get("DW_AT_name")
            if name_attr is not None:
                name = name_attr.value
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                if name == func_name:
                    found.append(die)
        for child in die.iter_children():
            walk(child)

    walk(cu.get_top_DIE())
    return found


def pointer_param_order(elf_path, func_name):
    """Returns one bool per formal parameter of func_name's
    DW_TAG_subprogram, in declaration order: True if that parameter's
    type resolves (through typedef/const/volatile/restrict) to a
    pointer or array type, False otherwise.

    Raises RuntimeError if func_name has no DWARF subprogram DIE with a
    DW_AT_low_pc (i.e. only declarations were found, or none at all),
    or if it is found with a low_pc in more than one CU (cross-checked
    against the ELF symbol table's address for func_name via
    ElfImage — ambiguous debug info the caller should investigate
    rather than silently guess at).
    """
    # Local import to avoid a hard circular/ordering dependency; this
    # module is usable standalone (e.g. from the command line) too.
    from .elfimage import ElfImage

    image = ElfImage(elf_path)
    try:
        want_addr = image.symbol(func_name).addr
    except KeyError:
        want_addr = None

    candidates = []  # (low_pc, [bool, ...])

    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        if not elf.has_dwarf_info():
            raise RuntimeError(f"{elf_path}: no DWARF debug info present")
        dwarf = elf.get_dwarf_info()

        for cu in dwarf.iter_CUs():
            for die in _find_subprogram_dies(cu, func_name):
                low_pc = die.attributes.get("DW_AT_low_pc")
                if low_pc is None:
                    continue  # declaration-only DIE, skip
                addr = low_pc.value & ~1  # strip thumb bit defensively

                params = []
                for child in die.iter_children():
                    if child.tag == "DW_TAG_formal_parameter":
                        params.append(_param_is_pointer(child, cu))
                    elif child.tag == "DW_TAG_unspecified_parameters":
                        # varargs "..." -- not a real formal parameter,
                        # ignore.
                        continue
                candidates.append((addr, params))

    if not candidates:
        raise RuntimeError(
            f"{elf_path}: no DW_TAG_subprogram DIE with formal parameters "
            f"and a DW_AT_low_pc found for function {func_name!r} -- is "
            f"the ELF built with debug info (-g) for this function?"
        )

    if len(candidates) == 1:
        return candidates[0][1]

    # More than one candidate: disambiguate using the symbol table
    # address, if we have one.
    if want_addr is not None:
        matches = [params for addr, params in candidates if addr == want_addr]
        if len(matches) == 1:
            return matches[0]

    raise RuntimeError(
        f"{elf_path}: function {func_name!r} has {len(candidates)} DWARF "
        f"subprogram DIEs with low_pc set ({[hex(a) for a, _ in candidates]}), "
        f"and the ELF symbol table address "
        f"({hex(want_addr) if want_addr is not None else 'unknown'}) did not "
        f"uniquely disambiguate -- refusing to silently pick one."
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <elf> <func>", file=sys.stderr)
        sys.exit(2)
    result = pointer_param_order(sys.argv[1], sys.argv[2])
    print(f"{sys.argv[2]}: {len(result)} params, pointer-ness = {result}")
