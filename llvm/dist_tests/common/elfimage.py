"""ELF loading and symbol lookup for bare-metal Cortex-M images."""

import bisect
import fnmatch
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile


@dataclass(frozen=True)
class Symbol:
    name: str
    addr: int  # thumb bit already stripped
    size: int
    kind: str  # STT_FUNC, STT_OBJECT, ...

    @property
    def end(self) -> int:
        return self.addr + self.size

    def contains(self, addr: int) -> bool:
        return self.addr <= addr < self.addr + max(self.size, 1)


@dataclass(frozen=True)
class Segment:
    addr: int
    data: bytes
    memsz: int


class ElfImage:
    """A loaded firmware image: segments to map plus a symbol index."""

    def __init__(self, path):
        self.path = str(path)
        self.segments = []
        self.symbols = []
        self._by_name = {}

        with open(self.path, "rb") as fh:
            elf = ELFFile(fh)
            if elf.header["e_machine"] != "EM_ARM":
                raise ValueError(f"{path}: not an ARM ELF ({elf.header['e_machine']})")
            self.entry = elf.header["e_entry"]

            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD" or seg["p_memsz"] == 0:
                    continue
                # Bare-metal images are loaded at their physical address; with
                # pqm4's DATA_IN_FLASH build vaddr == paddr anyway.
                self.segments.append(
                    Segment(seg["p_paddr"], seg.data(), seg["p_memsz"])
                )

            for section in elf.iter_sections():
                if section.header["sh_type"] not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                    continue
                for sym in section.iter_symbols():
                    if not sym.name:
                        continue
                    kind = sym["st_info"]["type"]
                    if kind not in ("STT_FUNC", "STT_OBJECT", "STT_NOTYPE"):
                        continue
                    addr = sym["st_value"]
                    if kind == "STT_FUNC":
                        addr &= ~1  # drop the thumb bit
                    self.symbols.append(
                        Symbol(sym.name, addr, sym["st_size"], kind)
                    )

        # A name may appear more than once (local statics); the first FUNC
        # definition wins, which is what a user typing a name expects.
        for sym in self.symbols:
            if sym.name not in self._by_name or (
                sym.kind == "STT_FUNC" and self._by_name[sym.name].kind != "STT_FUNC"
            ):
                self._by_name[sym.name] = sym

        self._index_functions()

    def _index_functions(self):
        """Order function symbols by address and give each one an extent.

        Hand-written assembly (the Keccak permutation, the NTT kernels) is
        routinely emitted with st_size == 0, so a size-only index leaves the
        hottest code in a pqm4 build unattributed.  Sizeless symbols instead
        run up to whatever symbol comes next.
        """
        funcs = sorted(
            (s for s in self.symbols if s.kind == "STT_FUNC"),
            key=lambda s: (s.addr, -s.size),
        )
        # Several symbols can share an address (a local alias for a loop
        # label); keep the first, which is the one with the largest size.
        deduped = []
        for sym in funcs:
            if not deduped or sym.addr != deduped[-1].addr:
                deduped.append(sym)

        self._funcs = deduped
        self._func_starts = [s.addr for s in deduped]
        self._func_ends = []
        for i, sym in enumerate(deduped):
            next_start = deduped[i + 1].addr if i + 1 < len(deduped) else None
            if sym.size:
                end = sym.addr + sym.size
            elif next_start is not None:
                end = next_start
            else:
                end = sym.addr + 4
            self._func_ends.append(end)

    # -- lookup -------------------------------------------------------------

    def symbol(self, name):
        """Look a symbol up by exact name, raising if it is not there."""
        try:
            return self._by_name[name]
        except KeyError:
            raise KeyError(f"{self.path}: no symbol named {name!r}") from None

    def addr_of(self, name_or_addr):
        """Resolve a symbol name (or pass an address straight through)."""
        if isinstance(name_or_addr, int):
            return name_or_addr
        return self.symbol(name_or_addr).addr

    def find(self, pattern, kind=None):
        """All symbols whose name matches a glob pattern, sorted by address."""
        out = [
            s
            for s in self.symbols
            if fnmatch.fnmatch(s.name, pattern) and (kind is None or s.kind == kind)
        ]
        return sorted(out, key=lambda s: s.addr)

    def func_at(self, addr):
        """The function containing `addr`, or None."""
        i = bisect.bisect_right(self._func_starts, addr) - 1
        if i < 0:
            return None
        return self._funcs[i] if addr < self._func_ends[i] else None

    def extent_of(self, name_or_addr):
        """(start, end) of a function, using the inferred end for sizeless ones."""
        addr = self.addr_of(name_or_addr)
        i = bisect.bisect_right(self._func_starts, addr) - 1
        if i < 0 or addr >= self._func_ends[i]:
            raise KeyError(f"{addr:#010x} is not inside a known function")
        return self._func_starts[i], self._func_ends[i]

    def describe(self, addr):
        """`addr` rendered as `func+0x..` when it falls inside a function."""
        sym = self.func_at(addr)
        if sym is None:
            return f"{addr:#010x}"
        off = addr - sym.addr
        return f"{sym.name}+{off:#x}" if off else sym.name

    @property
    def functions(self):
        return list(self._funcs)
