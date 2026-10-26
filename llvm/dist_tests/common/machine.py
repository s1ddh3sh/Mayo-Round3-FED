"""The emulated Cortex-M4 machine: load a firmware, boot it, call into it."""

import hashlib
import struct

import capstone
import unicorn
from unicorn import Uc, UcError
from unicorn import arm_const as A

from .elfimage import ElfImage
from .platform import MPS2_AN386, Peripherals

# Registers addressable by name through Machine.reg / Machine.set_reg.
REGS = {
    **{f"r{i}": getattr(A, f"UC_ARM_REG_R{i}") for i in range(13)},
    "sp": A.UC_ARM_REG_SP,
    "lr": A.UC_ARM_REG_LR,
    "pc": A.UC_ARM_REG_PC,
    "cpsr": A.UC_ARM_REG_CPSR,
    "r13": A.UC_ARM_REG_SP,
    "r14": A.UC_ARM_REG_LR,
    "r15": A.UC_ARM_REG_PC,
}
GP_REGS = [f"r{i}" for i in range(13)] + ["sp", "lr"]

# ARM semihosting operations (only the ones bare-metal pqm4 firmware uses).
SYS_WRITEC = 0x03
SYS_WRITE0 = 0x04
SYS_WRITE = 0x05
SYS_EXIT = 0x18

EXCP_BKPT = 7

# Spellings of the guest RNG entry point, most specific first.
RNG_SYMBOLS = ("randombytes", "PQCLEAN_randombytes")


class EmulationError(RuntimeError):
    """Raised when the guest faults or runs past its instruction budget."""

    def __init__(self, message, machine=None):
        if machine is not None:
            message = f"{message} at {machine.where()} after {machine.icount} insns"
        super().__init__(message)


class Snapshot:
    """Full machine state: registers, memory, and framework bookkeeping."""

    __slots__ = ("_ctx", "_mem", "icount", "_alloc", "_uart", "_periph", "_streams")

    def __init__(self, ctx, mem, icount, alloc, uart, periph, streams):
        self._ctx = ctx
        self._mem = mem
        self.icount = icount
        self._alloc = alloc
        self._uart = uart
        self._periph = periph
        # Python-side state that is part of the machine's behaviour, e.g. how
        # far a stubbed RNG stream has been consumed.
        self._streams = streams


class Machine:
    """A Cortex-M4 running a firmware image, with research-friendly hooks.

    Typical use::

        m = Machine.from_elf("firmware/mldsa44_m4f_test.elf")
        m.run()                       # boot and run to completion
        print(m.uart_text())

    or, to drive one function at a time::

        m = Machine.from_elf(...)
        m.boot()                      # stop at main(), C runtime initialised
        pk, sk = m.alloc(1312), m.alloc(2560)
        m.call("crypto_sign_keypair", [pk, sk])
    """

    def __init__(self, image, platform=MPS2_AN386, cpu=None):
        self.image = image
        self.platform = platform
        self.icount = 0
        self.exited = False
        self.exit_code = None

        self._precise = False
        self._block_cache = {}
        self._intercepts = {}
        self._hook_handles = []
        self._streams = []
        self._halt_reason = None

        self.uc = Uc(
            unicorn.UC_ARCH_ARM,
            unicorn.UC_MODE_THUMB | unicorn.UC_MODE_MCLASS | unicorn.UC_MODE_LITTLE_ENDIAN,
        )
        self.uc.ctl_set_cpu_model(cpu if cpu is not None else A.UC_CPU_ARM_CORTEX_M4)

        self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self.cs.detail = False

        self.peripherals = Peripherals(platform, lambda: self.icount)

        self._map_memory()
        self._load_image()
        self._install_core_hooks()
        self.reset()

    @classmethod
    def from_elf(cls, path, platform=MPS2_AN386, **kwargs):
        return cls(ElfImage(path), platform=platform, **kwargs)

    # -- setup --------------------------------------------------------------

    def _map_memory(self):
        p = self.platform
        for region in p.ram_regions:
            self.uc.mem_map(region.base, region.size)
        for region in (p.apb, p.ppb):
            # Unicorn reports MMIO accesses as an offset into the region, so
            # each region gets its own pair of callbacks carrying its base.
            self.uc.mmio_map(
                region.base,
                region.size,
                self._mmio_read,
                region.base,
                self._mmio_write,
                region.base,
            )
        # Direct calls return to this address; the guest never executes it
        # because emu_start is told to stop there, but it must be mapped so
        # that a stray return does not fault.
        self.uc.mem_write(p.trampoline.base, b"\xfe\xe7" * 8)  # b .

    def _load_image(self):
        for seg in self.image.segments:
            self.uc.mem_write(seg.addr, seg.data)
            pad = seg.memsz - len(seg.data)
            if pad > 0:  # .bss
                self.uc.mem_write(seg.addr + len(seg.data), b"\x00" * pad)

    def _install_core_hooks(self):
        uc = self.uc
        uc.hook_add(unicorn.UC_HOOK_INTR, self._hook_intr)
        uc.hook_add(unicorn.UC_HOOK_BLOCK, self._hook_block)
        uc.hook_add(
            unicorn.UC_HOOK_MEM_READ_UNMAPPED
            | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED
            | unicorn.UC_HOOK_MEM_FETCH_UNMAPPED,
            self._hook_unmapped,
        )

    def reset(self):
        """Put the core back in its post-reset state (does not reload memory)."""
        sp, entry = struct.unpack("<II", self.uc.mem_read(self.platform.flash.base, 8))
        self.uc.reg_write(A.UC_ARM_REG_SP, sp)
        self.uc.reg_write(A.UC_ARM_REG_PC, entry | 1)
        self.icount = 0
        self.exited = False
        self.exit_code = None
        self._booted = False
        self._alloc_ptr = self.platform.scratch.base

    # -- MMIO ---------------------------------------------------------------

    def _mmio_read(self, uc, offset, size, region_base):
        return self.peripherals.read(region_base + offset, size)

    def _mmio_write(self, uc, offset, size, value, region_base):
        self.peripherals.write(region_base + offset, size, value)

    # -- core hooks ---------------------------------------------------------

    def _hook_unmapped(self, uc, access, addr, size, value, _):
        self._halt_reason = f"unmapped access to {addr:#010x} (size {size})"
        return False  # let Unicorn raise

    def block_insn_count(self, addr, size):
        """Number of instructions in the basic block at `addr` (cached)."""
        key = (addr, size)
        count = self._block_cache.get(key)
        if count is None:
            code = self.uc.mem_read(addr, size)
            count = sum(1 for _ in self.cs.disasm(bytes(code), addr))
            self._block_cache[key] = count
        return count

    def _hook_block(self, uc, addr, size, _):
        if self._precise or size == 0:
            return
        self.icount += self.block_insn_count(addr, size)

    def _hook_precise_count(self, uc, addr, size, _):
        self.icount += 1

    def _hook_intr(self, uc, intno, _):
        if intno != EXCP_BKPT:
            self._halt_reason = f"cpu exception {intno}"
            uc.emu_stop()
            return
        pc = uc.reg_read(A.UC_ARM_REG_PC)
        insn = struct.unpack("<H", uc.mem_read(pc, 2))[0]
        if (insn & 0xFF00) != 0xBE00:  # not a BKPT: a real debug event
            self._halt_reason = f"unexpected breakpoint exception at {pc:#010x}"
            uc.emu_stop()
            return
        if (insn & 0xFF) != 0xAB:  # BKPT that is not a semihosting call
            self._halt_reason = f"BKPT #{insn & 0xFF:#x} at {pc:#010x}"
            uc.emu_stop()
            return
        result = self._semihosting(uc.reg_read(A.UC_ARM_REG_R0), uc.reg_read(A.UC_ARM_REG_R1))
        if result is None:  # SYS_EXIT
            uc.emu_stop()
            return
        uc.reg_write(A.UC_ARM_REG_R0, result)
        uc.reg_write(A.UC_ARM_REG_PC, pc + 2)

    def _semihosting(self, op, arg):
        uc = self.uc
        if op == SYS_EXIT:
            self.exited = True
            self.exit_code = arg
            return None
        if op == SYS_WRITEC:
            self._uart_emit(bytes(uc.mem_read(arg, 1)))
            return 0
        if op == SYS_WRITE0:
            out = bytearray()
            addr = arg
            while True:
                chunk = bytes(uc.mem_read(addr, 64))
                nul = chunk.find(b"\x00")
                if nul >= 0:
                    out += chunk[:nul]
                    break
                out += chunk
                addr += 64
            self._uart_emit(bytes(out))
            return 0
        if op == SYS_WRITE:
            _fd, ptr, length = struct.unpack("<III", uc.mem_read(arg, 12))
            self._uart_emit(bytes(uc.mem_read(ptr, length)))
            return 0
        return 0xFFFFFFFF  # unsupported call, as the spec prescribes

    def _uart_emit(self, data):
        for byte in data:
            self.peripherals.uart_out.append(byte)
            if self.peripherals.on_uart_byte is not None:
                self.peripherals.on_uart_byte(byte)

    # -- registers and memory ----------------------------------------------

    def reg(self, name):
        return self.uc.reg_read(REGS[name.lower()])

    def set_reg(self, name, value):
        self.uc.reg_write(REGS[name.lower()], value & 0xFFFFFFFF)

    def regs(self):
        return dict(zip(GP_REGS, self.uc.reg_read_batch([REGS[n] for n in GP_REGS])))

    def reg_batch(self, names):
        """Read several registers in one call into Unicorn.

        Per-instruction models (leakage, register-file diffs) read the whole
        file on every sample, where the per-call overhead dominates.
        """
        return self.uc.reg_read_batch([REGS[n.lower()] for n in names])

    def set_pc(self, addr):
        """Redirect execution, keeping the core in Thumb state.

        Cortex-M has no ARM mode, so a PC written with bit 0 clear makes
        Unicorn fetch the target as an A32 instruction and fault.  Anything
        that moves the PC (interception, instruction skipping) goes through
        here.
        """
        self.uc.reg_write(A.UC_ARM_REG_PC, (addr | 1) & 0xFFFFFFFF)

    def read(self, addr, size):
        return bytes(self.uc.mem_read(addr, size))

    def write(self, addr, data):
        self.uc.mem_write(addr, bytes(data))

    def read_u32(self, addr):
        return struct.unpack("<I", self.uc.mem_read(addr, 4))[0]

    def write_u32(self, addr, value):
        self.uc.mem_write(addr, struct.pack("<I", value & 0xFFFFFFFF))

    def alloc(self, size, align=8, fill=b"\x00"):
        """Reserve a buffer in framework-owned scratch memory."""
        base = (self._alloc_ptr + align - 1) & ~(align - 1)
        end = base + size
        if end > self.platform.scratch.end:
            raise EmulationError("scratch memory exhausted")
        self._alloc_ptr = end
        if fill:
            self.uc.mem_write(base, (fill * size)[:size])
        return base

    def alloc_bytes(self, data, align=8):
        addr = self.alloc(len(data), align=align, fill=b"")
        self.uc.mem_write(addr, bytes(data))
        return addr

    def scratch_mark(self):
        """Return the current scratch high-water mark, to be handed back to
        :meth:`scratch_reset`.  Use it to reclaim per-iteration scratch buffers
        in a loop so repeated `alloc`s do not exhaust the scratch region::

            mark = m.scratch_mark()
            for msg in messages:
                m.scratch_reset(mark)      # free last iteration's buffers
                ...
        """
        return self._alloc_ptr

    def scratch_reset(self, mark):
        """Rewind the scratch allocator to a mark from :meth:`scratch_mark`,
        freeing everything allocated since (the memory is not cleared, just made
        available again)."""
        self._alloc_ptr = mark

    # -- symbols ------------------------------------------------------------

    def addr_of(self, name_or_addr):
        return self.image.addr_of(name_or_addr)

    def where(self):
        """Current PC, rendered as `func+offset`."""
        return self.image.describe(self.reg("pc"))

    def uart_text(self):
        return self.peripherals.uart_out.decode("utf-8", errors="replace")

    # -- hooks --------------------------------------------------------------

    def add_hook(self, htype, callback, begin=1, end=0, user_data=None):
        """Register a Unicorn hook and make it apply to existing code.

        Unicorn compiles hook checks into its translation blocks, so a hook
        added after a block has already been translated is simply never called
        there.  Flushing the block cache is what makes it legitimate to attach
        a tracer or an injector to a machine that has already been booted --
        without it, hooks fire only on code the guest has not run yet.
        """
        handle = self.uc.hook_add(htype, callback, user_data, begin, end)
        self.uc.ctl_flush_tb()
        self._hook_handles.append(handle)
        return handle

    def hook_block(self, callback):
        """Per-basic-block hook; `callback(machine, address, size)`."""

        def shim(uc, address, size, _):
            callback(self, address, size)

        return self.add_hook(unicorn.UC_HOOK_BLOCK, shim)

    def hook_code(self, callback, begin=1, end=0, precise=True):
        """Per-instruction hook; `callback(machine, address, size)`.

        Restrict it with begin/end where possible: a whole-program code hook
        costs roughly an order of magnitude in emulation speed.

        `precise` also switches the machine to exact instruction counting,
        which is needed by anything that reports or triggers on an
        instruction index.  A hook scoped to a single address usually does not
        need it, and leaving it off keeps the fast block-level counter.
        """
        if precise:
            self._enable_precise_counting()

        def shim(uc, address, size, _):
            callback(self, address, size)

        return self.add_hook(unicorn.UC_HOOK_CODE, shim, begin=begin, end=end)

    def hook_mem(self, callback, read=True, write=True, begin=1, end=0):
        """Memory access hook; `callback(machine, is_write, addr, size, value)`."""

        def shim(uc, access, addr, size, value, _):
            callback(self, access == unicorn.UC_MEM_WRITE, addr, size, value)

        htype = 0
        if read:
            htype |= unicorn.UC_HOOK_MEM_READ
        if write:
            htype |= unicorn.UC_HOOK_MEM_WRITE
        return self.add_hook(htype, shim, begin=begin, end=end)

    def unhook(self, handle):
        self.uc.hook_del(handle)
        self.uc.ctl_flush_tb()
        if handle in self._hook_handles:
            self._hook_handles.remove(handle)

    def _enable_precise_counting(self):
        """Count every instruction instead of estimating per basic block.

        Block-level counting is fast but only updates when a block starts, so
        anything that needs an exact instruction index (tracing, fault
        injection) switches the machine over to per-instruction counting.
        """
        if self._precise:
            return
        self._precise = True
        self.add_hook(unicorn.UC_HOOK_CODE, self._hook_precise_count)

    @property
    def precise_counting(self):
        return self._precise

    # -- function interception ---------------------------------------------

    def intercept(self, func, handler):
        """Replace a guest function with a Python one.

        `handler(machine)` runs instead of the function body; whatever it
        returns is placed in r0 (or r0/r1 for a 2-tuple) and control returns
        to the caller.  Used to pin down randomness and timing, and handy for
        stubbing out anything the model does not need to execute.
        """
        addr = self.addr_of(func)

        def shim(uc, address, size, _):
            result = handler(self)
            if isinstance(result, tuple):
                self.set_reg("r0", result[0])
                self.set_reg("r1", result[1])
            elif result is not None:
                self.set_reg("r0", result)
            self.set_pc(uc.reg_read(A.UC_ARM_REG_LR))

        handle = self.add_hook(unicorn.UC_HOOK_CODE, shim, begin=addr, end=addr)
        self._intercepts[addr] = handle
        return handle

    def stub_randombytes(self, seed=b"", symbol=None):
        """Make the guest RNG a reproducible SHAKE256 stream.

        The symbol is auto-detected across the usual spellings (pqm4 renames
        randombytes to PQCLEAN_randombytes) unless one is given.  Returns the
        stream object, so a campaign can rewind it between trials.
        """
        if symbol is None:
            for candidate in RNG_SYMBOLS:
                try:
                    self.image.symbol(candidate)
                except KeyError:
                    continue
                symbol = candidate
                break
            else:
                raise KeyError(
                    f"no RNG symbol found (looked for {', '.join(RNG_SYMBOLS)}); "
                    "pass symbol=..."
                )
        stream = _Xof(seed)
        self._streams.append(stream)

        def handler(m):
            buf, length = m.reg("r0"), m.reg("r1")
            m.write(buf, stream.read(length))
            return 0

        self.intercept(symbol, handler)
        return stream

    def stub_cycle_counter(self, symbol="hal_get_time"):
        """Report the emulated instruction count as the guest's cycle counter.

        The firmware's own hal_get_time() reads SysTick and relies on an
        overflow interrupt we do not deliver, so anything measuring more than
        16.7 M cycles would wrap.  This makes hal_get_time() exact instead.
        """
        try:
            self.intercept(symbol, lambda m: (m.icount & 0xFFFFFFFF, m.icount >> 32))
        except KeyError:
            return False
        return True

    # -- execution ----------------------------------------------------------

    def _emu_start(self, begin, until, count=0, timeout=0):
        self._halt_reason = None
        try:
            self.uc.emu_start(begin, until, timeout=timeout, count=count)
        except UcError as exc:
            reason = self._halt_reason or str(exc)
            raise EmulationError(f"emulation fault: {reason}", self) from None
        if self._halt_reason is not None:
            raise EmulationError(self._halt_reason, self)

    def run(self, max_instructions=0, timeout=0):
        """Boot from the reset vector and run until the firmware exits.

        `max_instructions` and `timeout` (microseconds) are safety nets; 0
        means unlimited.
        """
        self._emu_start(
            self.reg("pc") | 1, 0, count=max_instructions, timeout=timeout
        )
        if not self.exited and max_instructions:
            raise EmulationError(
                f"instruction budget of {max_instructions} exhausted", self
            )
        return self.exit_code

    def run_until(self, target, max_instructions=0, timeout=0):
        """Run from the current PC until `target` is reached."""
        addr = self.addr_of(target)
        self._emu_start(self.reg("pc") | 1, addr, count=max_instructions, timeout=timeout)
        if self.reg("pc") & ~1 != addr:
            raise EmulationError(f"never reached {self.image.describe(addr)}", self)
        return addr

    def boot(self, stop_at="main", max_instructions=50_000_000):
        """Run reset -> C runtime init -> `stop_at`, then hand control back.

        This is what makes direct calls safe: .bss is zeroed, the FPU is on
        and constructors have run by the time we take over.
        """
        if self._booted:
            return
        self.run_until(stop_at, max_instructions=max_instructions)
        self._booted = True

    def call(
        self,
        func,
        args=(),
        max_instructions=200_000_000,
        timeout=0,
        stack_size=0x40000,
        ret64=False,
    ):
        """Call a guest function with the AAPCS calling convention.

        Arguments are 32-bit words (pass pointers as addresses); the first
        four go in r0-r3 and the rest on the stack.  Returns r0, or the
        r1:r0 pair when `ret64` is set.
        """
        if not self._booted:
            self.boot()

        addr = self.addr_of(func)
        ret_addr = self.platform.trampoline.base

        sp = (self.platform.stack_top - stack_size) & ~7
        args = list(args)
        stacked = args[4:]
        if stacked:
            if len(stacked) % 2:  # keep the 8-byte stack alignment
                stacked.append(0)
            sp -= 4 * len(stacked)
            self.write(sp, struct.pack(f"<{len(stacked)}I", *[a & 0xFFFFFFFF for a in stacked]))

        for i, value in enumerate(args[:4]):
            self.set_reg(f"r{i}", value)
        self.set_reg("sp", sp)
        self.set_reg("lr", ret_addr | 1)

        self._emu_start(addr | 1, ret_addr, count=max_instructions, timeout=timeout)

        pc = self.reg("pc") & ~1
        if pc != ret_addr:
            raise EmulationError(
                f"{self.image.describe(addr)} did not return "
                f"(budget {max_instructions} insns)",
                self,
            )
        if ret64:
            return (self.reg("r1") << 32) | self.reg("r0")
        return self.reg("r0")

    # -- snapshots ----------------------------------------------------------

    def snapshot(self, regions=None):
        """Capture registers + memory so a trial can be replayed cheaply."""
        regions = regions or self.platform.ram_regions
        mem = {r.name: (r.base, bytes(self.uc.mem_read(r.base, r.size))) for r in regions}
        return Snapshot(
            self.uc.context_save(),
            mem,
            self.icount,
            self._alloc_ptr,
            bytes(self.peripherals.uart_out),
            dict(self.peripherals.regs),
            [(s, s.pos) for s in self._streams],
        )

    def restore(self, snap):
        self.uc.context_restore(snap._ctx)
        for base, data in snap._mem.values():
            self.uc.mem_write(base, data)
        self.icount = snap.icount
        self._alloc_ptr = snap._alloc
        self.peripherals.uart_out[:] = snap._uart
        self.peripherals.regs = dict(snap._periph)
        for stream, pos in snap._streams:
            stream.pos = pos
        self.exited = False
        self.exit_code = None
        self._booted = True

    # -- disassembly --------------------------------------------------------

    def disasm(self, addr, count=1):
        """Disassemble `count` instructions at `addr`."""
        code = bytes(self.uc.mem_read(addr, 4 * count + 4))
        out = []
        for insn in self.cs.disasm(code, addr, count):
            out.append((insn.address, insn.size, f"{insn.mnemonic} {insn.op_str}".strip()))
        return out

    def disasm_one(self, addr):
        found = self.disasm(addr, 1)
        return found[0] if found else (addr, 2, "(undecodable)")


class _Xof:
    """Deterministic byte stream (SHAKE256) used to replace the guest RNG."""

    def __init__(self, seed=b""):
        self.seed = bytes(seed)
        self.pos = 0

    def read(self, length):
        # SHAKE is squeezed from the start every time and sliced, which keeps
        # the stream a pure function of (seed, pos) and therefore rewindable.
        end = self.pos + length
        out = hashlib.shake_256(self.seed).digest(end)[self.pos : end]
        self.pos = end
        return out

    def reset(self, seed=None):
        if seed is not None:
            self.seed = bytes(seed)
        self.pos = 0
