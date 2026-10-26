"""Machine model for the ARM Cortex-M4 target the Dilithium firmware runs on.

The default board is MPS2-AN386 (the same one pqm4 and the QEMU-test flow use),
so ELFs built by `make firmware` are byte-identical to what
`qemu-system-arm -M mps2-an386` executes.

Unicorn only emulates the CPU core: the vendor peripherals and even the ARM
System Control Space are plain unmapped addresses.  Everything the firmware
touches outside of RAM is therefore modelled here as MMIO.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Region:
    name: str
    base: int
    size: int

    @property
    def end(self) -> int:
        """Last valid address in the region."""
        return self.base + self.size - 1

    def contains(self, addr: int) -> bool:
        return self.base <= addr <= self.end


@dataclass(frozen=True)
class Platform:
    """Memory map + peripheral addresses of the emulated board."""

    name: str
    # ZBT_SRAM1, used as "flash": code, rodata, data and bss all live here
    # because pqm4 builds the MPS2 target with DATA_IN_FLASH=1.
    flash: Region
    # ZBT_SRAM2, holds the stack (which grows down from the very top).
    sram: Region
    # Vendor peripherals (CMSDK UART/GPIO/timers).
    apb: Region
    # Private Peripheral Bus: SCS (SysTick, SCB, NVIC) and the debug unit (DWT).
    ppb: Region
    # Scratch memory owned by the framework, not by the firmware.  Arguments
    # built for direct function calls are allocated here so that they can never
    # collide with the firmware's own heap.
    scratch: Region
    # One page of "no man's land" that direct calls use as a return address.
    trampoline: Region

    uart0: int
    gpio0: int

    @property
    def stack_top(self) -> int:
        return self.sram.base + self.sram.size

    @property
    def ram_regions(self) -> tuple:
        """Regions backed by real memory (as opposed to MMIO callbacks)."""
        return (self.flash, self.sram, self.scratch, self.trampoline)


MPS2_AN386 = Platform(
    name="mps2-an386",
    flash=Region("flash", 0x00000000, 0x00400000),
    sram=Region("sram", 0x20000000, 0x00400000),
    apb=Region("apb", 0x40000000, 0x00100000),
    ppb=Region("ppb", 0xE0000000, 0x00100000),
    scratch=Region("scratch", 0x30000000, 0x00100000),
    trampoline=Region("trampoline", 0x1F000000, 0x00001000),
    uart0=0x40004000,
    gpio0=0x40010000,
)

PLATFORMS = {MPS2_AN386.name: MPS2_AN386}


# --- CMSDK APB peripherals -------------------------------------------------

UART_DATA = 0x00
UART_STATE = 0x04
UART_CTRL = 0x08

# --- Private peripheral bus ------------------------------------------------

DWT_CTRL = 0xE0001000
DWT_CYCCNT = 0xE0001004

SYSTICK_CTRL = 0xE000E010
SYSTICK_LOAD = 0xE000E014
SYSTICK_VAL = 0xE000E018
SYSTICK_CALIB = 0xE000E01C

SCB_CPUID = 0xE000ED00
SCB_CPACR = 0xE000ED88

CPUID_CORTEX_M4 = 0x410FC241
SYSTICK_COUNTFLAG = 1 << 16


class Peripherals:
    """MMIO model for the parts of the board Unicorn does not emulate.

    Reads and writes that are not explicitly modelled fall back to a plain
    word store, so firmware that pokes an unrelated register keeps running
    instead of dying on an unmapped access.  Every unmodelled access is
    recorded in :attr:`unknown` so it can be inspected afterwards.
    """

    def __init__(self, platform: Platform, cycles):
        self.platform = platform
        # Callable returning the current instruction count; SysTick and the
        # DWT cycle counter are derived from it.
        self._cycles = cycles
        self.uart_out = bytearray()
        # Called with each byte written to the UART data register.
        self.on_uart_byte = None
        self.regs = {}
        self.unknown = []
        self._systick_reload = 0x00FFFFFF
        self._systick_seen_wraps = 0

    # -- UART ---------------------------------------------------------------

    def _uart_read(self, offset, size):
        if offset == UART_STATE:
            return 0  # TX buffer is never full, RX buffer is never full
        return self.regs.get(self.platform.uart0 + offset, 0)

    def _uart_write(self, offset, size, value):
        if offset == UART_DATA:
            byte = value & 0xFF
            self.uart_out.append(byte)
            if self.on_uart_byte is not None:
                self.on_uart_byte(byte)
        else:
            self.regs[self.platform.uart0 + offset] = value

    # -- SysTick ------------------------------------------------------------

    def _systick_val(self):
        """Model the 24-bit down-counter off the emulated instruction count."""
        period = (self._systick_reload & 0x00FFFFFF) + 1
        return (period - 1) - (self._cycles() % period)

    def systick_wraps(self):
        """How many times SysTick has wrapped since reset."""
        period = (self._systick_reload & 0x00FFFFFF) + 1
        return self._cycles() // period

    # -- dispatch -----------------------------------------------------------

    def read(self, addr, size):
        p = self.platform
        if p.uart0 <= addr < p.uart0 + 0x1000:
            return self._uart_read(addr - p.uart0, size)
        if addr == SYSTICK_VAL:
            return self._systick_val()
        if addr == SYSTICK_LOAD:
            return self._systick_reload
        if addr == SYSTICK_CALIB:
            return 0x40000000  # NOREF: no external reference clock
        if addr == SYSTICK_CTRL:
            ctrl = self.regs.get(SYSTICK_CTRL, 0)
            wraps = self.systick_wraps()
            if wraps > self._systick_seen_wraps:
                # COUNTFLAG reads as 1 if the timer wrapped since the last read
                # and is cleared by the read itself.
                self._systick_seen_wraps = wraps
                return ctrl | SYSTICK_COUNTFLAG
            return ctrl
        if addr == DWT_CYCCNT:
            return self._cycles() & 0xFFFFFFFF
        if addr == SCB_CPUID:
            return CPUID_CORTEX_M4
        if addr in self.regs:
            return self.regs[addr]
        self.unknown.append(("read", addr, size))
        return 0

    def write(self, addr, size, value):
        p = self.platform
        if p.uart0 <= addr < p.uart0 + 0x1000:
            self._uart_write(addr - p.uart0, size, value)
            return
        if addr == SYSTICK_LOAD:
            self._systick_reload = value & 0x00FFFFFF
            return
        if addr == SYSTICK_VAL:
            # Writing any value clears the counter; we cannot rewind the
            # instruction counter, so only the wrap bookkeeping is reset.
            self._systick_seen_wraps = self.systick_wraps()
            return
        if addr in (SYSTICK_CTRL, SCB_CPACR, DWT_CTRL):
            self.regs[addr] = value
            return
        if p.ppb.contains(addr) or p.apb.contains(addr):
            self.regs[addr] = value
            return
        self.unknown.append(("write", addr, size))
