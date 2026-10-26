#!/usr/bin/env python3
"""unicorn_runner.py — in-process trial runner that replaces the
gdb-batch-mode driver_dist.py + real qemu-system-arm subprocess pair
with a single Unicorn (Cortex-M4) emulation, for the SAME correct.elf /
faulty.elf paired-comparison workflow.

Produces the exact same trial JSON schema as driver_dist.py's
run_collect()/run_probe(): {"inputs": {...}, "outputs": {...}}, with
"inputs" holding every written input (scalar or pointer buffer, keyed
by the witness layout name, or "<name>_pre" for an also_input buffer)
and "outputs" holding every role="output" buffer's post-call bytes.

How argument resolution differs from the gdb driver
-----------------------------------------------------
driver_dist.py breaks at the FUT's (post-prologue-resolved) entry and
reads gdb's live DWARF frame/block to find each pointer argument's
runtime address directly. This runner instead:

  1. Runs the guest from reset to main()'s TRUE first instruction
     (Machine.run_until("main") stops exactly there -- no prologue-skip
     ambiguity, since Unicorn's emu_start(begin, until) stops BEFORE
     executing the instruction at `until`).
  2. Writes every scalar input (backed by a patchable global anchor)
     into memory -- this happens after main() is reached (so it
     doesn't get clobbered by Reset_Handler's .data init) but before
     main() has executed any instruction that would consume it, since
     we haven't resumed execution yet.
  3. Installs a ONE-SHOT code hook at the FUT's RAW entry symbol
     address (before its prologue runs). At that exact PC, AAPCS
     guarantees argument words are still in r0-r3 (first four) and on
     the incoming stack (word i>=4 at sp+4*(i-4)), in declaration
     order -- no prologue instruction has executed yet to spill them
     anywhere else. dwarf_params.pointer_param_order() gives us, for
     every formal parameter in declaration order, whether it's
     pointer-typed; matching that against the witness's ordered
     pointer-buffer names gives each pointer buffer's AAPCS slot
     directly.
  4. The hook reads r0-r3/stack for each pointer buffer's address,
     writes its content (sampled per its "distribution"), then
     unhooks itself and lets execution continue uninterrupted to
     main()'s return address (captured from $lr at step 1, before
     anything could overwrite it).
  5. After the single emu_start() call returns, every role="output"
     entry is read back from its now-known address.
"""

import os
import struct
import time

from .dwarf_params import pointer_param_order
from .elfimage import ElfImage
from .machine import Machine


# Wall-clock cap for the single emu_start() of one trial. A faulty ELF (e.g.
# a skipped loop-counter update) can spin forever; Unicorn's own timeout
# stops silently, so run_trial() detects it and raises TrialTimeout.
# Override with UNICORN_TRIAL_TIMEOUT_S (seconds, 0 disables).
TRIAL_TIMEOUT_S = float(os.environ.get("UNICORN_TRIAL_TIMEOUT_S", "300"))


class TrialTimeout(RuntimeError):
    """The trial did not return from main() within TRIAL_TIMEOUT_S."""


class TrialError(RuntimeError):
    """Raised when a trial cannot be completed (mirrors a failed gdb run)."""


def _int_to_bytes_le(val, width):
    val &= (1 << (8 * width)) - 1
    return [(val >> (8 * i)) & 0xFF for i in range(width)]


def _read_aapcs_word(m, slot):
    """Read AAPCS argument word `slot` (0-based across ALL params) at
    the exact PC of a not-yet-executed function entry: r0-r3 for slots
    0-3, or the incoming stack for slot >= 4."""
    if slot < 4:
        return m.reg(f"r{slot}")
    sp = m.reg("sp")
    return m.read_u32(sp + 4 * (slot - 4))


def _random_fill(rng, field_mod, length):
    """Port of driver_dist.py's local random_fill() helper: a plain
    uniform byte fill in [0, field_mod), used ONLY by probe mode (never
    the algorithm's sample_fn/distribution table -- see calibrate.py's
    module docstring for why probing is deliberately distribution-blind)."""
    return [rng.randrange(field_mod) for _ in range(length)]


def run_trial(
    elf_path,
    layout,
    func,
    mode,
    field_mod,
    rng_seed,
    variant,
    fixed_scalars,
    sample_fn,
    active_lengths=None,
    override_buf="",
    override_pos=-1,
    override_val=-1,
    also_override_hook=None,
    probe_buf=None,
    probe_len=0,
    probe_seed=0,
    co_seed=0,
    eph_secret=None,
    eph_seed=None,
):
    """Run one correct/faulty trial in-process via Unicorn.

    collect mode returns {"inputs": {...}, "outputs": {...}} matching
    driver_dist.py's run_collect() trial JSON schema exactly.

    probe mode returns a flat {"<name>": [bytes]} outputs dict, matching
    driver_dist.py's run_probe() exactly (no "inputs" wrapper) -- this is
    what calibrate.py's calibrate_buffer() compares with `result !=
    reference`. probe mode always uses a plain uniform byte fill in
    [0, field_mod) for every buffer (see _random_fill above), never
    sample_fn/the algorithm's distribution table.

    layout: the parsed qemu_witness.json["layout"] dict (name -> spec).
    sample_fn(dist_name, length, rng, field_mod) -> list[int 0-255]:
        algorithm-specific distribution sampler (ported verbatim from
        that algorithm's driver_dist.py). Unused in probe mode.
    also_override_hook(name, spec, vals, override_pos, override_val) ->
        list[int] | None: optional algorithm-specific override-encoding
        hook (e.g. Dilithium's whole-coefficient override, Kyber's
        word-size-2 override) called AFTER the plain single-byte
        override would apply, for the CALLER to fully own how an
        override is encoded onto `vals` in place; if it returns a
        value, that value REPLACES the plain single-byte override
        instead of layering on top of it. Pass None for a plain
        single-byte override (the common case, and what covers MAYO
        and the default paths of Kyber/Dilithium's own override
        helpers when called with byte semantics). Unused in probe mode.
    probe_buf/probe_len/probe_seed/co_seed: probe-mode-only. probe_buf is
        the name of the buffer being probed; probe_len is the prefix
        length to randomize for it; probe_seed seeds the RNG used for
        probe_buf's own values; co_seed seeds a SEPARATE RNG used for
        every OTHER pointer/scalar buffer, held fixed across the binary
        search (mirrors driver_dist.py's run_probe()).
    """
    import random

    # eph_secret: set of pointer-buffer names that are EPHEMERAL secrets
    # (collect mode only). They are not public inputs, so they must not
    # follow the shared public-background stream; they are drawn from a
    # dedicated RNG seeded by eph_seed (the caller passes one value per public seed, so
    # r_k comes from the same N seeds as p_k; same for the correct and faulty
    # run => f and f~ get the same r). The
    # main rng still draws (and discards) their bytes so every OTHER
    # buffer's sampling is unchanged.
    eph_secret = set(eph_secret or ())
    eph_rng = random.Random(eph_seed) if eph_secret else None

    if mode not in ("collect", "probe"):
        raise ValueError(f"unknown mode {mode!r}")

    active_lengths = active_lengths or {}
    fixed_scalars = fixed_scalars or set()

    m = Machine.from_elf(elf_path)

    # -- 1. boot to main()'s TRUE first instruction -------------------
    m.run_until("main")
    # emu_start's `begin` must carry the Thumb bit (Cortex-M has no ARM
    # mode); `reg("pc")` itself may or may not report it depending on
    # Unicorn's internal state, so set it explicitly rather than assume.
    main_entry_pc = m.reg("pc") | 1
    return_addr = m.reg("lr") & ~1

    if mode == "probe":
        rng = random.Random(probe_seed)
        co_rng = random.Random(co_seed)
    else:
        rng = random.Random(rng_seed)
        co_rng = None

    written_inputs = {}
    scalar_addr = {}

    # -- 2. scalar inputs: write now, before resuming ------------------
    for name, spec in layout.items():
        if spec.get("type") != "scalar":
            continue
        addr = m.addr_of(spec["anchor"])
        scalar_addr[name] = addr
        if spec.get("role") != "input":
            continue

        width = spec.get("length", 1)
        if name in fixed_scalars:
            init = spec.get("init_value", 0) & ((1 << (8 * width)) - 1)
            vals = _int_to_bytes_le(init, width)
        elif mode == "probe":
            active_rng = rng if name == probe_buf else co_rng
            vals = [active_rng.randrange(field_mod) for _ in range(width)]
        else:
            vals = sample_fn(spec.get("distribution"), width, rng, field_mod)
            if name == override_buf and 0 <= override_pos < width:
                if also_override_hook is not None:
                    replaced = also_override_hook(
                        name, spec, vals, override_pos, override_val
                    )
                    if replaced is not None:
                        vals = replaced
                    else:
                        vals[override_pos] = override_val & 0xFF
                else:
                    vals[override_pos] = override_val & 0xFF

        m.write(addr, bytes(v & 0xFF for v in vals))
        written_inputs[name] = vals

    # -- 3. resolve pointer-argument AAPCS slots via DWARF -------------
    ptr_names = [n for n, s in layout.items() if s.get("type") != "scalar"]

    slot_of = {}
    if ptr_names:
        try:
            param_is_ptr = pointer_param_order(elf_path, func)
        except RuntimeError as exc:
            raise TrialError(
                f"could not resolve pointer parameter order for {func!r}: {exc}"
            ) from exc

        ptr_slots = [i for i, is_ptr in enumerate(param_is_ptr) if is_ptr]
        if len(ptr_slots) != len(ptr_names):
            raise TrialError(
                f"layout has {len(ptr_names)} pointer buffers {ptr_names}, but "
                f"DWARF says {func} has {len(ptr_slots)} pointer-typed formal "
                f"parameters (out of {len(param_is_ptr)} total: "
                f"{param_is_ptr}) — order/count mismatch"
            )
        slot_of = dict(zip(ptr_names, ptr_slots))

    ptr_addr = {}
    hook_handle = [None]

    def fut_entry_hook(machine, address, size):
        for name in ptr_names:
            ptr_addr[name] = _read_aapcs_word(machine, slot_of[name])

        if hook_handle[0] is not None:
            machine.unhook(hook_handle[0])

        # -- 4. write pointer-buffer inputs, now that addresses are known
        for name in ptr_names:
            spec = layout[name]
            also_in = spec.get("also_input")
            is_input = spec.get("role") == "input" or also_in
            if not is_input:
                continue

            addr = ptr_addr[name]
            if spec.get("type") == "scalar_ptr":
                width = spec.get("length", 4)
                init = spec.get("init_value", 0) & ((1 << (8 * width)) - 1)
                vals = _int_to_bytes_le(init, width)
                if mode != "probe" and name == override_buf and 0 <= override_pos < len(vals):
                    if also_override_hook is not None:
                        replaced = also_override_hook(
                            name, spec, vals, override_pos, override_val
                        )
                        vals = replaced if replaced is not None else vals
                    else:
                        vals[override_pos] = override_val & 0xFF
                machine.write(addr, bytes(v & 0xFF for v in vals))
                written_inputs[name] = vals
                continue

            if mode == "probe":
                if name == probe_buf:
                    vals = _random_fill(rng, field_mod, probe_len)
                else:
                    vals = _random_fill(co_rng, field_mod, spec["length"])
            else:
                fill_len = active_lengths.get(name, spec["length"])
                vals = sample_fn(spec.get("distribution"), fill_len, rng, field_mod)
                if name in eph_secret:
                    vals = sample_fn(spec.get("distribution"), fill_len,
                                     eph_rng, field_mod)

                if name == override_buf and 0 <= override_pos < len(vals):
                    if also_override_hook is not None:
                        replaced = also_override_hook(
                            name, spec, vals, override_pos, override_val
                        )
                        if replaced is not None:
                            vals = replaced
                        else:
                            vals[override_pos] = override_val & 0xFF
                    else:
                        vals[override_pos] = override_val & 0xFF

            machine.write(addr, bytes(v & 0xFF for v in vals))
            key = f"{name}_pre" if also_in else name
            written_inputs[key] = vals

    if ptr_names:
        fut_addr = m.addr_of(func)
        hook_handle[0] = m.hook_code(
            fut_entry_hook, begin=fut_addr, end=fut_addr, precise=False
        )

    # -- 5. run main() to completion in one shot -----------------------
    t0 = time.monotonic()
    m._emu_start(main_entry_pc, return_addr,
                 timeout=int(TRIAL_TIMEOUT_S * 1_000_000))
    if (TRIAL_TIMEOUT_S > 0 and m.reg("pc") & ~1 != return_addr
            and time.monotonic() - t0 >= TRIAL_TIMEOUT_S * 0.99):
        raise TrialTimeout(
            f"main() did not return within {TRIAL_TIMEOUT_S:g}s "
            f"(pc=0x{m.reg('pc'):x})")

    # -- 6. read outputs -------------------------------------------------
    addr_of = {**scalar_addr, **ptr_addr}
    outputs = {}
    for name, spec in layout.items():
        if spec.get("role") == "output":
            addr = addr_of.get(name)
            if addr is None:
                raise TrialError(
                    f"output {name!r} has no resolved address (pointer "
                    f"resolution hook never fired -- did the FUT get "
                    f"called at all?)"
                )
            outputs[name] = list(m.read(addr, spec["length"]))

    if mode == "probe":
        return outputs
    return {"inputs": written_inputs, "outputs": outputs}
