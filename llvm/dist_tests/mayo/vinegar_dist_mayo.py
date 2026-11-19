#!/usr/bin/env python3
"""vinegar_dist_mayo.py — secret-dependence *distribution* test on the MAYO
signing vinegar, run in-process via Unicorn (dist_tests/common/machine.py)
against a pair of gated whole-program MAYO ELFs (a correct build and a faulty
build). Adapted from vinegar_dist_snova.py for MAYO's one-shot SHAKE API and
its sign ABI.

In honest MAYO signing (Alg. 8, mayo_sign_signature) the vinegar block V is

    V = SHAKE256( digest || R || csk_seed || ... )       (len 430 for MAYO_1)

so it is keyed by the 24-byte compact private seed `csk`. Any fault that stops
the private seed from entering this SHAKE leaves V attacker-recomputable from
public data, and V stops depending on the secret.

Both an honest V and a secret-free V are UNIFORM over GF(16), so a frequency /
chi-square test on the value histogram cannot tell them apart. What changes is
the *conditional* distribution V | csk:

    correct : as csk varies, V varies   -> each nibble position carries
              ~log2(16)=4 bits of entropy w.r.t. the secret sweep
    faulty  : as csk varies, V is frozen -> ~0 bits of entropy

So this test sweeps N random private seeds (everything else held fixed via a
snapshot taken at the sign entry, so randombytes/salt are reproduced
identically each trial), captures the vinegar block per seed in both builds,
and compares the per-position secret-sweep entropy:

    live-in-correct   : H_correct[p] high (secret reaches this position)
    collapsed (leaked): H_correct[p] high AND H_faulty[p] near 0

    leak_fraction = #collapsed / #live-in-correct
      == 1  -> FULL collapse  (vinegar wholly secret-independent)
      0<..<1-> PARTIAL collapse
      == 0  -> no collapse

How the vinegar is captured
---------------------------
MAYO uses the one-shot shake256(out, outlen, in, inlen). The vinegar expand is
identified robustly as the shake256 call whose output length is VINEGAR_LEN
(430 for MAYO_1); the other shake256 calls in sign produce the 32-byte digest,
the 24-byte salt and the 39-byte t-encoding, so 430 is unique. The private
seed is patched at csk[0:24] at the sign-entry snapshot before each run.

Usage
-----
    python3 dist_tests/mayo/vinegar_dist_mayo.py \\
      --correct-elf build/tests_mayo/pqmayo_MAYO_1_ref_mayo_sign_signature/full_mayo_gated/gated_pqmayo_MAYO_1_ref_mayo_sign_signature.elf \\
      --faulty-elf  build/tests_mayo/.../full_mayo_gated/gated_..._<fault>.elf \\
      --n-seeds 64
"""

import argparse
import collections
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from dist_tests.common.machine import Machine, EmulationError  # noqa: E402

DEFAULT_ENTRY = "pqmayo_MAYO_1_ref_mayo_sign_signature"
SHAKE = "shake256"
VINEGAR_LEN = 440    # MAYO_1 round3: k*v_bytes+r_bytes = 10*40+40
PRIV_OFF = 0         # csk IS the private seed (no public prefix)
PRIV_LEN = 24        # MAYO_1 CSK_BYTES
RUN_TIMEOUT_US = 60_000_000

# Entropy thresholds, as fractions of the max observable per-position entropy
# Hmax = min(log2(16), log2(N)). A position is "live" above LIVE_FRAC*Hmax and
# "frozen" below FROZEN_FRAC*Hmax; the wide gap makes the verdict robust to
# finite-sample entropy bias.
LIVE_FRAC = 0.50
FROZEN_FRAC = 0.15


class VinegarSession:
    """Boots one gated MAYO ELF to the sign entry, snapshots there, and then
    captures the per-call vinegar block for an arbitrary private seed by
    hooking shake256 and reading the vinegar call's output buffer.

    MAYO's sign signature is
        mayo_sign_signature(p, sig, siglen, m, mlen, csk)
    so the 24-byte private seed `csk` is the 6th argument -- passed on the
    stack (AAPCS: args 5,6 at [sp+0], [sp+4] at the function's first
    instruction, before the prologue)."""

    def __init__(self, elf_path, entry=DEFAULT_ENTRY, vinegar_len=VINEGAR_LEN):
        self.entry = entry
        self.vinegar_len = vinegar_len
        m = Machine.from_elf(elf_path)
        self.m = m
        self.elf_path = elf_path
        m.run_until("main")
        main_pc = m.reg("pc") | 1
        self.main_ret = m.reg("lr") & ~1

        addrs = {}
        for name in (entry, f"{entry}__faulted"):
            try:
                addrs[name] = m.addr_of(name)
            except KeyError:
                continue
        if entry not in addrs:
            raise EmulationError(f"{elf_path}: no symbol named {entry!r}")
        self.shake_addr = m.addr_of(SHAKE)

        hit = {}

        def sign_hook(machine, address, size):
            if "csk" not in hit:
                sp = machine.reg("sp")
                # arg5 (mlen) at [sp], arg6 (csk) at [sp+4], before prologue.
                hit["csk"] = int.from_bytes(machine.read(sp + 4, 4), "little")
                hit["pc"] = address
                hit["ret"] = machine.reg("lr") & ~1
                machine.uc.emu_stop()

        handles = [m.hook_code(sign_hook, begin=a, end=a, precise=False)
                   for a in addrs.values()]
        try:
            m._emu_start(main_pc, self.main_ret, timeout=RUN_TIMEOUT_US)
        finally:
            for h in handles:
                m.unhook(h)
        if "csk" not in hit:
            raise EmulationError(f"{elf_path}: {entry} never reached from main")

        self.csk = hit["csk"]
        self.sign_pc = hit["pc"]
        self.sign_ret = hit["ret"]
        self.snap = m.snapshot()

    def vinegar(self, seed_bytes):
        """Return the vinegar block for a given PRIV_LEN-byte private seed.

        The vinegar instance is identified robustly as the shake256 call whose
        output length is self.vinegar_len (430 for MAYO_1), unique among sign's
        shake256 calls (digest 32, salt 24, t-enc 39). Earlier/other shake256
        calls are ignored.
        """
        m = self.m
        m.restore(self.snap)
        m.write(self.csk + PRIV_OFF, bytes(seed_bytes))
        cap = {}

        def sh(machine, address, size):
            # shake256(out=r0, outlen=r1, in=r2, inlen=r3)
            if machine.reg("r1") == self.vinegar_len and "dest" not in cap:
                cap["dest"] = machine.reg("r0")
                cap["len"] = machine.reg("r1")
                cap["ret"] = machine.reg("lr") & ~1
                cap["entry"] = address
                machine.uc.emu_stop()

        hs = m.hook_code(sh, begin=self.shake_addr, end=self.shake_addr, precise=False)
        try:
            m._emu_start(self.sign_pc | 1, self.sign_ret, timeout=RUN_TIMEOUT_US)
            if "dest" not in cap:
                raise EmulationError(
                    f"{self.elf_path}: vinegar shake256 (outlen={self.vinegar_len}) "
                    f"not reached")
            # Run the shake256 body to completion, then read its output buffer.
            m._emu_start(cap["entry"] | 1, cap["ret"], timeout=RUN_TIMEOUT_US)
            return bytes(m.read(cap["dest"], cap["len"]))
        finally:
            m.unhook(hs)


# --------------------------------------------------------------------------
# distribution statistics
# --------------------------------------------------------------------------

def _nibbles(data):
    out = []
    for b in data:
        out.append(b & 0xF)
        out.append((b >> 4) & 0xF)
    return out


def _entropy_bits(values):
    if not values:
        return 0.0
    n = len(values)
    h = 0.0
    for cnt in collections.Counter(values).values():
        p = cnt / n
        h -= p * math.log2(p)
    return h


def _position_entropies(blocks):
    nib = [_nibbles(b) for b in blocks]
    npos = len(nib[0])
    return [_entropy_bits([row[p] for row in nib]) for p in range(npos)]


def _hist_str(blocks):
    c = collections.Counter()
    for b in blocks:
        c.update(_nibbles(b))
    total = sum(c.values()) or 1
    return " ".join(f"{x:x}:{100 * c[x] / total:.0f}%" for x in range(16))


def _collision_rate(blocks):
    n = len(blocks)
    if n < 2:
        return 0.0
    pairs = n * (n - 1) // 2
    same = sum(c * (c - 1) // 2 for c in collections.Counter(blocks).values())
    return same / pairs


def collect(label, elf_path, seeds, entry=DEFAULT_ENTRY, vinegar_len=VINEGAR_LEN):
    sess = VinegarSession(elf_path, entry=entry, vinegar_len=vinegar_len)
    vs = [sess.vinegar(s) for s in seeds]
    ent = _position_entropies(vs)
    res = {
        "label": label.strip(), "elf": elf_path,
        "n_seeds": len(seeds), "block_len": len(vs[0]),
        "distinct": len(set(vs)),
        "collision_rate": _collision_rate(vs),
        "mean_pos_entropy": sum(ent) / len(ent),
        "pos_entropy": ent,
        "nibble_hist": _hist_str(vs),
        "blocks_hex": [v.hex() for v in vs],
    }
    print(f"[i] {label}: {len(seeds)} seeds -> {res['distinct']} distinct block(s), "
          f"collision rate {res['collision_rate']:.3f}, "
          f"mean per-position entropy {res['mean_pos_entropy']:.2f} bits")
    print(f"[i] {label}: nibble histogram (value distribution): {res['nibble_hist']}")
    return res


def compare(res_c, res_f, n_seeds):
    hmax = min(4.0, math.log2(n_seeds)) if n_seeds > 1 else 0.0
    live_t = LIVE_FRAC * hmax
    frozen_t = FROZEN_FRAC * hmax

    hc, hf = res_c["pos_entropy"], res_f["pos_entropy"]
    live = [p for p in range(len(hc)) if hc[p] >= live_t]
    collapsed = [p for p in live if hf[p] <= frozen_t]
    leak_fraction = (len(collapsed) / len(live)) if live else 0.0
    return {
        "hmax_bits": hmax, "live_threshold": live_t, "frozen_threshold": frozen_t,
        "n_positions": len(hc), "n_live_in_correct": len(live),
        "n_collapsed": len(collapsed), "leak_fraction": leak_fraction,
        "collapsed_positions": collapsed,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--correct-elf", required=True)
    ap.add_argument("--faulty-elf", required=True)
    ap.add_argument("--func", default=DEFAULT_ENTRY,
                    help="fixed observation point: the signing entry symbol whose "
                         "vinegar is captured (default %(default)s). The faulty ELF's "
                         "injected fault may live anywhere in the call tree; this only "
                         "names where the vinegar is read, and is the SAME for every "
                         "gated ELF pair.")
    ap.add_argument("--vinegar-len", type=int, default=VINEGAR_LEN,
                    help="byte length of the vinegar shake256 output used to "
                         "identify it (default %(default)s for MAYO_1).")
    ap.add_argument("--n-seeds", type=int, default=64,
                    help="number of random private seeds swept (default 64).")
    ap.add_argument("--seed", type=int, default=1, help="RNG seed for the swept seeds.")
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    for lbl, p in (("correct", args.correct_elf), ("faulty", args.faulty_elf)):
        if not os.path.isfile(p):
            print(f"[!] {lbl} ELF not found: {p}", file=sys.stderr)
            sys.exit(1)
    if args.n_seeds < 2:
        print("[!] --n-seeds must be >= 2 for a distribution comparison", file=sys.stderr)
        sys.exit(1)

    rng = random.Random(args.seed)
    seeds = [bytes(rng.randrange(256) for _ in range(PRIV_LEN)) for _ in range(args.n_seeds)]

    print("=" * 74)
    print("MAYO vinegar secret-dependence DISTRIBUTION test (correct vs faulty)")
    print("=" * 74)

    try:
        res_c = collect("correct", args.correct_elf, seeds, entry=args.func,
                        vinegar_len=args.vinegar_len)
        res_f = collect("faulty ", args.faulty_elf, seeds, entry=args.func,
                        vinegar_len=args.vinegar_len)
    except EmulationError as e:
        print(f"[!] emulation failed: {e}", file=sys.stderr)
        sys.exit(2)

    cmp = compare(res_c, res_f, args.n_seeds)

    print()
    print("=" * 74)
    print("Verdict")
    print("=" * 74)
    print(f"[i] max observable per-position entropy Hmax = {cmp['hmax_bits']:.2f} bits "
          f"(live > {cmp['live_threshold']:.2f}, frozen < {cmp['frozen_threshold']:.2f})")
    print(f"[i] correct: mean per-position entropy {res_c['mean_pos_entropy']:.2f} bits "
          f"({cmp['n_live_in_correct']}/{cmp['n_positions']} positions secret-dependent)")
    print(f"[i] faulty : mean per-position entropy {res_f['mean_pos_entropy']:.2f} bits")
    print(f"[i] leak: {cmp['n_collapsed']}/{cmp['n_live_in_correct']} secret-dependent "
          f"positions FROZEN in the faulty build (leak fraction {cmp['leak_fraction']:.2f})")

    lf = cmp["leak_fraction"]
    if lf >= 0.999:
        verdict = "full"
        print("[!] FULL COLLAPSE: every secret-dependent position of the vinegar is "
              "frozen in the faulty build -- the private seed no longer enters the "
              "vinegar PRG, so the vinegar is attacker-recomputable from public data.")
        exit_code = 1
    elif lf > 0.0:
        verdict = "partial"
        print(f"[!] PARTIAL COLLAPSE: {cmp['n_collapsed']} of {cmp['n_live_in_correct']} "
              "secret-dependent vinegar positions are frozen in the faulty build. "
              f"Collapsed nibble positions: {cmp['collapsed_positions']}")
        exit_code = 1
    else:
        verdict = "none"
        print("[i] NO COLLAPSE: the faulty build's vinegar depends on the secret seed "
              "as strongly as the correct build's.")
        exit_code = 0

    if args.report:
        with open(args.report, "w") as f:
            json.dump({"correct": res_c, "faulty": res_f,
                       "comparison": cmp, "verdict": verdict,
                       "collapse_detected": exit_code == 1}, f, indent=2)
        print(f"[i] report written to {args.report}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
