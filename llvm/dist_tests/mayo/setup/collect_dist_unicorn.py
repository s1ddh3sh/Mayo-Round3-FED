#!/usr/bin/env python3
"""collect_dist_unicorn.py (mayo) — drop-in replacement for
collect_dist.py that runs every trial IN-PROCESS via the Unicorn
Cortex-M4 emulator (dist_tests/common/unicorn_runner.py) instead of
spawning a fresh qemu-system-arm + gdb-multiarch subprocess pair per
trial. MAYO's driver has no distribution table (plain uniform-byte fill
everywhere, plain single-byte override) -- see
dist_tests/mayo/setup/distributions_unicorn.py.

Output filenames/schema (correct_sv###.json / faulty_sv###.json)
identical to collect_dist.py's, so ineffective_mayo.py /
correction_mayo.py work unchanged against --dist-dir pointed here.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from dist_tests.common.unicorn_runner import run_trial, TrialError
from dist_tests.mayo.setup.distributions_unicorn import (
    sample_for_distribution,
    MAYO_FIELD_MOD,
)


class RunFailed(Exception):
    """Raised when a single correct/faulty run doesn't produce output."""


def run_one(elf_path, witness_path, active_lengths_path, func, field_mod,
            seed, variant, out_path, machine, fixed_scalars,
            secret_buf, secret_pos, secret_val, eph_secret=None, eph_index=0):
    with open(witness_path) as f:
        layout = json.load(f)["layout"]
    with open(active_lengths_path) as f:
        active_lengths = json.load(f)

    eph_set = set(s for s in (eph_secret or "").split(",") if s)
    for name in eph_set:
        if name not in layout:
            raise RunFailed(f"eph_secret {name!r} not in witness layout")

    fixed_set = set(s for s in (fixed_scalars or "").split(",") if s)

    try:
        result = run_trial(
            elf_path, layout, func, "collect", field_mod, seed, variant,
            fixed_set, sample_for_distribution, active_lengths,
            secret_buf, secret_pos, secret_val,
            eph_secret=eph_set,
            # r_j depends on the draw index only, not on the public seed,
            # so every public seed is run with every ephemeral draw.
            eph_seed=f"eph:{eph_index}",
        )
    except (TrialError, Exception) as e:
        raise RunFailed(
            f"{variant} run for {secret_buf}[{secret_pos}]={secret_val} "
            f"(seed={seed}) raised: {type(e).__name__}: {e}"
        ) from e

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(result, f)


def run_sweep(args):
    os.makedirs(args.outdir, exist_ok=True)
    print(f"[i] sweeping {args.secret_buf}[{args.secret_pos}] over "
          f"{args.field_mod} values, background seed p={args.seed} "
          f"[unicorn backend]")
    print(f"[i] total in-process trials: {args.field_mod} * 2 = {args.field_mod * 2}")

    failures = []
    for sval in range(args.field_mod):
        c_path = os.path.join(args.outdir, f"correct_sv{sval:02d}.json")
        f_path = os.path.join(args.outdir, f"faulty_sv{sval:02d}.json")
        if sval % 25 == 0:
            print(f"  s={sval}: correct + faulty", flush=True)
        for variant, elf_path, out_path in (
            ("correct", args.correct_elf, c_path),
            ("faulty", args.faulty_elf, f_path),
        ):
            try:
                run_one(elf_path, args.witness, args.active_lengths, args.func,
                        args.field_mod, args.seed, variant, out_path, args.machine,
                        args.fixed_scalars, args.secret_buf, args.secret_pos, sval,
                        args.eph_secret, args.eph_index)
            except RunFailed as e:
                print(f"[!] FAILED: {variant} sval={sval}\n{e}", flush=True)
                failures.append((variant, sval, str(e)))

    if failures:
        print(f"\n[!] {len(failures)}/{args.field_mod * 2} runs failed.")
        raise SystemExit(1)

    print(f"[i] done. {args.field_mod} secret values x 2 variants "
          f"= {args.field_mod * 2} runs in {args.outdir}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--witness", required=True)
    ap.add_argument("--active-lengths", required=True)
    ap.add_argument("--correct-elf", required=True)
    ap.add_argument("--faulty-elf", required=True)
    ap.add_argument("--func", required=True)
    ap.add_argument(
        "--field-mod", type=int, default=MAYO_FIELD_MOD,
        help="number of values to sweep --secret-pos through. Default: "
             "%(default)s (GF(16) -- MAYO has no distribution table, so "
             "this is a fixed constant, not auto-derived).",
    )
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--machine", default="mps2-an386",
                     help="ignored -- accepted only for CLI compatibility.")
    ap.add_argument("--fixed-scalars", default="")
    ap.add_argument("--eph-secret", default="",
                    help="comma-separated ephemeral-secret buffers: draw --eph-index, "
                         "independent of --seed, shared by the correct and faulty "
                         "run and by every swept secret value.")
    ap.add_argument("--eph-index", type=int, default=0,
                    help="ephemeral draw r_j to use (default: %(default)s)")
    ap.add_argument("--secret-buf", required=True)
    ap.add_argument("--secret-pos", type=int, required=True)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    run_sweep(args)


if __name__ == "__main__":
    main()
