#!/usr/bin/env python3
"""
ineffective_paired_test.py (single-background mode)

Reports d1, d2 for every (s1, s2) pair against the ONE shared background p
collected by collect_paired_sweep.py, per your algorithm:

    y1 = f_correct(s1, p),  y2 = f_faulty(s1, p),  delta1 = y1 xor y2
    y3 = f_correct(s2, p),  y4 = f_faulty(s2, p),  delta2 = y3 xor y4
    d1 = (delta1 == 0),     d2 = (delta2 == 0)

Updated query (see the document): the sample is a grid of K public seeds
p_k x J ephemeral draws r_j (drawn independently; J = 1 without an
ephemeral input), one --dist-dir per (p_k, r_j), passed seed-major:

    forall p  exists s1,s2 : (forall r d(s1,r,p)) and (forall r not d(s2,r,p))
    -> for EVERY seed a pair exists (it may differ per seed) with s1
       ineffective on all J draws and s2 effective on all J draws

The text below describes the original single-background form.

This is DESCRIPTIVE, not a hypothesis test -- with a single p, there is
only one (d1, d2) observation per pair, which is not enough data for a
p-value. It reports, per output position, how many of the 256 ordered
(s1, s2) pairs show d1 != d2 (a "disagreement": whether the fault is
silently absorbed differs between s1 and s2, for this one background).

Usage:
    python3 ineffective_paired_test.py \
        --dist-dir test_mayo/m_vec_add/dist_paired \
        --out-buf acc --active-len 40 --out-word-size 1
"""

import argparse
import glob
import json
import re
import struct
import os
import sys

import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from dist_tests.common.ineffective import analyse  # noqa: E402


def decode_words(values, word_size):
    if word_size == 1:
        return list(values)
    if word_size == 4:
        n = len(values) // 4
        return list(struct.unpack(f"<{n}i", bytes(values)))
    raise ValueError(f"unsupported word size {word_size}")


def get_buffer(record, buf_name):
    pre = record.get("pre_transform", {})
    if buf_name in pre and pre[buf_name] is not None:
        return pre[buf_name]
    captured = record.get("captured", {})
    if buf_name in captured and captured[buf_name] is not None:
        return captured[buf_name]
    inputs = record.get("inputs", {})
    if buf_name in inputs:
        return inputs[buf_name]
    outputs = record.get("outputs", {})
    if buf_name in outputs:
        return outputs[buf_name]
    raise KeyError(f"'{buf_name}' not found (inputs={sorted(inputs.keys())}, "
                   f"outputs={sorted(outputs.keys())})")


_FNAME_RE = re.compile(r"correct_sv(\d+)\.json")

def load_sweep(dist_dir, out_buf, active_len, out_word_size):
    """Returns d[sv] = numpy bool array of length active_len."""
    d = {}
    for cpath in sorted(glob.glob(f"{dist_dir}/correct_sv*.json")):
        basename = os.path.basename(cpath)
        m = _FNAME_RE.search(basename)
        if not m:
            continue
        sv = int(m.group(1))
        fpath = f"{dist_dir}/faulty_sv{sv:02d}.json"

        with open(cpath) as f:
            c = json.load(f)
        with open(fpath) as f:
            fdata = json.load(f)

        co = np.asarray(decode_words(get_buffer(c, out_buf), out_word_size), dtype=np.int64)
        fo = np.asarray(decode_words(get_buffer(fdata, out_buf), out_word_size), dtype=np.int64)
        co = co[:active_len]
        fo = fo[:active_len]
        delta = np.bitwise_xor(co, fo)

        d[sv] = ((delta & 15) == 0)

    return d
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist-dir", required=True, nargs="+",
                    help="one sweep directory per (public seed p_k, ephemeral "
                         "draw r_j), seed-major: the J draws of seed 0, then "
                         "the J draws of seed 1, ...")
    ap.add_argument("--out-buf", required=True)
    ap.add_argument("--active-len", type=int, required=True)
    ap.add_argument("--out-word-size", type=int, default=1, choices=[1, 4])
    ap.add_argument("--eph-draws", type=int, default=1,
                    help="J, the number of ephemeral draws per public seed "
                         "(default 1: no ephemeral input)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    sweeps = [load_sweep(d, args.out_buf, args.active_len, args.out_word_size)
              for d in args.dist_dir]
    secret_values = sorted(set.intersection(*(set(w) for w in sweeps)))
    if len(secret_values) < 2:
        raise RuntimeError(f"only {len(secret_values)} secret values common to all --dist-dir")

    J = args.eph_draws
    if J < 1 or len(sweeps) % J:
        raise RuntimeError(f"{len(sweeps)} --dist-dir values is not a "
                           f"multiple of --eph-draws={J}")
    K, S = len(sweeps) // J, len(secret_values)
    print(f"[i] loaded {S} secret values x {K} public seeds x {J} "
          f"ephemeral draw(s) -- per-seed pair, constant over all draws")

    # Safety clamp (see original note): bound the position loop by the real
    # output length, not the secret buffer's calibrated length.
    out_len = min(len(w[sv]) for w in sweeps for sv in secret_values)
    safe_len = min(args.active_len, out_len)
    if safe_len < args.active_len:
        print(
            f"[!] --active-len={args.active_len} exceeds the output buffer "
            f"'{args.out_buf}''s actual length ({out_len}); clamping "
            f"position loop to {safe_len}."
        )

    eq = np.stack([np.stack([w[sv][:safe_len] for sv in secret_values])
                   for w in sweeps])                    # (K*J, S, P)
    eq = eq.reshape(K, J, S, safe_len)                  # seed-major
    n_pairs, leak = analyse(eq)
    total = S * (S - 1) // 2

    for pos in range(safe_len):
        if not (args.verbose or leak[pos]):
            continue
        print("=" * 75)
        # "pos N: X/Y pairs disagree" is parsed by generic_tests_plot.py.
        print(f"pos {pos}: {int(n_pairs[pos])}/{total} pairs disagree "
              f"(d1 != d2; unordered pairs, minimum over seeds)")
        if leak[pos]:
            for k in range(K):
                ine = [sv for i, sv in enumerate(secret_values) if eq[k, :, i, pos].all()]
                eff = [sv for i, sv in enumerate(secret_values) if (~eq[k, :, i, pos]).all()]
                print(f"    seed#{k}: s1={ine[0]} (ineffective) vs s2={eff[0]} "
                      f"(effective), on all {J} ephemeral draw(s)")
        print("=" * 75)


if __name__ == "__main__":
    main()
