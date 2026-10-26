#!/usr/bin/env python3
"""
correction_mayo.py (paired sweep over secret s, multiple public backgrounds p)

Correction-fault query:

    y1 = f_correct(s, p),  y2 = f_faulty(s, p)

    exists alpha, s  such that  for all r, p:  y1 = y2 xor alpha

i.e. there is a secret value s for which the divergence Delta_p(s) =
y1 xor y2 is one constant alpha across EVERY background (p, r). Each
--dist-dir holds one single-background secret sweep (correct_sv*.json /
faulty_sv*.json) collected with one public seed p and one ephemeral draw r
(the grid of every seed x every draw; just the seeds without an eph input).
For each output position, every secret value s present in all dirs is
checked: if Delta_p(s) is identical for all p, (s, alpha) is a witness.
alpha = 0 is excluded (y1 == y2: position unaffected by the fault).

Pass at least 2 --dist-dir values; with one, "for all p" is vacuous.

Usage:
    python3 correction_mayo.py \
        --dist-dir test_mayo/mat_add/dist_paired_p0 \
                   test_mayo/mat_add/dist_paired_p1 \
        --out-buf s --active-len 78 --out-word-size 1
"""

import argparse
import glob
import json
import os
import re
import struct

import numpy as np


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
    """
    Returns delta[sv] = numpy int64 array of length min(active_len,
    len(out_buf)) -- the raw Delta(s) values, NOT booleans, unlike
    ineffective_paired_test.py's d[sv].
    """
    delta = {}
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

        delta[sv] = np.bitwise_xor(co, fo)

    return delta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist-dir", required=True, nargs="+",
                    help="one sweep directory per background (public seed p, eph draw r)")
    ap.add_argument("--out-buf", required=True)
    ap.add_argument("--active-len", type=int, required=True)
    ap.add_argument("--out-word-size", type=int, default=1, choices=[1, 4])
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if len(args.dist_dir) < 2:
        print("[!] only one --dist-dir (one public background p): "
              "'for all p' is vacuous, every s trivially qualifies.")

    # sweeps[i][sv] = Delta array for public background i
    sweeps = [load_sweep(d, args.out_buf, args.active_len, args.out_word_size)
              for d in args.dist_dir]
    secret_values = sorted(set.intersection(*(set(w) for w in sweeps)))
    if not secret_values:
        raise RuntimeError("no secret value present in every --dist-dir")

    print(f"[i] {len(secret_values)} secret values x {len(sweeps)} "
          f"backgrounds (public seed x ephemeral draw)")

    # --active-len is normally derived from the SECRET buffer's length,
    # which can exceed the OUTPUT buffer's true length; clamp to the
    # actual (already truncated) delta length.
    out_len = min(len(w[sv]) for w in sweeps for sv in secret_values)
    safe_len = min(args.active_len, out_len)
    if safe_len < args.active_len:
        print(
            f"[!] --active-len={args.active_len} exceeds the output buffer "
            f"'{args.out_buf}''s actual length ({out_len}); clamping "
            f"position loop to {safe_len}."
        )

    for pos in range(safe_len):
        witnesses = []   # (s, alpha): Delta_p(s) == alpha for every p
        for sv in secret_values:
            alpha = int(sweeps[0][sv][pos])
            # alpha != 0: alpha == 0 means y1 == y2 (position unaffected
            # by the fault), which is a false positive, not a correction.
            if alpha != 0 and all(int(w[sv][pos]) == alpha for w in sweeps):
                witnesses.append((sv, alpha))

        if args.verbose or witnesses:
            print("=" * 75)
            print(f"pos {pos}: {len(witnesses)}/{len(secret_values)} secret "
                  f"values with y1 = y2 xor alpha (alpha != 0) for all {len(sweeps)} (p, r)")
            for sv, alpha in witnesses[:10]:
                print(f"    s={sv}, alpha={alpha}")
            if len(witnesses) > 10:
                print(f"    ... and {len(witnesses) - 10} more")
            print("=" * 75)


if __name__ == "__main__":
    main()
