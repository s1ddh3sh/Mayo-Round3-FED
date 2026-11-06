#!/usr/bin/env python3
"""Upsert timing rows into the run_tests_all.sh CSVs.

Two sub-commands, both idempotent (re-running updates rows in place rather
than duplicating them):

  perfunc  --csv PATH --scheme NAME
      Reads lines "<function> <status> <seconds>" from stdin and upserts one
      row per function into the per-function timing CSV:
          function,status,seconds
      Keyed by `function`; rows are kept sorted by function name.

  summary  --csv PATH --scheme NAME --n N --sum SUM
      Upserts this scheme's aggregate row into the cross-scheme summary CSV:
          scheme,functions,avg_seconds,sum_seconds,updated
      Keyed by `scheme`. After upserting the scheme row, the pooled "ALL"
      row is recomputed from every non-ALL row as
          functions = sum of functions, sum_seconds = sum of sum_seconds,
          avg_seconds = sum_seconds / functions
      so "ALL" is the average wall time per function across all schemes.

All writes go through a temp file + os.replace so a crash cannot leave a
half-written CSV.
"""
import argparse
import csv
import datetime
import os
import sys
import tempfile


def _atomic_write(path, header, rows):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".timing.", suffix=".csv")
    try:
        with os.fdopen(fd, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_rows(path, header):
    """Return {key_first_field: row_list} preserving insertion order."""
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, newline="") as f:
        r = csv.reader(f)
        try:
            first = next(r)
        except StopIteration:
            return out
        # If the first line is not our header, treat it as data (keyed row).
        if first != header:
            if first:
                out[first[0]] = first
        for row in r:
            if row:
                out[row[0]] = row
    return out


def cmd_perfunc(args):
    header = ["function", "status", "seconds"]
    rows = _read_rows(args.csv, header)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        func, status, seconds = parts[0], parts[1], parts[2]
        rows[func] = [func, status, seconds]
    ordered = [rows[k] for k in sorted(rows)]
    _atomic_write(args.csv, header, ordered)


def cmd_summary(args):
    header = ["scheme", "functions", "avg_seconds", "sum_seconds", "updated"]
    rows = _read_rows(args.csv, header)

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    avg = (args.sum / args.n) if args.n > 0 else 0.0
    rows[args.scheme] = [
        args.scheme,
        str(args.n),
        f"{avg:.3f}",
        f"{args.sum:.3f}",
        now,
    ]

    # Recompute the pooled ALL row from every non-ALL scheme row.
    tot_n, tot_sum = 0, 0.0
    for key, row in rows.items():
        if key == "ALL":
            continue
        try:
            tot_n += int(row[1])
            tot_sum += float(row[3])
        except (ValueError, IndexError):
            continue
    all_avg = (tot_sum / tot_n) if tot_n > 0 else 0.0
    rows["ALL"] = ["ALL", str(tot_n), f"{all_avg:.3f}", f"{tot_sum:.3f}", now]

    # Emit scheme rows sorted, with ALL always last.
    scheme_keys = sorted(k for k in rows if k != "ALL")
    ordered = [rows[k] for k in scheme_keys] + [rows["ALL"]]
    _atomic_write(args.csv, header, ordered)

    print(
        f"[i] cross-scheme ALL: avg {all_avg:.1f}s/function "
        f"over {tot_n} function(s) across {len(scheme_keys)} scheme(s)"
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("perfunc")
    p.add_argument("--csv", required=True)
    p.add_argument("--scheme", required=True)
    p.set_defaults(func=cmd_perfunc)

    s = sub.add_parser("summary")
    s.add_argument("--csv", required=True)
    s.add_argument("--scheme", required=True)
    s.add_argument("--n", type=int, required=True)
    s.add_argument("--sum", type=float, required=True)
    s.set_defaults(func=cmd_summary)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
