#!/usr/bin/env python3
"""
report_findings.py — scan tests_mayo/, tests_kyber/, tests_dilithium/ for
fault-leakage test results and collate them into one CSV per scheme.

Two result-file conventions exist side by side and are BOTH scanned,
independently, per fault folder (a folder can have either, both, or
neither -- e.g. a function tested via both the full paired-sweep
pipeline (run_tests.sh / run_tests_unicorn.sh) and the early-stop
pipeline (run_combined.sh / run_combined_unicorn.sh, Dilithium/Kyber
only) gets one row per test per source file it actually has):

  test_result.txt (Dilithium/Kyber only -- written by dist_and_test.py /
  early_stop_sweep_unicorn.py): a test is detected iff the file has its
  "[+]" line (each test is judged independently):
      [+] INEFFECTIVE hit at pos 0: s1=0 (d1=True, ineffective) vs s2=2 (d2=False, effective)
      [+] CORRECTION hit at pos 0: s=2, alpha=1 constant across 4 public backgrounds ...
  The "[RESULT] <test> test: ..." lines are recorded as the CSV detail.

  ineffective_paired_result.txt / correction_paired_result.txt (all three
  schemes -- written by run_ineffective_paired.sh / run_correction_paired.sh,
  wrapping ineffective_<algo>.py / correction_<algo>.py): a "DETECTED" verdict
  isn't printed explicitly -- presence of at least one
      pos N: X/Y pairs disagree
  (ineffective test, and older correction_<algo>.py runs), or
      pos N: X/Y secret values with y1 = y2 xor alpha (alpha != 0) for all P p
  (current correction_<algo>.py), with X > 0 anywhere in the file IS the
  detection; the no-detection case has no "pos N:" line at all, just the
  header (see report.sh, which this script supersedes for the paired-result
  format and extends with Dilithium + the test_result.txt format +
  machine-readable CSV output).

Direct-leak results are not scanned from tests_<scheme>/: they are read
from the CSV that dist_tests/run_direct_leak.sh writes (--direct-leak-csv,
default direct_leak_report.csv), added as a third test "direct_leak" to the
per-scheme / combined CSVs and to every plot style.

A fault folder's name is its path relative to the function's tests_<algo>/
<func_name>/ directory (e.g. "loopOrFuncSkip/<faulty_stem>" for a nested
Dilithium/Kyber fault, or "add_f_line0_opA" for a flat MAYO one), so
nested layouts are preserved instead of collapsed to a basename.

Usage:
    python3 report_findings.py [--outdir DIR] [--schemes mayo,kyber,dilithium]

Writes <outdir>/fault_report_<scheme>.csv for each scheme that has any
tests_<scheme>/ directory, plus a combined fault_report_all.csv, and
prints a short per-scheme detected/total summary to stdout.
"""

import argparse
import csv
import os
import re
import sys

PAIRED_FILENAMES = {
    "ineffective_paired_result.txt": "ineffective",
    "correction_paired_result.txt": "correction",
}
PAIRED_HIT_RE = re.compile(
    r"^pos (\d+): (\d+)/(\d+) (pairs disagree|secret values with y1 = y2 xor alpha)",
    re.MULTILINE,
)

TEST_RESULT_FILENAME = "test_result.txt"
# A "[+] INEFFECTIVE hit ..." / "[+] CORRECTION hit ..." line means that test
# detected the fault; the "[RESULT] <test> test: ..." line is kept as detail.
TEST_HIT_RE = re.compile(r"^\[\+\] (INEFFECTIVE|CORRECTION) hit\b.*$", re.MULTILINE)
TEST_RESULT_RE = re.compile(r"^\[RESULT\] (ineffective|correction) test: (.*)$", re.MULTILINE)

# A run that died on a subprocess timeout (e.g. gdb-multiarch exceeding its
# limit) leaves a traceback ending in this, and no verdict at all. Recorded as
# detected="timeout" for BOTH tests so it is plotted rather than dropped.
TIMEOUT_RE = re.compile(r"subprocess\.TimeoutExpired")

FIELDNAMES = ["scheme", "function", "fault", "source", "test", "detected", "detail"]

# Status colors (fixed, never themed) and the two-test categorical pair, from
# the project's dataviz palette: slot-1 blue / slot-2 orange for the
# ineffective/correction series identity, status-critical red used only for
# the scalar "faults with NO leak detected by either test" callout.
COLOR_INEFFECTIVE = "#2a78d6"   # categorical slot 1 (blue)
COLOR_CORRECTION = "#eb6834"    # categorical slot 2 (orange)
COLOR_DIRECT = "#1baf7a"        # categorical slot 3 (aqua)
COLOR_UNDETECTED = "#d03b3b"    # status critical (used sparingly, labeled)
COLOR_TIMEOUT = "#9a9a94"       # neutral grey: "no verdict", not good/bad
COLOR_GRID = "#d9d8d2"
COLOR_TEXT = "#0b0b0b"
COLOR_TEXT_MUTED = "#52514e"

# Every test the plots know about, in fixed order (= fixed colour slot).
# direct_leak rows come from the direct-leak CSV (dist_tests/run_direct_leak.sh),
# not from the result files scanned under tests_<scheme>/.
TESTS = ("ineffective", "correction", "direct_leak")
TEST_COLORS = {"ineffective": COLOR_INEFFECTIVE, "correction": COLOR_CORRECTION,
               "direct_leak": COLOR_DIRECT}
TEST_LABELS = {"ineffective": "ineffective", "correction": "correction",
               "direct_leak": "direct leak"}


def parse_paired_result(path):
    """Returns [(detected: bool | "timeout", detail: str)] -- at most one row, since a
    paired-result file is one test's ENTIRE verdict, not per-position."""
    try:
        text = open(path, errors="replace").read()
    except OSError as e:
        return [(False, f"(unreadable: {e})")]
    if TIMEOUT_RE.search(text):
        return [("timeout", "subprocess.TimeoutExpired")]
    hits = PAIRED_HIT_RE.findall(text)
    positive = [(pos, x, y, phrase) for pos, x, y, phrase in hits if int(x) > 0]
    if positive:
        pos, x, y, phrase = positive[0]
        extra = f" (+{len(positive) - 1} more position(s))" if len(positive) > 1 else ""
        return [(True, f"pos {pos}: {x}/{y} {phrase}{extra}")]
    return [(False, "no position with disagreeing pairs")]


def parse_test_result(path):
    """Returns [(test, detected, detail), ...] for whichever of
    ineffective/correction have a [RESULT] line in this file (normally
    both, but don't assume it)."""
    try:
        text = open(path, errors="replace").read()
    except OSError as e:
        return [("ineffective", False, f"(unreadable: {e})"), ("correction", False, f"(unreadable: {e})")]
    hits = {m.group(1).lower(): m.group(0).strip() for m in TEST_HIT_RE.finditer(text)}
    verdicts = {t: v.strip() for t, v in TEST_RESULT_RE.findall(text)}
    if TIMEOUT_RE.search(text) and not hits and not verdicts:
        return [(t, "timeout", "subprocess.TimeoutExpired") for t in ("ineffective", "correction")]
    out = []
    for test in ("ineffective", "correction"):
        if test not in hits and test not in verdicts:
            continue
        out.append((test, test in hits, verdicts.get(test) or hits.get(test)))
    return out


def _status(detected):
    return detected if detected == "timeout" else ("yes" if detected else "no")


def fault_name(func_dir, result_path):
    rel = os.path.relpath(os.path.dirname(result_path), func_dir)
    rel = rel.replace(os.sep, "/")
    return "(root)" if rel == "." else rel


def scan_scheme(scheme, tests_root):
    """Yields dicts matching FIELDNAMES for every result file found under
    tests_root (a tests_<scheme>/ directory, symlink-followed)."""
    if not os.path.isdir(tests_root):
        return
    for func_name in sorted(os.listdir(tests_root)):
        func_dir = os.path.join(tests_root, func_name)
        if not os.path.isdir(func_dir):
            continue
        for dirpath, _dirnames, filenames in os.walk(func_dir, followlinks=True):
            for fn in filenames:
                if fn in PAIRED_FILENAMES:
                    path = os.path.join(dirpath, fn)
                    test = PAIRED_FILENAMES[fn]
                    fault = fault_name(func_dir, path)
                    for detected, detail in parse_paired_result(path):
                        yield {
                            "scheme": scheme,
                            "function": func_name,
                            "fault": fault,
                            "source": fn,
                            "test": test,
                            "detected": _status(detected),
                            "detail": detail,
                        }
                elif fn == TEST_RESULT_FILENAME:
                    path = os.path.join(dirpath, fn)
                    fault = fault_name(func_dir, path)
                    for test, detected, detail in parse_test_result(path):
                        yield {
                            "scheme": scheme,
                            "function": func_name,
                            "fault": fault,
                            "source": fn,
                            "test": test,
                            "detected": _status(detected),
                            "detail": detail,
                        }


def load_direct_leak(csv_path, schemes):
    """Rows of the direct-leak CSV (dist_tests/run_direct_leak.sh), already in
    the FIELDNAMES schema, grouped by scheme. Its "detected" values are
    yes / no / skip / error: an error caused by an emulation timeout becomes
    "timeout" (inconclusive, like the other tests); skipped rows (the secret
    is not in the trace) and other errors are not a verdict and are dropped.
    Returns ({scheme: [rows]}, n_dropped)."""
    by_scheme, dropped = {}, 0
    if not csv_path or not os.path.isfile(csv_path):
        return by_scheme, dropped
    with open(csv_path, newline="") as f:
        for r in csv.DictReader(f):
            if r.get("scheme") not in schemes:
                continue
            status = r.get("detected", "")
            if status == "error" and "Timeout" in r.get("detail", ""):
                status = "timeout"
            if status not in ("yes", "no", "timeout"):
                dropped += 1
                continue
            row = {k: r.get(k, "") for k in FIELDNAMES}
            row["test"], row["detected"] = "direct_leak", status
            by_scheme.setdefault(r["scheme"], []).append(row)
    return by_scheme, dropped


def present_tests(counts, funcs):
    """The tests (in TESTS order) with at least one tested fault in funcs."""
    return tuple(t for t in TESTS if any(counts[f][t][2] for f in funcs))


def aggregate_detection_rates(rows):
    """Collapses `rows` (as written to the CSV) to one status per
    (function, fault, test) -- if ANY source file for a given fault+test says
    detected it counts as detected once (so a fault tested via both the
    paired-sweep and early-stop pipelines isn't double-counted); otherwise a
    timeout beats a plain "no" (it is an inconclusive run, not a clean pass).
    Returns {function: {test: [n_detected, n_timeout, n_total]}}."""
    rank = {"no": 0, "timeout": 1, "yes": 2}
    verdict = {}  # (function, fault, test) -> "yes" | "timeout" | "no"
    for r in rows:
        key = (r["function"], r["fault"], r["test"])
        if rank[r["detected"]] >= rank[verdict.get(key, "no")]:
            verdict[key] = r["detected"]

    counts = {}
    for (func, _fault, test), status in verdict.items():
        bucket = counts.setdefault(func, {t: [0, 0, 0] for t in TESTS})
        bucket[test][2] += 1
        if status == "yes":
            bucket[test][0] += 1
        elif status == "timeout":
            bucket[test][1] += 1
    return counts


def plot_scheme(scheme, rows, out_path):
    """Horizontal grouped bar chart: one row per function that has at least
    one tested fault, one bar per test with data (ineffective / correction /
    direct leak).
    Requires matplotlib -- raises a clear RuntimeError if it isn't
    installed, rather than a bare ImportError traceback."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as e:
        raise RuntimeError(
            "matplotlib is required for --plot (pip install matplotlib)"
        ) from e

    counts = aggregate_detection_rates(rows)
    # Drop functions with zero tested faults for BOTH tests -- nothing to
    # plot, and they'd otherwise render as two zero-length bars.
    funcs = [f for f, c in counts.items() if any(c[t][2] for t in TESTS)]
    if not funcs:
        raise RuntimeError(f"no plottable data for scheme {scheme!r}")

    def hit(func, test):
        return counts[func][test][0]

    def n_to(func, test):
        return counts[func][test][1]

    def total(func, test):
        return counts[func][test][2]

    # Bar lengths are ABSOLUTE fault counts (shared x-axis), so 200 detected
    # faults draws 200x longer than 1. A faint track behind each bar spans
    # the number of faults tested, so a short bar next to a long track reads
    # as "few detected out of many".
    # Functions keep their scan order (alphabetical by tests_<scheme>/ dir);
    # deliberately not sorted by count.
    tests = present_tests(counts, funcs)
    max_total = max(total(f, t) for f in funcs for t in tests)
    n = len(funcs)
    fig_h = max(3.0, 0.17 * len(tests) * n + 1.5)
    fig, ax = plt.subplots(figsize=(10, fig_h), dpi=150)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")

    y = range(n)
    # One bar per present test, top to bottom in TESTS order.
    bar_h = 0.76 / len(tests)
    series = tuple(
        ((k - (len(tests) - 1) / 2) * (bar_h + 0.02), t, TEST_COLORS[t],
         f"{TEST_LABELS[t]} test")
        for k, t in enumerate(tests)
    )
    for k, (offset, test, color, label) in enumerate(series):
        pos = [i + offset for i in y]
        ax.barh(pos, [total(f, test) for f in funcs], height=bar_h,
                color=COLOR_GRID, alpha=0.55, zorder=2,
                label="faults tested" if k == 0 else None)
        ax.barh(pos, [hit(f, test) for f in funcs], height=bar_h,
                color=color, label=label, zorder=3)
        # Timeouts stack after the detected segment as hatched grey: they
        # are inconclusive runs (subprocess.TimeoutExpired), and are
        # included in the faults-tested total.
        ax.barh(pos, [n_to(f, test) for f in funcs],
                left=[hit(f, test) for f in funcs], height=bar_h,
                color=COLOR_TIMEOUT, hatch="///", edgecolor="#fcfcfb",
                linewidth=0, zorder=3,
                label="timeout (TimeoutExpired)" if k == 0 else None)

    # Direct labels: "detected/tested" at the end of the track.
    for i, f in enumerate(funcs):
        for offset, test, _color, _label in series:
            if total(f, test) == 0:
                continue
            lab = f"{hit(f, test)}/{total(f, test)}" + (
                f" (+{n_to(f, test)} timeout)" if n_to(f, test) else "")
            ax.text(total(f, test) + 0.01 * max_total, i + offset, lab,
                    va="center", ha="left", fontsize=7.5, color=COLOR_TEXT_MUTED)

    ax.set_yticks(list(y))
    ax.set_yticklabels(funcs, fontsize=8.5, color=COLOR_TEXT)
    ax.invert_yaxis()
    ax.set_xlim(0, max_total * 1.3)
    ax.set_xlabel("number of faults (bar = leak DETECTED, hatched = timed out, faint track = tested)", fontsize=9, color=COLOR_TEXT_MUTED)
    ax.set_title(
        f"{scheme}: fault-leakage detections by function\n"
        f"(counts = distinct faults tested, OR'd across every result source found)",
        fontsize=11, color=COLOR_TEXT, loc="left", pad=12,
    )
    ax.grid(axis="x", color=COLOR_GRID, linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(COLOR_GRID)
    ax.tick_params(left=False, bottom=False)
    ax.legend(
        loc="lower right", frameon=False, fontsize=8.5,
        labelcolor=COLOR_TEXT_MUTED,
    )

    fig.tight_layout()
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    return out_path


def plot_scheme_heatmap(scheme, rows, out_path):
    """Compact alternative to plot_scheme: one row per function (scan
    order), one column per test with data (ineffective / correction /
    direct leak). Each cell is shaded by
    detection rate and annotated "detected/tested"; cells containing
    timed-out faults get a grey hatched overlay and a "+N TO" note."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.patches import Rectangle
        from matplotlib.colors import LinearSegmentedColormap
    except ImportError as e:
        raise RuntimeError(
            "matplotlib is required for --plot (pip install matplotlib)"
        ) from e

    counts = aggregate_detection_rates(rows)
    funcs = [f for f, c in counts.items() if any(c[t][2] for t in TESTS)]
    if not funcs:
        raise RuntimeError(f"no plottable data for scheme {scheme!r}")

    tests = present_tests(counts, funcs)
    # Each column is shaded in its own test's hue (one hue, light -> dark).
    cmaps = {t: LinearSegmentedColormap.from_list(f"detect_{t}", ["#f1f0ec", TEST_COLORS[t]])
             for t in tests}

    n = len(funcs)
    row_h = 0.24
    fig_h = max(2.5, row_h * n + 1.6)
    fig, ax = plt.subplots(figsize=(7.5, fig_h), dpi=150)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")

    for i, f in enumerate(funcs):
        for j, test in enumerate(tests):
            n_hit, n_to, n_total = counts[f][test]
            if n_total == 0:
                continue
            rate = n_hit / n_total
            ax.add_patch(Rectangle((j, i), 1, 1, facecolor=cmaps[test](rate),
                                   edgecolor="#fcfcfb", linewidth=1.5, zorder=2))
            if n_to:
                ax.add_patch(Rectangle((j, i), 1, 1, facecolor="none",
                                       edgecolor=COLOR_TIMEOUT, hatch="////",
                                       linewidth=0, zorder=3, alpha=0.8))
            lab = f"{n_hit}/{n_total}" + (f" +{n_to} TO" if n_to else "")
            ax.text(j + 0.5, i + 0.5, lab, ha="center", va="center", fontsize=7,
                    color="white" if rate > 0.55 else COLOR_TEXT, zorder=4)

    ax.set_xlim(0, len(tests))
    ax.set_ylim(n, 0)
    ax.set_xticks([j + 0.5 for j in range(len(tests))])
    ax.set_xticklabels([f"{TEST_LABELS[t]} test" for t in tests], fontsize=9, color=COLOR_TEXT)
    ax.xaxis.tick_top()
    ax.set_yticks([i + 0.5 for i in range(n)])
    ax.set_yticklabels(funcs, fontsize=7.5, color=COLOR_TEXT)
    ax.tick_params(left=False, top=False)
    for spine in ax.spines.values():
        spine.set_visible(False)
    fig.suptitle(
        f"{scheme}: faults with the leak detected, by function\n"
        f"cell = detected/tested, shade = detection rate\n"
        f"hatched = includes timed-out faults (TO)",
        x=0.01, ha="left", fontsize=9, color=COLOR_TEXT,
    )

    fig.tight_layout(rect=(0, 0, 1, 1 - 0.3 / fig_h))
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    return out_path


def plot_scheme_summary(scheme, rows, out_path):
    """Overall summary + per-function table. Top: one stacked bar per test
    (detected / not detected / timeout) over ALL faults of the scheme.
    Bottom: a text table of detected/tested per function (scan order)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as e:
        raise RuntimeError(
            "matplotlib is required for --plot (pip install matplotlib)"
        ) from e

    counts = aggregate_detection_rates(rows)
    funcs = [f for f, c in counts.items() if any(c[t][2] for t in TESTS)]
    if not funcs:
        raise RuntimeError(f"no plottable data for scheme {scheme!r}")
    tests = present_tests(counts, funcs)
    colors = TEST_COLORS

    totals = {t: [sum(counts[f][t][k] for f in funcs) for k in range(3)] for t in tests}

    n = len(funcs)
    row_h = 0.2
    fig_h = 1.4 + 0.25 * len(tests) + row_h * (n + 1)
    fig = plt.figure(figsize=(8, fig_h), dpi=150)
    fig.patch.set_facecolor("#fcfcfb")
    gs = fig.add_gridspec(2, 1, height_ratios=[0.5 * len(tests) + 0.5, row_h * (n + 1)],
                          hspace=0.12)

    # -- summary bars (absolute counts, one shared axis) -------------------
    ax = fig.add_subplot(gs[0])
    ax.set_facecolor("#fcfcfb")
    max_total = max(t[2] for t in totals.values())
    for i, test in enumerate(tests):
        hit, to, tot = totals[test]
        miss = tot - hit - to
        ax.barh(i, hit, height=0.5, color=colors[test], zorder=3)
        ax.barh(i, to, left=hit, height=0.5, color=COLOR_TIMEOUT, hatch="///",
                edgecolor="#fcfcfb", linewidth=0, zorder=3)
        ax.barh(i, miss, left=hit + to, height=0.5, color=COLOR_GRID,
                alpha=0.7, zorder=2)
        pct = 100.0 * hit / tot if tot else 0.0
        lab = f"{hit}/{tot} detected ({pct:.0f}%)" + (f", {to} timeout" if to else "")
        ax.text(tot + 0.01 * max_total, i, lab, va="center", ha="left",
                fontsize=8, color=COLOR_TEXT_MUTED)
    ax.set_yticks(range(len(tests)))
    ax.set_yticklabels([f"{TEST_LABELS[t]} test" for t in tests], fontsize=9, color=COLOR_TEXT)
    ax.invert_yaxis()
    ax.set_xlim(0, max_total * 1.45)
    ax.set_xlabel("number of faults (colour = detected, hatched = timed out, "
                  "faint = not detected)", fontsize=8, color=COLOR_TEXT_MUTED)
    ax.grid(axis="x", color=COLOR_GRID, linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(COLOR_GRID)
    ax.tick_params(left=False, bottom=False)
    ax.set_title(f"{scheme}: fault-leakage detection summary", fontsize=10,
                 color=COLOR_TEXT, loc="left", pad=8)

    # -- per-function table -------------------------------------------------
    tx = fig.add_subplot(gs[1])
    tx.axis("off")

    def cell(f, t):
        n_hit, n_to, n_tot = counts[f][t]
        if n_tot == 0:
            return "-"
        return f"{n_hit}/{n_tot}" + (f" (+{n_to} TO)" if n_to else "")

    cells = [[f] + [cell(f, t) for t in tests] for f in funcs]
    tbl = tx.table(cellText=cells,
                   colLabels=["function"] + [TEST_LABELS[t] for t in tests],
                   colWidths=[0.4 + 0.2 * (3 - len(tests))] + [0.2] * len(tests),
                   cellLoc="left", loc="upper left", bbox=[0, 0, 1, 1])
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(7)
    for (r, c), tc in tbl.get_celld().items():
        tc.set_edgecolor(COLOR_GRID)
        tc.set_linewidth(0.4)
        tc.set_facecolor("#fcfcfb" if r % 2 else "#f4f3ef")
        tc.get_text().set_color(COLOR_TEXT)
        if r == 0:
            tc.set_facecolor("#e9e8e2")
            tc.get_text().set_fontweight("bold")
        elif c > 0:
            n_hit, _to, n_tot = counts[funcs[r - 1]][tests[c - 1]]
            if n_tot and n_hit == n_tot:
                tc.get_text().set_color(colors[tests[c - 1]])
                tc.get_text().set_fontweight("bold")
            elif n_tot and n_hit == 0:
                tc.get_text().set_color(COLOR_TEXT_MUTED)

    # Table spans the full width; only the summary bars get a left margin
    # for their "<test> test" labels.
    fig.subplots_adjust(left=0.03, right=0.97, top=1 - 0.4 / fig_h, bottom=0.01)
    pos = ax.get_position()
    ax.set_position([0.2, pos.y0, 0.77, pos.height])
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    return out_path


def plot_combined(rows_by_scheme, out_path):
    """One figure covering every scheme: per scheme, one 100%-stacked bar
    per test with data (ineffective / correction / direct leak), split into
    detected / timed out / not detected. Percent-normalized because the schemes test very different
    numbers of faults; the labels carry the absolute counts."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as e:
        raise RuntimeError(
            "matplotlib is required for --plot (pip install matplotlib)"
        ) from e

    tests = TESTS
    colors = TEST_COLORS
    data = []  # (scheme, test, hit, to, tot)
    for scheme, rows in rows_by_scheme.items():
        counts = aggregate_detection_rates(rows)
        for t in tests:
            tot = sum(c[t][2] for c in counts.values())
            if tot:
                data.append((scheme, t, sum(c[t][0] for c in counts.values()),
                             sum(c[t][1] for c in counts.values()), tot))
    if not data:
        raise RuntimeError("no plottable data for any scheme")

    schemes = list(dict.fromkeys(d[0] for d in data))
    tests = tuple(t for t in tests if any(d[1] == t for d in data))
    fig, ax = plt.subplots(figsize=(9, 1.0 + 0.45 * len(tests) * len(schemes)), dpi=150)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")

    bar_h = 0.7 / len(tests)
    yticks, ylabels, labelled = [], [], set()
    for si, scheme in enumerate(schemes):
        for ti, t in enumerate(tests):
            y = si + (ti - (len(tests) - 1) / 2) * (bar_h + 0.04)
            match = [d for d in data if d[0] == scheme and d[1] == t]
            if not match:
                continue
            _s, _t, hit, to, tot = match[0]
            pct = lambda v: 100.0 * v / tot
            ax.barh(y, pct(hit), height=bar_h, color=colors[t], zorder=3,
                    label=None if t in labelled else f"{TEST_LABELS[t]} test: detected")
            labelled.add(t)
            ax.barh(y, pct(to), left=pct(hit), height=bar_h, color=COLOR_TIMEOUT,
                    hatch="///", edgecolor="#fcfcfb", linewidth=0, zorder=3,
                    label="timeout (TimeoutExpired)" if (si, ti) == (0, 0) else None)
            ax.barh(y, 100 - pct(hit) - pct(to), left=pct(hit) + pct(to),
                    height=bar_h, color=COLOR_GRID, alpha=0.7, zorder=2,
                    label="not detected" if (si, ti) == (0, 0) else None)
            lab = f"{hit}/{tot} ({pct(hit):.0f}%)" + (f", {to} timeout" if to else "")
            ax.text(101.5, y, lab, va="center", ha="left", fontsize=7.5,
                    color=COLOR_TEXT_MUTED)
        yticks.append(si)
        ylabels.append(scheme)

    ax.set_yticks(yticks)
    ax.set_yticklabels(ylabels, fontsize=10, color=COLOR_TEXT)
    ax.invert_yaxis()
    ax.set_xlim(0, 135)
    ax.set_xticks(range(0, 101, 20))
    ax.set_xlabel("% of faults tested (labels: detected/tested faults)",
                  fontsize=8.5, color=COLOR_TEXT_MUTED)
    ax.set_title("Fault-leakage detection summary, all schemes", fontsize=11,
                 color=COLOR_TEXT, loc="left", pad=10)
    ax.grid(axis="x", color=COLOR_GRID, linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(COLOR_GRID)
    ax.tick_params(left=False, bottom=False)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=len(tests) + 2,
              frameon=False, fontsize=8, labelcolor=COLOR_TEXT_MUTED)

    fig.tight_layout()
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    return out_path


def find_tests_root(root, scheme, override=None):
    """The scheme's results directory: --tests-dir if given, else the first
    that exists of tests_<scheme>/ (test_qemu layout), test_<scheme>/ and
    llvm/test_<scheme>/ (this repo, where run_combined_unicorn.sh writes
    them). Falls back to tests_<scheme>/ so the 'not found' message names it."""
    if override:
        return override if os.path.isabs(override) else os.path.join(root, override)
    candidates = [f"tests_{scheme}", f"test_{scheme}",
                  os.path.join("llvm", f"test_{scheme}")]
    for c in candidates:
        path = os.path.join(root, c)
        if os.path.isdir(path):
            return path
    return os.path.join(root, candidates[0])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="repo root (default: cwd)")
    ap.add_argument(
        "--tests-dir", default=None,
        help="results directory to scan, relative to --root unless absolute "
             "(default: first existing of tests_<scheme>, test_<scheme>, "
             "llvm/test_<scheme>). Only sensible with a single --schemes entry.",
    )
    ap.add_argument("--outdir", default=".", help="where to write CSVs (default: cwd)")
    ap.add_argument("--plotdir", default="plots",
                    help="where to write PNG plots (default: plots/)")
    ap.add_argument(
        "--schemes", default="mayo,kyber,dilithium",
        help="comma-separated subset of mayo,kyber,dilithium (default: all three)",
    )
    ap.add_argument(
        "--plot", action="store_true",
        help="also write fault_report_<scheme>.png: a horizontal bar chart "
             "of ineffective/correction/direct-leak detections by function "
             "(requires matplotlib).",
    )
    ap.add_argument(
        "--style", choices=("bar", "heatmap", "summary"), default="bar",
        help="plot style used with --plot: 'bar' (default, "
             "fault_report_<scheme>.png) or the more compact 'heatmap' "
             "(fault_report_<scheme>_heatmap.png) or 'summary' (overall "
             "stacked bars + per-function table, "
             "fault_report_<scheme>_summary.png).",
    )
    ap.add_argument(
        "--direct-leak-csv", default="direct_leak_report.csv",
        help="CSV written by dist_tests/run_direct_leak.sh, relative to --root "
             "unless absolute (default: %(default)s). Its rows are added as the "
             "'direct_leak' test to the CSVs and plots; ignored if missing.",
    )
    ap.add_argument(
        "--combined", action="store_true",
        help="with --plot, also write fault_report_combined.png: one "
             "summary figure covering every scheme. Independent of --style.",
    )
    args = ap.parse_args()

    schemes = [s.strip() for s in args.schemes.split(",") if s.strip()]
    os.makedirs(args.outdir, exist_ok=True)
    if args.plot:
        os.makedirs(args.plotdir, exist_ok=True)

    dl_path = args.direct_leak_csv
    if dl_path and not os.path.isabs(dl_path):
        dl_path = os.path.join(args.root, dl_path)
    direct_leak, dl_dropped = load_direct_leak(dl_path, schemes)
    if direct_leak:
        print(f"[all] {dl_path}: {sum(map(len, direct_leak.values()))} direct-leak "
              f"result(s) added ({dl_dropped} skipped/error row(s) left out)")
    elif dl_path:
        print(f"[all] {dl_path}: no direct-leak results (file missing or empty)")

    all_rows = []
    rows_by_scheme = {}
    for scheme in schemes:
        tests_root = find_tests_root(args.root, scheme, args.tests_dir)
        rows = list(scan_scheme(scheme, tests_root)) + direct_leak.get(scheme, [])
        all_rows.extend(rows)
        if rows:
            rows_by_scheme[scheme] = rows

        out_path = os.path.join(args.outdir, f"fault_report_{scheme}.csv")
        with open(out_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=FIELDNAMES)
            w.writeheader()
            for row in sorted(rows, key=lambda r: (r["function"], r["fault"], r["test"], r["source"])):
                w.writerow(row)

        n_detected = sum(1 for r in rows if r["detected"] == "yes")
        n_timeout = sum(1 for r in rows if r["detected"] == "timeout")
        n_faults = len({(r["function"], r["fault"]) for r in rows})
        n_funcs = len({r["function"] for r in rows})
        if rows:
            print(f"[{scheme}] {out_path}: {len(rows)} test result(s) across "
                  f"{n_faults} fault(s) in {n_funcs} function(s) -- "
                  f"{n_detected} DETECTED, {n_timeout} TIMEOUT")
        else:
            print(f"[{scheme}] {out_path}: no result files found under {tests_root}")

        if args.plot and rows:
            if args.style in ("heatmap", "summary"):
                png_path = os.path.join(args.plotdir, f"fault_report_{scheme}_{args.style}.png")
                plot_fn = plot_scheme_heatmap if args.style == "heatmap" else plot_scheme_summary
            else:
                png_path = os.path.join(args.plotdir, f"fault_report_{scheme}.png")
                plot_fn = plot_scheme
            try:
                plot_fn(scheme, rows, png_path)
                print(f"[{scheme}] {png_path}: detection-by-function {args.style}")
            except RuntimeError as e:
                print(f"[{scheme}] [!] plot skipped: {e}")

    if args.plot and args.combined and rows_by_scheme:
        png_path = os.path.join(args.plotdir, "fault_report_combined.png")
        try:
            plot_combined(rows_by_scheme, png_path)
            print(f"[all] {png_path}: combined summary chart")
        except RuntimeError as e:
            print(f"[all] [!] combined plot skipped: {e}")

    combined_path = os.path.join(args.outdir, "fault_report_all.csv")
    with open(combined_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        for row in sorted(all_rows, key=lambda r: (r["scheme"], r["function"], r["fault"], r["test"], r["source"])):
            w.writerow(row)
    print(f"[all] {combined_path}: {len(all_rows)} total test result(s)")


if __name__ == "__main__":
    sys.exit(main())
