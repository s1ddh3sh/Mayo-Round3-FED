#!/usr/bin/env python3
"""func_config.py -- shared helper for reading the root-level
<algo>.json curated config maps (dilithium.json / kyber.json /
mayo.json), keyed by function name, e.g.:

    {"mat_add": {"secret-buf": "Ox", "fixed-scalars": "m,n"}}

so run_tests_unicorn.sh doesn't require the caller to pass
--secret-buf/--fixed-scalars by hand for every already-curated function.

This is provided as an importable Python helper for any Python caller
that wants it; the shell scripts themselves inline the equivalent
lookup directly in a small heredoc (see collect_dist_unicorn.sh /
run_tests_unicorn.sh's own resolve_func_config()), matching the existing
style already used by run_ineffective_paired.sh's derive_out_buf() /
derive_active_len() -- both approaches read the exact same file/schema.
"""
import json
import os

# This file lives at <repo_root>/dist_tests/common/func_config.py, so the
# repo root is two directories up. This matches how these scripts are
# always invoked in practice (`./dist_tests/<algo>/run_tests_unicorn.sh
# ...` from the repo root -- see e.g. run_tests_unicorn.sh's own
# OUT_DIR="tests_<algo>/${FUNC_NAME}", which is already relative to cwd
# and only works under that same assumption).
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def load_func_config(algo, func_name):
    """Reads <repo_root>/<algo>.json (algo in dilithium/kyber/mayo),
    keyed by function name exactly as it appears there (the full
    mangled symbol name or a short name, depending on the algo's own
    convention -- just match the literal key).

    Returns {"secret_buf": str|None, "fixed_scalars": str} --
    fixed_scalars defaults to "" if the function has an entry but no
    "fixed-scalars" key, or if the function has no entry at all.
    secret_buf is None if the function isn't in the JSON at all (the
    caller decides whether that's fatal).
    """
    path = os.path.join(_REPO_ROOT, f"{algo}.json")
    if not os.path.isfile(path):
        return {"secret_buf": None, "fixed_scalars": ""}

    with open(path) as f:
        config = json.load(f)

    entry = config.get(func_name)
    if entry is None:
        return {"secret_buf": None, "fixed_scalars": ""}

    return {
        "secret_buf": entry.get("secret-buf"),
        "fixed_scalars": entry.get("fixed-scalars", ""),
    }
