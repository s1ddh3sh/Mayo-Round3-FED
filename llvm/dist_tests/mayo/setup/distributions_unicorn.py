#!/usr/bin/env python3
"""distributions_unicorn.py (mayo) — sampling helper ported VERBATIM from
dist_tests/mayo/setup/driver_dist.py's random_fill(). MAYO's driver has
no _DISTRIBUTION_TABLE at all (confirmed by reading driver_dist.py in
full) -- every buffer/scalar gets a plain uniform byte fill in
[0, field_mod), regardless of any "distribution" key a witness might
carry. sample_for_distribution() here is therefore just random_fill()
under the name unicorn_runner.run_trial() expects, so the same call
site works unmodified across all three algorithms.

Do not hand-edit this without also checking driver_dist.py, in case a
future MAYO harness build starts emitting real distribution hints.
"""


def random_fill(rng, field_mod, length):
    return [rng.randrange(field_mod) for _ in range(length)]


# MAYO's own driver_dist.py/collect_dist.sh hardcodes FIELD_MOD=16
# unconditionally (GF(16), confirmed by reading dist_tests/mayo/
# collect_dist.sh) -- there is no per-distribution derivation to do here
# (see module docstring: MAYO has no distribution table at all), so this
# is just the fixed constant every MAYO sweep/trial uses by default.
MAYO_FIELD_MOD = 16


def sample_for_distribution(dist_name, length, rng, field_mod):
    """MAYO ignores dist_name entirely (no distribution table exists in
    the original driver) -- always a plain uniform [0, field_mod) fill."""
    return random_fill(rng, field_mod, length)
