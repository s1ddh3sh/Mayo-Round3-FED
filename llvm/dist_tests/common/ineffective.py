"""Ineffective-fault decision logic shared by the MAYO / Kyber / Dilithium
tests (offline: ineffective_mayo.py; incremental: early_stop_sweep_unicorn.py).

The sample is a grid: K public seeds p_k and, if the function has an
ephemeral input, J ephemeral draws r_j, drawn independently of each other
(every p_k is run with every r_j). The correct and faulty run share the
whole input. Inputs are the observations

    eq[k][j][s][pos] = (Delta(s, r_j, p_k)[pos] == 0)

over the K public seeds, the J ephemeral draws, the swept secret values s
and the output positions. The query (see the document) is

    forall p  exists s1,s2 :  (forall r Delta(s1,r,p)=0) and (forall r Delta(s2,r,p)!=0)

On the grid: for EVERY public seed k there is a pair, which may differ
per seed, such that s1 is ineffective on ALL J draws and s2 effective on
ALL J draws. A secret value whose outcome changes with r qualifies as
neither. Without an ephemeral input, J = 1 and the inner "forall r" is
trivially true.

A positive is a witness on the sampled (p, r) only: the universal parts
("forall p", "forall r") are checked over the K and J sampled values, and
only the swept secret values are searched for s1, s2.
"""

import numpy as np


class IneffectiveTracker:
    """Incremental version: feed one swept secret value at a time."""

    def __init__(self, n_pos, n_seeds):
        shape = (n_seeds, n_pos)
        self.has_inef = np.zeros(shape, dtype=bool)
        self.has_eff = np.zeros(shape, dtype=bool)
        self.val_inef = np.zeros(shape, dtype=np.int64)
        self.val_eff = np.zeros(shape, dtype=np.int64)

    def update(self, sv, eq):
        """eq: bool array (n_seeds, n_eph, n) for secret value sv, n <= n_pos."""
        eq = np.asarray(eq, dtype=bool)
        n = eq.shape[2]
        inef, eff = eq.all(axis=1), (~eq).all(axis=1)    # (n_seeds, n)
        sl = (slice(None), slice(0, n))
        new = inef & ~self.has_inef[sl]
        self.val_inef[sl][new] = sv
        self.has_inef[sl] |= inef
        new = eff & ~self.has_eff[sl]
        self.val_eff[sl][new] = sv
        self.has_eff[sl] |= eff

    def hit(self):
        """None, or (pos, witnesses): witnesses = [(s_ineffective, s_effective)]
        one entry per public seed."""
        ok = (self.has_inef & self.has_eff).all(axis=0)
        pos = np.flatnonzero(ok)
        if pos.size == 0:
            return None
        pos = int(pos[0])
        return pos, [(int(self.val_inef[k, pos]), int(self.val_eff[k, pos]))
                     for k in range(self.val_inef.shape[0])]


def analyse(eq):
    """Offline version. eq: bool array (K seeds, J eph draws, S secret values,
    P positions). Returns (n_pairs[P], leak[P]); n_pairs>0 iff leak.
    n_pairs is the minimum over seeds of (#ineffective x #effective) values."""
    eq = np.asarray(eq, dtype=bool)
    n_t = eq.all(axis=1).sum(axis=1)       # (K, P): ineffective on every r
    n_f = (~eq).all(axis=1).sum(axis=1)    # (K, P): effective on every r
    pairs = (n_t * n_f).min(axis=0)
    return pairs, pairs > 0
