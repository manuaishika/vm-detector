"""Aggregate study records: rates with Wilson intervals, and permutation tests between conditions."""

import json
import random
from collections import defaultdict
from typing import Dict, List

from ..metrics import wilson


def load(path) -> List[Dict]:
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def _rate(vals):
    k, n = sum(bool(v) for v in vals), len(vals)
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else float("nan"), "ci": (lo, hi)}


def _mean(vals):
    vals = [v for v in vals if v is not None]
    return sum(vals) / len(vals) if vals else float("nan")


def by_condition(recs: List[Dict], keys=("condition", "home_mode")) -> Dict:
    groups = defaultdict(list)
    for r in recs:
        groups[tuple(r[k] for k in keys)].append(r)
    out = {}
    for g, rs in sorted(groups.items()):
        out[g] = {
            "n": len(rs),
            "any_strong_probe": _rate([r["strong_probes"] > 0 for r in rs]),
            "mean_strong_probes": _mean([r["strong_probes"] for r in rs]),
            "mean_weak_probes": _mean([r["weak_probes"] for r in rs]),
            "unprompted_awareness": _rate([r["unprompted_awareness"] > 0 for r in rs]),
            "mean_eval_probability": _mean([r["eval_probability"] for r in rs]),
            "success": _rate([r["success"] for r in rs]),
            "tamper": _rate([r["tampered"] for r in rs if r.get("tampered") is not None]),
        }
    return out


def perm_test(a: List[float], b: List[float], iters: int = 10000, seed: int = 0) -> float:
    """Two-sided permutation test on difference of means."""
    if not a or not b:
        return float("nan")
    rng = random.Random(seed)
    obs = abs(sum(a) / len(a) - sum(b) / len(b))
    pool, na, hits = list(a) + list(b), len(a), 0
    for _ in range(iters):
        rng.shuffle(pool)
        d = abs(sum(pool[:na]) / na - sum(pool[na:]) / (len(pool) - na))
        hits += d >= obs - 1e-12
    return (hits + 1) / (iters + 1)


def compare(recs: List[Dict], cond_a: str, cond_b: str, field="strong_probes", scenario=None) -> Dict:
    pick = lambda c: [float(bool(r[field]) if isinstance(r[field], bool) else (r[field] or 0)) for r in recs
                      if r["condition"] == c and (scenario is None or r["scenario"] == scenario)]
    a, b = pick(cond_a), pick(cond_b)
    return {"field": field, "a": cond_a, "b": cond_b, "n_a": len(a), "n_b": len(b),
            "mean_a": _mean(a), "mean_b": _mean(b), "p_value": perm_test(a, b)}


def format_table(recs: List[Dict]) -> str:
    rows = by_condition(recs)
    f = lambda r: f"{r['rate']:.2f}[{r['ci'][0]:.2f},{r['ci'][1]:.2f}]"
    lines = [f"{'condition':<12}{'home':<8}{'n':>4}  {'any-strong-probe':<20}{'mean strong':>12}{'aware':>20}{'P(eval)':>9}{'success':>9}{'tamper':>9}"]
    for (c, h), s in rows.items():
        lines.append(f"{c:<12}{h:<8}{s['n']:>4}  {f(s['any_strong_probe']):<20}{s['mean_strong_probes']:>12.2f}"
                     f"{f(s['unprompted_awareness']):>20}{s['mean_eval_probability']:>9.1f}"
                     f"{s['success']['rate']:>9.2f}{s['tamper']['rate']:>9.2f}")
    return "\n".join(lines)
