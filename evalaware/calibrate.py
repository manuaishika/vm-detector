"""Empirical checks on the tell weights, using labelled records.

Four questions, each answered without tuning the prior weights on the data being scored:

1. per_tell_stats   - for each tell, how often does it fire when its boundary is truly present (TPR) vs
                      absent (FPR)? Does the prior weight rank tells the way the data does?
2. grouped_cv       - does a model fitted to data (logistic regression for the container boundary)
                      beat the hand-set prior weights when whole configurations are held out?
3. sensitivity      - how much does accuracy move if every weight is randomly perturbed, or the
                      stack threshold changes? (If a result only holds at exactly these numbers it is
                      not a finding.)
4. tell_ablation    - is any single tell critical, or is the evidence redundant?

Boundaries absent from the data cannot be evaluated: with every sample on a VM host there are no
negatives for 'vm', and there are no positives for 'userspace_kernel'. Those cases are flagged, not scored.
"""

import math
import random
from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from .classify import classify, fire_all
from .dataset import fingerprint_of
from .metrics import accuracy, wilson
from .rationale import tier_of
from .taxonomy import BOUNDARIES, CLASSES, REGISTRY, noisy_or

Rec = Dict


def _present(rec: Rec, boundary: str) -> bool:
    return boundary in (rec.get("stack") or ([] if rec["label"] == "bare_metal" else [rec["label"]]))


def fired_matrix(records: Sequence[Rec]) -> List[set]:
    return [{h.name for h in fire_all(fingerprint_of(r))} for r in records]


# ---------------------------------------------------------------- 1. per-tell statistics
def per_tell_stats(records: Sequence[Rec]) -> List[Dict]:
    fired = fired_matrix(records)
    rows = []
    for name, spec in REGISTRY.items():
        for boundary, w in spec.votes.items():
            if boundary not in BOUNDARIES:
                continue
            pos = [i for i, r in enumerate(records) if _present(r, boundary)]
            neg = [i for i in range(len(records)) if i not in set(pos)]
            tp = sum(name in fired[i] for i in pos)
            fp = sum(name in fired[i] for i in neg)
            tpr = tp / len(pos) if pos else float("nan")
            fpr = fp / len(neg) if neg else float("nan")
            # Balanced precision = P(boundary | tell fired) if present/absent were equally likely. Unlike plain
            # precision it does not depend on how many positives the dataset happens to contain. +0.5 smoothing.
            bp = ((tp + .5) / (len(pos) + 1)) / (((tp + .5) / (len(pos) + 1)) + ((fp + .5) / (len(neg) + 1))) \
                if pos and neg else float("nan")
            rows.append({
                "tell": name, "tier": tier_of(name), "boundary": boundary, "prior_weight": w,
                "n_pos": len(pos), "n_neg": len(neg), "tp": tp, "fp": fp, "tpr": tpr, "fpr": fpr,
                "tpr_ci": wilson(tp, len(pos)), "fpr_ci": wilson(fp, len(neg)),
                "youden": tpr - fpr if pos and neg else float("nan"), "balanced_precision": bp,
                "informative": bool(pos and neg),
            })
    return rows


def _ranks(xs):
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    r = [0.0] * len(xs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        for k in range(i, j + 1):
            r[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return r


def spearman(x: Sequence[float], y: Sequence[float]) -> float:
    if len(x) < 3:
        return float("nan")
    rx, ry = _ranks(x), _ranks(y)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else float("nan")


def rank_agreement(rows: List[Dict], boundary: str) -> Dict:
    sel = [r for r in rows if r["boundary"] == boundary and r["informative"] and r["tp"] + r["fp"] > 0]
    return {"boundary": boundary, "n_tells": len(sel),
            "spearman": spearman([r["prior_weight"] for r in sel], [r["balanced_precision"] for r in sel])}


# ---------------------------------------------------------------- 2. fitted model + grouped CV
def _sigmoid(z):
    return 1 / (1 + math.exp(-max(-30, min(30, z))))


def fit_logreg(X: List[List[float]], y: List[int], l2: float = 1.0, iters: int = 400, lr: float = 0.3):
    """L2-regularised logistic regression by full-batch gradient descent (bias unpenalised)."""
    n, d = len(X), len(X[0]) if X else 0
    w, b = [0.0] * d, 0.0
    for _ in range(iters):
        gw, gb = [l2 * wi / max(n, 1) for wi in w], 0.0
        for xi, yi in zip(X, y):
            err = _sigmoid(sum(a * c for a, c in zip(w, xi)) + b) - yi
            for j, xj in enumerate(xi):
                if xj:
                    gw[j] += err * xj / n
            gb += err / n
        w = [wi - lr * g for wi, g in zip(w, gw)]
        b -= lr * gb
    return w, b


def _class_probs(sc, su, sv):
    return {"container": sc, "userspace_kernel": su * (1 - sc), "vm": sv * (1 - sc) * (1 - su),
            "bare_metal": (1 - sc) * (1 - su) * (1 - sv)}


def grouped_cv(records: Sequence[Rec], l2: float = 1.0) -> Dict:
    """Leave-one-configuration-out. Compares the prior detector with a container head fitted on the
    other configurations (vm and userspace_kernel scores stay at their prior values: the data cannot fit them)."""
    recs = list(records)
    fired = fired_matrix(recs)
    names = sorted({n for f in fired for n in f if REGISTRY[n].votes.keys() & {"container"}})
    X = [[1.0 if n in f else 0.0 for n in names] for f in fired]
    y = [1 if _present(r, "container") else 0 for r in recs]
    groups = sorted({r.get("group", r["id"]) for r in recs})
    prior_pred, fit_pred, truth, prior_pc, fit_pc = [], [], [], [], []
    for g in groups:
        te = [i for i, r in enumerate(recs) if r.get("group", r["id"]) == g]
        tr = [i for i in range(len(recs)) if i not in set(te)]
        if len({y[i] for i in tr}) < 2:
            continue
        w, b = fit_logreg([X[i] for i in tr], [y[i] for i in tr], l2=l2)
        for i in te:
            v = classify(fingerprint_of(recs[i]))
            pc = _sigmoid(sum(a * c for a, c in zip(w, X[i])) + b)
            probs = _class_probs(pc, v.boundary_scores["userspace_kernel"], v.boundary_scores["vm"])
            fit_pred.append(max(CLASSES, key=lambda c: probs[c]))
            prior_pred.append(v.primary)
            truth.append(recs[i]["label"])
            prior_pc.append(v.probs["container"]); fit_pc.append(pc)
    ybin = [1 if t == "container" else 0 for t in truth]
    brier = lambda ps: sum((p - t) ** 2 for p, t in zip(ps, ybin)) / len(ybin) if ybin else float("nan")
    return {"n": len(truth), "n_groups": len(groups),
            "prior": {"accuracy": accuracy(truth, prior_pred), "container_brier": brier(prior_pc)},
            "fitted": {"accuracy": accuracy(truth, fit_pred), "container_brier": brier(fit_pc)},
            "features": names, "l2": l2}


def fitted_weights(records: Sequence[Rec], l2: float = 1.0) -> List[Tuple[str, float, float]]:
    """(tell, prior weight, fitted coefficient) for the container head trained on all data."""
    recs = list(records)
    fired = fired_matrix(recs)
    names = sorted({n for f in fired for n in f if "container" in REGISTRY[n].votes})
    X = [[1.0 if n in f else 0.0 for n in names] for f in fired]
    y = [1 if _present(r, "container") else 0 for r in recs]
    w, _ = fit_logreg(X, y, l2=l2)
    return [(n, REGISTRY[n].votes["container"], wi) for n, wi in zip(names, w)]


# ---------------------------------------------------------------- 3. sensitivity
def _primary_acc(records, weights=None, threshold=None):
    kw = {} if threshold is None else {"threshold": threshold}
    return accuracy([r["label"] for r in records],
                    [classify(fingerprint_of(r), weights=weights, **kw).primary for r in records])


def perturbation(records: Sequence[Rec], sigma: float, draws: int = 200, seed: int = 0) -> Dict:
    """Multiply every vote weight by exp(sigma*z), z~N(0,1), clipped to (0.01, 0.99)."""
    rng = random.Random(seed)
    accs = []
    for _ in range(draws):
        w = {n: min(0.99, max(0.01, max(s.votes.values()) * math.exp(sigma * rng.gauss(0, 1))))
             for n, s in REGISTRY.items()}
        # weights override by name: keep per-boundary structure by scaling each tell's top vote only
        accs.append(_primary_acc(records, weights=w))
    accs.sort()
    return {"sigma": sigma, "draws": draws, "mean": sum(accs) / len(accs), "p05": accs[int(0.05 * draws)],
            "min": accs[0], "baseline": _primary_acc(records)}


def threshold_sweep(records: Sequence[Rec], thresholds=(0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8)) -> List[Dict]:
    out = []
    for t in thresholds:
        ok = sum(classify(fingerprint_of(r), threshold=t).stack == list(r.get("stack") or []) for r in records)
        out.append({"threshold": t, "stack_exact": ok / len(records)})
    return out


# ---------------------------------------------------------------- 4. per-tell ablation / redundancy
def tell_ablation(records: Sequence[Rec]) -> Dict:
    base = _primary_acc(records)
    fired = set().union(*fired_matrix(records)) if records else set()
    drops = []
    for n in sorted(fired):
        acc = _primary_acc(records, weights={n: 0.0})
        drops.append((n, base - acc))
    critical = [(n, d) for n, d in drops if d > 1e-9]
    cont = [r for r in records if r["label"] == "container"]
    counts = [sum("container" in REGISTRY[n].votes and REGISTRY[n].votes["container"] >= 0.6 for n in f)
              for f, r in zip(fired_matrix(records), records) if r["label"] == "container"]
    return {"baseline": base, "n_tells": len(fired), "critical": critical,
            "container_strong_tells_min": min(counts) if counts else None,
            "container_strong_tells_max": max(counts) if counts else None}
