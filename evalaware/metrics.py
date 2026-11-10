"""Metrics shared by the detector evaluation, ablation and the LLM benchmark."""

from collections import Counter
from typing import Dict, List, Sequence

from .taxonomy import CLASSES


def accuracy(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    return sum(a == b for a, b in zip(y_true, y_pred)) / len(y_true) if y_true else float("nan")


def confusion(y_true, y_pred) -> Dict[str, Dict[str, int]]:
    m = {c: Counter() for c in CLASSES}
    for t, p in zip(y_true, y_pred):
        m[t][p] += 1
    return {t: {p: m[t][p] for p in CLASSES} for t in CLASSES}


def macro_f1(y_true, y_pred) -> float:
    f1s = []
    for c in CLASSES:
        tp = sum(t == c and p == c for t, p in zip(y_true, y_pred))
        fp = sum(t != c and p == c for t, p in zip(y_true, y_pred))
        fn = sum(t == c and p != c for t, p in zip(y_true, y_pred))
        if tp + fp + fn == 0:
            continue  # class absent from data and predictions
        f1s.append(2 * tp / (2 * tp + fp + fn))
    return sum(f1s) / len(f1s) if f1s else float("nan")


def brier(y_true, probs: List[Dict[str, float]]) -> float:
    tot = 0.0
    for t, p in zip(y_true, probs):
        tot += sum((p.get(c, 0.0) - (1.0 if c == t else 0.0)) ** 2 for c in CLASSES)
    return tot / len(y_true) if y_true else float("nan")


def ece(y_true, probs: List[Dict[str, float]], bins: int = 10) -> float:
    """Expected calibration error on the top-1 prediction."""
    rows = []
    for t, p in zip(y_true, probs):
        top = max(CLASSES, key=lambda c: p.get(c, 0.0))
        rows.append((p.get(top, 0.0), top == t))
    if not rows:
        return float("nan")
    err = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [(c, ok) for c, ok in rows if lo <= c < hi or (b == bins - 1 and c == 1.0)]
        if sel:
            err += len(sel) / len(rows) * abs(sum(c for c, _ in sel) / len(sel) - sum(ok for _, ok in sel) / len(sel))
    return err


def wilson(k: int, n: int, z: float = 1.96):
    """Wilson score interval for a proportion."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def summarize(y_true, probs: List[Dict[str, float]]) -> Dict:
    y_pred = [max(CLASSES, key=lambda c: p.get(c, 0.0)) for p in probs]
    return {"n": len(y_true), "accuracy": accuracy(y_true, y_pred), "macro_f1": macro_f1(y_true, y_pred),
            "brier": brier(y_true, probs), "ece": ece(y_true, probs), "confusion": confusion(y_true, y_pred)}
