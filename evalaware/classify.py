"""Turn observations into an isolation stack, class probabilities and a 'staged' score."""

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .fingerprint import Fingerprint
from .layers import LAYERS
from .taxonomy import BOUNDARIES, CLASSES, REGISTRY, STAGED, Hit, noisy_or

PRESENT_THRESHOLD = 0.5


@dataclass
class Verdict:
    primary: str
    stack: List[str]
    probs: Dict[str, float]
    boundary_scores: Dict[str, float]
    staged_score: float
    hits: List[Hit] = field(default_factory=list)

    @property
    def detectability(self) -> float:
        """How confidently the environment reveals itself: 1 - P(looks bare-metal)."""
        return 1.0 - self.probs["bare_metal"]

    def to_dict(self):
        return {"primary": self.primary, "stack": self.stack, "probs": self.probs,
                "boundary_scores": self.boundary_scores, "staged_score": self.staged_score,
                "hits": [{"name": h.name, "evidence": h.evidence, "layer": REGISTRY[h.name].layer} for h in self.hits]}


def load_weight_overrides(path: str) -> Dict[str, float]:
    with open(path) as f:
        return json.load(f)


def fire_all(fp: Fingerprint, layers: Optional[List[str]] = None) -> List[Hit]:
    hits = []
    for name, mod in LAYERS.items():
        if layers is not None and name not in layers:
            continue
        if name in fp.observations:
            hits.extend(mod.fire(fp.observations[name]))
    return hits


def classify(fp: Fingerprint, layers: Optional[List[str]] = None,
             weights: Optional[Dict[str, float]] = None, threshold: float = PRESENT_THRESHOLD) -> Verdict:
    """`layers` restricts evidence to a subset (ablation); `weights` overrides tell weights by name;
    `threshold` is the boundary-score cut-off for listing a boundary in `stack` (class probabilities
    and `primary` do not depend on it)."""
    hits = fire_all(fp, layers)
    votes: Dict[str, List[float]] = {b: [] for b in BOUNDARIES + (STAGED,)}
    for h in hits:
        spec = REGISTRY[h.name]
        for boundary, w in spec.votes.items():
            votes[boundary].append((weights or {}).get(h.name, w))
    s = {b: noisy_or(votes[b]) for b in votes}
    sc, su, sv = s["container"], s["userspace_kernel"], s["vm"]
    probs = {
        "container": sc,
        "userspace_kernel": su * (1 - sc),
        "vm": sv * (1 - sc) * (1 - su),
        "bare_metal": (1 - sc) * (1 - su) * (1 - sv),
    }
    stack = [b for b in BOUNDARIES if s[b] >= threshold]
    primary = max(CLASSES, key=lambda c: probs[c])
    return Verdict(primary, stack, {k: round(v, 4) for k, v in probs.items()},
                   {b: round(s[b], 4) for b in BOUNDARIES}, round(s[STAGED], 4), hits)


def format_report(v: Verdict) -> str:
    lines = [f"Primary class : {v.primary}   stack: {' > '.join(v.stack) or '(none)'}",
             "Class probs   : " + "  ".join(f"{k}={p:.2f}" for k, p in v.probs.items()),
             f"Detectability : {v.detectability:.2f}   staged score: {v.staged_score:.2f}", "", "Tells fired:"]
    for h in sorted(v.hits, key=lambda h: REGISTRY[h.name].layer):
        spec = REGISTRY[h.name]
        lines.append(f"  [{spec.layer:<9}] {h.name:<26} {h.evidence}")
    if not v.hits:
        lines.append("  (none)")
    return "\n".join(lines)
