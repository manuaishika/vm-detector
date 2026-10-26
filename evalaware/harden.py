"""Remediation advice: which tells fired, and how to remove them."""

from .classify import Verdict
from .taxonomy import REGISTRY


def remediation_plan(v: Verdict):
    """Ordered by the strongest vote each tell contributes (biggest leak first)."""
    plan = []
    for h in v.hits:
        spec = REGISTRY[h.name]
        plan.append({"tell": h.name, "layer": spec.layer, "evidence": h.evidence,
                     "max_weight": max(spec.votes.values()), "fix": spec.remediation or "(no known fix)"})
    return sorted(plan, key=lambda p: -p["max_weight"])


def format_plan(v: Verdict) -> str:
    plan = remediation_plan(v)
    if not plan:
        return "No tells fired - nothing to remediate."
    return "\n".join(f"{p['max_weight']:.2f}  {p['tell']:<26} {p['fix']}" for p in plan)
