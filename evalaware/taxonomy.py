"""Shared vocabulary: isolation boundaries, tell registry, layer plumbing."""

from dataclasses import dataclass, field
from typing import Dict, List

# Isolation boundaries a process can sit behind, outermost first.
BOUNDARIES = ("vm", "userspace_kernel", "container")
# Primary class labels used by the dataset and benchmark.
CLASSES = ("bare_metal", "vm", "userspace_kernel", "container")
# Orthogonal score: how staged / synthetic the environment looks.
STAGED = "staged"


@dataclass(frozen=True)
class TellSpec:
    name: str
    layer: str
    description: str
    votes: Dict[str, float]  # boundary (or STAGED) -> weight in (0, 1)
    remediation: str = ""


@dataclass
class Hit:
    name: str
    evidence: str


REGISTRY: Dict[str, TellSpec] = {}


def register(name, layer, description, votes, remediation="") -> str:
    REGISTRY[name] = TellSpec(name, layer, description, dict(votes), remediation)
    return name


def noisy_or(weights: List[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - w
    return 1.0 - p
