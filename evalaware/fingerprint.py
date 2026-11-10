"""Collect raw observations from every layer into one serialisable Fingerprint."""

import os
import platform
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict

from .layers import LAYERS
from .layers import kernel as _kernel


@dataclass
class Fingerprint:
    observations: Dict[str, Dict[str, Any]]
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(observations=d["observations"], meta=d.get("meta", {}))


def collect(root="/", env=None, layers=None, live=True) -> Fingerprint:
    """Observe the host. `root` lets tests point at a fixture tree; live=False skips subprocesses."""
    root = Path(root)
    env = dict(os.environ if env is None else env)
    obs = {}
    for name, mod in LAYERS.items():
        if layers and name not in layers:
            continue
        if mod is _kernel:
            obs[name] = mod.observe(root, env, live=live)
        else:
            obs[name] = mod.observe(root, env)
    meta = {"collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python": platform.python_version(), "machine": platform.machine()}
    return Fingerprint(obs, meta)
