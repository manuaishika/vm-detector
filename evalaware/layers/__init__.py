"""Detection layers. Each module exposes observe(root, env) -> dict and fire(obs) -> [Hit].

observe() only gathers raw, JSON-serialisable facts; fire() is pure. That split lets the
classifier, benchmark and ablation run on stored observations without touching a live host.
"""

from . import hardware, kernel, container, network, timing, realism

LAYERS = {
    "hardware": hardware,
    "kernel": kernel,
    "container": container,
    "network": network,
    "timing": timing,
    "realism": realism,
}
