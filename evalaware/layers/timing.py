"""Layer 5 - timing side channels: syscall latency, tail jitter, timer overshoot.

Weights here are priors, not measurements (calibrated=False); the ablation in
`python -m evalaware ablate` is how they get checked against a labelled dataset.
"""

import os
import statistics
import time
from ..taxonomy import Hit, register

register("tm.slow_syscall", "timing", "Median getppid() latency > 1µs (user-space kernel / ptrace)",
         {"userspace_kernel": 0.5}, "Use a KVM-backed runtime where syscalls do not leave the guest.",
         calibrated=False)
register("tm.tail_jitter", "timing", "p99/median syscall latency ratio is large", {"vm": 0.15},
         "Pin vCPUs and reduce host contention.", calibrated=False)
register("tm.coarse_sleep", "timing", "1ms sleep overshoots by > 400µs on average", {"vm": 0.15},
         "Use a high-resolution guest clocksource.", calibrated=False)


def observe(root, env, budget_s=0.25):
    deadline = time.perf_counter() + budget_s
    samples = []
    while time.perf_counter() < deadline and len(samples) < 200:
        t = time.perf_counter_ns()
        for _ in range(200):
            os.getppid()
        samples.append((time.perf_counter_ns() - t) / 200)
    samples.sort()
    over = []
    for _ in range(5):
        t = time.perf_counter_ns()
        time.sleep(0.001)
        over.append((time.perf_counter_ns() - t) / 1000 - 1000)
    med = statistics.median(samples) if samples else None
    return {
        "syscall_median_ns": round(med, 1) if med else None,
        "syscall_tail_ratio": round(samples[int(len(samples) * 0.99) - 1] / med, 2) if samples and med else None,
        "sleep_overshoot_us": round(statistics.mean(over), 1),
    }


def fire(obs):
    hits = []
    m = obs.get("syscall_median_ns")
    if m and m > 1000:
        hits.append(Hit("tm.slow_syscall", f"median getppid {m:.0f}ns"))
    r = obs.get("syscall_tail_ratio")
    if r and r > 5:
        hits.append(Hit("tm.tail_jitter", f"p99/median {r}"))
    s = obs.get("sleep_overshoot_us")
    if s and s > 400:
        hits.append(Hit("tm.coarse_sleep", f"sleep overshoot {s}µs"))
    return hits
