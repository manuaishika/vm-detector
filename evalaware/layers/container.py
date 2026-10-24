"""Layer 3 - container runtime artefacts: marker files, env vars, PID 1."""

from ..taxonomy import Hit, register
from .util import exists, read

register("ct.dockerenv", "container", "/.dockerenv present", {"container": 0.9},
         "Remove /.dockerenv from the image.")
register("ct.containerenv", "container", "/run/.containerenv present (podman)", {"container": 0.9},
         "Remove /run/.containerenv.")
register("ct.k8s_env", "container", "KUBERNETES_SERVICE_HOST set", {"container": 0.8},
         "Unset Kubernetes service env vars (enableServiceLinks: false, automount off).")
register("ct.container_env", "container", "'container' env var set (systemd convention)", {"container": 0.6},
         "Unset $container in the workload's environment.")
register("ct.pid1_not_init", "container", "PID 1 is not a conventional init", {"container": 0.2, "staged": 0.3},
         "Run a real init (systemd/tini) as PID 1 and hide the agent supervisor.", calibrated=False)

INITS = ("systemd", "init", "/sbin/init", "/lib/systemd/systemd", "tini", "dumb-init", "/usr/sbin/init")


def observe(root, env):
    pid1 = (read(root, "/proc/1/cmdline") or "").replace("\0", " ").strip()
    return {
        "dockerenv": exists(root, "/.dockerenv"),
        "containerenv": exists(root, "/run/.containerenv"),
        "k8s_env": "KUBERNETES_SERVICE_HOST" in env,
        "container_env": env.get("container"),
        "pid1_cmdline": pid1[:200] or None,
    }


def fire(obs):
    hits = []
    if obs.get("dockerenv"):
        hits.append(Hit("ct.dockerenv", "/.dockerenv exists"))
    if obs.get("containerenv"):
        hits.append(Hit("ct.containerenv", "/run/.containerenv exists"))
    if obs.get("k8s_env"):
        hits.append(Hit("ct.k8s_env", "KUBERNETES_SERVICE_HOST set"))
    if obs.get("container_env"):
        hits.append(Hit("ct.container_env", f"container={obs['container_env']}"))
    p = obs.get("pid1_cmdline")
    if p and not any(p.split()[0].endswith(i) or p.split()[0] == i for i in INITS):
        hits.append(Hit("ct.pid1_not_init", f"PID 1 = {p[:60]}"))
    return hits
