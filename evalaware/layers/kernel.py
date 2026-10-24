"""Layer 2 - kernel & boot: kernel banner, cmdline, virtio bus, mounts, systemd's own verdict."""

import re
import subprocess
from ..taxonomy import Hit, register
from .util import listdir, read

register("kn.gvisor_banner", "kernel", "Fixed gVisor /proc/version banner", {"userspace_kernel": 0.9},
         "Not removable without patching the sentry; consider a microVM runtime instead.")
register("kn.cmdline_vm_marker", "kernel", "Kernel cmdline mentions firecracker/virtio_mmio/pci=off/no_guest_*",
         {"vm": 0.5}, "Do not expose the real boot cmdline (/proc/cmdline) to the workload.")
register("kn.virtio_bus", "kernel", "virtio devices on /sys/bus/virtio", {"vm": 0.6},
         "Hard to hide on KVM; accept or use device passthrough.", calibrated=False)
register("kn.overlay_root", "kernel", "Root filesystem is overlayfs", {"container": 0.35},
         "Back the root with a plain block device inside the sandbox.")
register("kn.cgroup_container_path", "kernel", "cgroup path names docker/kubepods/containerd/lxc",
         {"container": 0.7}, "Mount a private cgroup namespace or a sanitised /proc/1/cgroup.")
register("kn.systemd_vm", "kernel", "systemd-detect-virt --vm reports a hypervisor", {"vm": 0.6},
         "Hide the underlying DMI/CPUID evidence systemd uses.")
register("kn.image_residue", "kernel", "/run/systemd/container left over from a container image build",
         {"container": 0.2}, "Clean image-build residue before use.", calibrated=False)

CONTAINER_CGROUP = re.compile(r"docker|kubepods|containerd|lxc|libpod|crio|garden", re.I)
VM_SYSTEMD = {"kvm", "qemu", "vmware", "microsoft", "oracle", "xen", "bochs", "uml", "parallels",
              "bhyve", "qnx", "acrn", "powervm", "apple", "amazon", "google", "zvm"}


def _systemd(flag):
    try:
        out = subprocess.run(["systemd-detect-virt", flag], capture_output=True, text=True, timeout=3)
        return out.stdout.strip() or "none"
    except (OSError, subprocess.SubprocessError):
        return None


def _root_fstype(mountinfo):
    for line in (mountinfo or "").splitlines():
        parts = line.split()
        if len(parts) > 8 and parts[4] == "/" and "-" in parts:
            return parts[parts.index("-") + 1]
    return None


def observe(root, env, live=True):
    cmdline = (read(root, "/proc/cmdline") or "").strip()
    virtio = listdir(root, "/sys/bus/virtio/devices") or []
    obs = {
        "version": (read(root, "/proc/version") or "").strip(),
        "cmdline": cmdline[:400] or None,
        "virtio_devices": len(virtio),
        "root_fstype": _root_fstype(read(root, "/proc/self/mountinfo")),
        "cgroup_pid1": (read(root, "/proc/1/cgroup") or "")[:600],
        "run_systemd_container": (read(root, "/run/systemd/container") or "").strip() or None,
    }
    obs["systemd_detect_virt_vm"] = _systemd("--vm") if live else None
    return obs


def fire(obs):
    hits = []
    v = obs.get("version") or ""
    if "gvisor" in v.lower() or re.search(r"4\.4\.0 .*2016", v):
        hits.append(Hit("kn.gvisor_banner", "gVisor-style /proc/version"))
    cl = (obs.get("cmdline") or "").lower()
    if any(m in cl for m in ("firecracker", "virtio_mmio", "pci=off", "no_guest_host", "no_guest_guest")):
        hits.append(Hit("kn.cmdline_vm_marker", f"cmdline: {cl[:80]}"))
    if obs.get("virtio_devices", 0) > 0:
        hits.append(Hit("kn.virtio_bus", f"{obs['virtio_devices']} virtio devices"))
    if obs.get("root_fstype") == "overlay":
        hits.append(Hit("kn.overlay_root", "root mounted as overlay"))
    if CONTAINER_CGROUP.search(obs.get("cgroup_pid1") or ""):
        hits.append(Hit("kn.cgroup_container_path", "container runtime in /proc/1/cgroup"))
    if (obs.get("systemd_detect_virt_vm") or "none") in VM_SYSTEMD:
        hits.append(Hit("kn.systemd_vm", f"systemd-detect-virt --vm = {obs['systemd_detect_virt_vm']}"))
    if obs.get("run_systemd_container"):
        hits.append(Hit("kn.image_residue", f"/run/systemd/container = {obs['run_systemd_container']}"))
    return hits
