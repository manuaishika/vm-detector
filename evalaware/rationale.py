"""Why each tell has the weight it has.

Weights are not tuned numbers. Each tell is placed in an evidence tier by a fixed rubric, and the
weight must fall inside that tier's band (enforced by tests/test_rationale.py). The rubric asks two
questions about the artefact the tell observes:

  1. Is it *produced by* the boundary (it cannot exist without it), or merely *correlated* with it?
  2. How many benign environments show it anyway, and how easy is it to remove on purpose?

  Tier A  0.80-0.90  produced by the boundary or its runtime; absent elsewhere; removal needs deliberate effort
  Tier B  0.60-0.70  strong correlate set by runtime defaults; configurable, occasionally present elsewhere
  Tier C  0.30-0.50  circumstantial: common under the boundary but also seen in benign setups
  Tier D  0.10-0.25  weak heuristic: shows up on many ordinary machines

Tier bands are priors from how these systems are documented to behave. docs/WEIGHTS.md then checks them
against measured data (per-tell true/false positive rates, rank agreement, grouped cross-validation,
sensitivity to perturbing every weight). Where data disagrees with a tier, the report says so.
"""

from .taxonomy import REGISTRY

TIERS = {"A": (0.80, 0.90), "B": (0.60, 0.70), "C": (0.30, 0.50), "D": (0.10, 0.25)}

# name -> (tier, mechanism, known confounders)
RATIONALE = {
    "hw.dmi_vendor_vm": ("A", "Hypervisors write their own vendor/product into SMBIOS (VMware, innotek/VirtualBox, QEMU, Amazon EC2…); bare-metal OEMs never do.",
                         "A cloud/VM operator can set arbitrary SMBIOS strings (this is the standard spoofing step)."),
    "hw.hypervisor_sysfs": ("A", "/sys/hypervisor/type is created by the Xen/KVM guest support code only when running as a guest.",
                            "Absent on most KVM guests, so it is high-precision, low-recall."),
    "kn.gvisor_banner": ("A", "gVisor's sentry reports a fixed, synthetic /proc/version (Linux 4.4.0, 2016 build date) that no real kernel build uses.",
                         "Could be changed in a fork of the sentry."),
    "ct.dockerenv": ("A", "Docker creates /.dockerenv in every container's root filesystem.",
                     "Survives in `docker export` trees, so a chroot of one looks like a container (measured: chroot-export)."),
    "ct.containerenv": ("A", "Podman/CRI-O create /run/.containerenv in the container.", "Same residue risk as /.dockerenv."),
    "ct.k8s_env": ("A", "The kubelet injects KUBERNETES_SERVICE_HOST into every pod's environment.",
                   "Trivial to unset; absent when enableServiceLinks is false or automount is off."),
    "kn.mount_runtime_path": ("A", "The container's root mount line carries the runtime's storage path (/var/lib/docker, containerd snapshotter) in its overlay options.",
                              "Only checked on the '/' mount; a host's own mountinfo also lists runtime mounts (measured false positive, fixed)."),
    "hw.cpu_hypervisor_flag": ("B", "CPUID leaf 1 ECX bit 31 is set by hypervisors and surfaces as 'hypervisor' in /proc/cpuinfo.",
                               "Can be hidden (KVM `kvm=off`, hv-passthrough); also set on bare metal running as a nested L1 guest."),
    "hw.cpu_model_virtual": ("B", "QEMU's default CPU models carry names like 'QEMU Virtual CPU'.", "Host-passthrough models report the real CPU name."),
    "kn.virtio_bus": ("B", "virtio devices on /sys/bus/virtio exist because the VMM emulates them.",
                      "Also present on bare-metal hosts that expose virtio for containers/vsock; cannot be removed without changing the device model."),
    "kn.systemd_vm": ("B", "systemd-detect-virt combines DMI, CPUID and device probes and names the hypervisor.", "Inherits its inputs' spoofing weaknesses; --container output is unreliable on image-built VMs."),
    "kn.cgroup_container_path": ("B", "PID 1's cgroup path contains the runtime's slice (/docker/<id>, /kubepods/…).",
                                 "A private cgroup namespace hides it (measured: docker-hardened-cgroupns)."),
    "ct.container_env": ("B", "systemd convention: container managers set $container.", "Many runtimes do not set it; trivial to unset."),
    "nt.mac_oui_vm": ("B", "Hypervisors allocate NIC MACs from vendor OUIs (08:00:27, 00:0c:29, 52:54:00, …).", "MACs are configurable; cloud NICs use other ranges."),
    "nt.mac_firecracker": ("B", "Firecracker documents 'AA:FC:00:00:00:01'-style default guest MACs.", "Operators can assign any MAC."),
    "nt.mac_docker": ("B", "Docker's bridge assigns 02:42:<ip> MACs to container interfaces.",
                      "Host-side docker0/br-*/veth* interfaces carry the same prefix (measured false positive, fixed by excluding them)."),
    "hw.dmi_absent": ("C", "Real x86 machines always expose SMBIOS; microVMs and masked sysfs often do not.", "Also absent in containers with masked /sys and on some minimal VMs."),
    "kn.cmdline_vm_marker": ("C", "Boot cmdlines of microVM launchers contain markers (firecracker, virtio_mmio, pci=off).",
                             "Visible only if /proc/cmdline is exposed; real tags vary by launcher."),
    "kn.overlay_root": ("C", "Container runtimes mount the image as an overlayfs root.", "Live-boot ISOs and some immutable-OS setups also use overlay roots."),
    "nt.hostname_random_hex": ("C", "Docker defaults the container hostname to the 12-hex-digit container ID.", "Any runtime can set --hostname; unrelated machines are sometimes named randomly."),
    "tm.slow_syscall": ("C", "User-space kernels (gVisor ptrace/systrap) pay microseconds per syscall; native/KVM guests pay ~100-200 ns.",
                        "Absolute thresholds are hardware-dependent; slow CPUs or heavy load can exceed 1 µs."),
    "nt.hostname_generic": ("C", "Placeholder hostnames (vm, sandbox, ubuntu, runner) come from images, not from people naming their machines.", "Plenty of real machines keep 'ubuntu'/'localhost'."),
    "ct.pid1_not_init": ("C", "Containers and agent sandboxes usually run an app or supervisor as PID 1 instead of init/systemd.", "Minimal VMs and rescue shells also run odd PID 1s."),
    "rl.fresh_boot": ("C", "Per-task sandboxes are cold-booted, so uptime is minutes.", "Laptops that just woke from a reboot or crash look the same."),
    "rl.sparse_home": ("C", "Real users accumulate files in $HOME.", "Fresh installs and service accounts have empty homes."),
    "hw.cpu_model_masked": ("D", "Cloud vendors report generic strings ('Intel(R) Xeon(R) Processor @ …GHz') that omit the model number.", "Many ordinary servers report similar strings."),
    "kn.image_residue": ("D", "/run/systemd/container is written when a systemd image was built or run in a container.", "Stale after the image is reused as a VM rootfs; a documented source of false positives."),
    "tm.tail_jitter": ("D", "Hypervisor scheduling adds tail latency to tight syscall loops.", "Any busy machine shows tail jitter."),
    "tm.coarse_sleep": ("D", "Virtualised timers can overshoot short sleeps.", "Depends on kernel HZ and load, not just virtualisation."),
    "rl.no_shell_history": ("D", "People who use a shell leave history files.", "History can be disabled; service accounts have none."),
    "rl.few_processes": ("D", "Sandboxes run few background services.", "Servers and minimal installs run few processes too."),
    "rl.default_user": ("D", "Sandboxes run as root/ubuntu/runner.", "Common on cloud servers and CI."),
    "rl.no_ssh_state": ("D", "Developer machines have ~/.ssh or ~/.gitconfig.", "Non-developer machines do not."),
    "rl.workdir_scratch": ("D", "Agents start in /tmp, /workspace or /mnt.", "Many legitimate jobs run there."),
    "nt.public_dns_only": ("D", "Sandboxes inherit public resolvers.", "Home users configure 8.8.8.8 voluntarily."),
}


def tier_of(name):
    return RATIONALE[name][0]


def check():
    """Return a list of problems: missing rationale, or a weight outside its tier's band."""
    problems = []
    for name, spec in REGISTRY.items():
        if name not in RATIONALE:
            problems.append(f"{name}: no rationale")
            continue
        lo, hi = TIERS[RATIONALE[name][0]]
        top = max(spec.votes.values())
        if not (lo - 1e-9 <= top <= hi + 1e-9):
            problems.append(f"{name}: max weight {top} outside tier {RATIONALE[name][0]} band {lo}-{hi}")
    problems += [f"{n}: rationale for unknown tell" for n in RATIONALE if n not in REGISTRY]
    return problems
