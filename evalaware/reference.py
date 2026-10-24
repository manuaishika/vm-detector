"""Hand-written reference profiles built from publicly documented artefacts of each environment.

IMPORTANT: these are fixtures, not measurements. The tell weights were written by the same
author, so a detector scoring well on them proves only that the code matches the author's
mental model. They exist to (1) unit-test the layers, (2) smoke-test the benchmark harness, and
(3) include a few *hardened* variants where individual tells are scrubbed. Quote accuracy only
on records with source='measured'.
"""

import copy
import json
from typing import Dict, List

from .fingerprint import Fingerprint


def _base() -> Dict:
    """A populated, bare-metal Linux workstation."""
    return {
        "hardware": {"arch": "x86_64", "dmi_present": True,
                     "dmi": {"sys_vendor": "Dell Inc.", "product_name": "XPS 15 9520", "bios_vendor": "Dell Inc.",
                             "board_vendor": "Dell Inc.", "chassis_vendor": "Dell Inc."},
                     "cpu_model": "12th Gen Intel(R) Core(TM) i7-12700H", "cpu_hypervisor_flag": False,
                     "hypervisor_sysfs": False, "hypervisor_type": None},
        "kernel": {"version": "Linux version 6.5.0-44-generic (buildd@lcy02) #44~22.04.1-Ubuntu SMP",
                   "cmdline": "BOOT_IMAGE=/vmlinuz-6.5.0-44-generic root=UUID=0a1b quiet splash",
                   "virtio_devices": 0, "root_fstype": "ext4", "cgroup_pid1": "0::/init.scope\n",
                   "run_systemd_container": None, "systemd_detect_virt_vm": "none"},
        "container": {"dockerenv": False, "containerenv": False, "k8s_env": False, "container_env": None,
                      "pid1_cmdline": "/sbin/init splash"},
        "network": {"hostname": "aishika-xps", "ifaces": [{"name": "lo", "mac": "00:00:00:00:00:00"},
                                                          {"name": "wlp0s20f3", "mac": "3c:f0:11:a2:7b:90"}],
                    "nameservers": ["127.0.0.53"], "proxy_env": False},
        "timing": {"syscall_median_ns": 95.0, "syscall_tail_ratio": 1.4, "sleep_overshoot_us": 60.0},
        "realism": {"uptime_s": 412000.0, "home_entries": 61, "has_shell_history": True, "has_ssh_or_git": True,
                    "process_count": 380, "user": "aishika", "cwd": "/home/aishika/projects/thesis"},
    }


def _merge(base: Dict, patch: Dict) -> Dict:
    out = copy.deepcopy(base)
    for layer, vals in patch.items():
        out[layer].update(vals)
    return out


def _rec(id_, label, stack, patch, notes):
    return {"id": id_, "label": label, "stack": stack, "source": "reference", "notes": notes,
            "fingerprint": Fingerprint(_merge(_base(), patch), {"collected_at": "n/a"}).to_dict()}


VMISH_REALISM = {"uptime_s": 380.0, "home_entries": 3, "has_shell_history": False, "has_ssh_or_git": False,
                 "process_count": 70, "user": "ubuntu", "cwd": "/tmp/work"}


def profiles() -> List[Dict]:
    cloud_hw = {"cpu_hypervisor_flag": True, "cpu_model": "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz"}
    docker_k = {"cgroup_pid1": "12:memory:/docker/9f1c2d3e4b5a\n1:name=systemd:/docker/9f1c2d3e4b5a\n",
                "root_fstype": "overlay"}
    return [
        _rec("ref-baremetal-laptop", "bare_metal", [], {}, "Populated developer laptop"),
        _rec("ref-baremetal-server", "bare_metal", [],
             {"realism": {"user": "deploy", "cwd": "/srv/app", "process_count": 210, "home_entries": 14}},
             "Long-lived physical server"),
        _rec("ref-virtualbox", "vm", ["vm"],
             {"hardware": {"dmi": {"sys_vendor": "innotek GmbH", "product_name": "VirtualBox", "bios_vendor": "innotek GmbH",
                                   "board_vendor": "Oracle Corporation", "chassis_vendor": "Oracle Corporation"},
                           "cpu_hypervisor_flag": True},
              "network": {"hostname": "ubuntu", "ifaces": [{"name": "enp0s3", "mac": "08:00:27:4e:66:a1"}]},
              "kernel": {"virtio_devices": 0, "systemd_detect_virt_vm": "oracle"}, "realism": VMISH_REALISM},
             "VirtualBox guest"),
        _rec("ref-vmware", "vm", ["vm"],
             {"hardware": {"dmi": {"sys_vendor": "VMware, Inc.", "product_name": "VMware Virtual Platform",
                                   "bios_vendor": "Phoenix Technologies LTD", "board_vendor": "Intel Corporation",
                                   "chassis_vendor": "No Enclosure"}, "cpu_hypervisor_flag": True},
              "network": {"ifaces": [{"name": "ens33", "mac": "00:0c:29:3b:11:5d"}]},
              "kernel": {"systemd_detect_virt_vm": "vmware"}},
             "VMware Workstation guest"),
        _rec("ref-kvm-qemu", "vm", ["vm"],
             {"hardware": {"dmi": {"sys_vendor": "QEMU", "product_name": "Standard PC (Q35 + ICH9, 2009)",
                                   "bios_vendor": "SeaBIOS", "board_vendor": None, "chassis_vendor": "QEMU"},
                           "cpu_model": "QEMU Virtual CPU version 2.5+", "cpu_hypervisor_flag": True},
              "network": {"ifaces": [{"name": "ens3", "mac": "52:54:00:12:34:56"}]},
              "kernel": {"virtio_devices": 4, "systemd_detect_virt_vm": "kvm"}, "realism": VMISH_REALISM},
             "libvirt/QEMU guest"),
        _rec("ref-aws-ec2", "vm", ["vm"],
             {"hardware": dict(cloud_hw, dmi={"sys_vendor": "Amazon EC2", "product_name": "m6i.large",
                                              "bios_vendor": "Amazon EC2", "board_vendor": "Amazon EC2",
                                              "chassis_vendor": "Amazon EC2"}),
              "network": {"ifaces": [{"name": "ens5", "mac": "0a:4f:9c:12:ab:34"}]},
              "kernel": {"virtio_devices": 0, "systemd_detect_virt_vm": "amazon"},
              "realism": {"user": "ec2-user", "uptime_s": 86000.0, "home_entries": 9, "has_shell_history": True}},
             "AWS Nitro instance"),
        _rec("ref-firecracker-hardened", "vm", ["vm"],
             {"hardware": {"dmi_present": True, "dmi": {"sys_vendor": "Dell Inc.", "product_name": "PowerEdge R650"},
                           "cpu_hypervisor_flag": False, "cpu_model": "Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz"},
              "kernel": {"cmdline": "console=ttyS0 root=/dev/vda rw", "virtio_devices": 3, "systemd_detect_virt_vm": "none"},
              "network": {"ifaces": [{"name": "eth0", "mac": "5e:12:a0:77:3d:c1"}], "hostname": "build-07"},
              "realism": {"uptime_s": 200000.0, "home_entries": 25, "has_shell_history": True, "has_ssh_or_git": True,
                          "user": "dev", "process_count": 160}},
             "HARDENED: Firecracker guest with DMI spoofed, CPUID bit hidden, MAC randomised. Only virtio remains."),
        _rec("ref-kvm-fully-hardened", "vm", ["vm"],
             {"hardware": {"cpu_hypervisor_flag": False, "cpu_model": "Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz"},
              "kernel": {"virtio_devices": 0, "root_fstype": "ext4", "cmdline": "root=/dev/sda1 ro quiet"},
              "network": {"ifaces": [{"name": "eno1", "mac": "b8:ca:3a:5e:12:90"}], "hostname": "build-09"},
              "realism": {"uptime_s": 90000.0, "home_entries": 30, "has_shell_history": True, "has_ssh_or_git": True,
                          "user": "dev", "process_count": 200}},
             "KNOWN-UNDETECTABLE: every static tell scrubbed (passthrough devices). Floor for any classifier."),
        _rec("ref-docker-on-metal", "container", ["container"],
             {"container": {"dockerenv": True, "pid1_cmdline": "sleep infinity"}, "kernel": docker_k,
              "network": {"hostname": "9f1c2d3e4b5a", "ifaces": [{"name": "eth0", "mac": "02:42:ac:11:00:02"}],
                          "nameservers": ["8.8.8.8"]},
              "realism": VMISH_REALISM},
             "Docker container on a physical host"),
        _rec("ref-docker-on-cloud-vm", "container", ["vm", "container"],
             {"hardware": dict(cloud_hw, dmi={"sys_vendor": "Amazon EC2", "product_name": "m6i.large"}),
              "container": {"dockerenv": True, "pid1_cmdline": "/bin/bash"}, "kernel": docker_k,
              "network": {"hostname": "3a7be9d0c411", "ifaces": [{"name": "eth0", "mac": "02:42:ac:11:00:03"}]},
              "realism": VMISH_REALISM},
             "Docker container on a cloud VM; primary label = innermost boundary"),
        _rec("ref-k8s-pod", "container", ["container"],
             {"container": {"k8s_env": True, "pid1_cmdline": "/pause"},
              "kernel": {"cgroup_pid1": "0::/kubepods/burstable/pod1234/abcd\n", "root_fstype": "overlay"},
              "network": {"hostname": "agent-runner-6d9f7c-xk2lp", "ifaces": [{"name": "eth0", "mac": "ea:7c:11:05:9a:20"}]},
              "realism": VMISH_REALISM},
             "Kubernetes pod"),
        _rec("ref-gvisor", "userspace_kernel", ["userspace_kernel"],
             {"hardware": {"dmi_present": False, "dmi": {}, "cpu_model": "unknown"},
              "kernel": {"version": "Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016",
                         "cmdline": None, "root_fstype": "9p", "cgroup_pid1": "", "systemd_detect_virt_vm": "none"},
              "container": {"pid1_cmdline": "/pause"}, "timing": {"syscall_median_ns": 2300.0, "syscall_tail_ratio": 3.0},
              "network": {"hostname": "runsc-sandbox", "ifaces": [{"name": "eth0", "mac": "ba:4a:00:00:12:34"}]},
              "realism": VMISH_REALISM},
             "gVisor (runsc) sandbox"),
    ]


def write(path: str) -> int:
    recs = profiles()
    with open(path, "w") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    return len(recs)
