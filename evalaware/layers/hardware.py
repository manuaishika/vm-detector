"""Layer 1 - hardware identity: DMI strings, CPU flags, hypervisor sysfs."""

import platform
import re
from ..taxonomy import Hit, register
from .util import exists, listdir, read

VM_DMI = ("vmware", "virtualbox", "innotek", "qemu", "kvm", "bochs", "xen", "parallels",
          "amazon ec2", "google compute engine", "alibaba cloud", "openstack", "firecracker",
          "cloud hypervisor", "virtual machine", "bhyve")

DMI_FIELDS = ("sys_vendor", "product_name", "bios_vendor", "board_vendor", "chassis_vendor")

register("hw.dmi_vendor_vm", "hardware", "DMI/BIOS strings name a hypervisor or cloud", {"vm": 0.9},
         "Expose a plausible OEM DMI table (e.g. via a custom SMBIOS in the VMM).")
register("hw.dmi_absent", "hardware", "x86 host with no /sys/class/dmi/id", {"vm": 0.3, "container": 0.1},
         "Provide SMBIOS tables to the guest; do not mask /sys/class/dmi.")
register("hw.cpu_hypervisor_flag", "hardware", "'hypervisor' bit in /proc/cpuinfo flags", {"vm": 0.7},
         "Hide the CPUID hypervisor bit (kvm=off / cpu host-passthrough with hv bit masked).")
register("hw.cpu_model_virtual", "hardware", "CPU model string is a virtual CPU", {"vm": 0.6},
         "Pass through the host CPU model instead of a generic virtual one.")
register("hw.cpu_model_masked", "hardware", "Generic cloud CPU string without model number", {"vm": 0.2},
         "Expose full CPU brand string.")
register("hw.hypervisor_sysfs", "hardware", "/sys/hypervisor exists", {"vm": 0.9},
         "Do not mount hypervisor sysfs into the guest.")


def observe(root, env):
    cpu = read(root, "/proc/cpuinfo") or ""
    model = re.search(r"model name\s*:\s*(.+)", cpu)
    flags = re.search(r"flags\s*:\s*(.+)", cpu)
    dmi = {f: (read(root, f"/sys/class/dmi/id/{f}") or "").strip() or None for f in DMI_FIELDS}
    return {
        "arch": platform.machine(),
        "dmi_present": exists(root, "/sys/class/dmi/id"),
        "dmi": dmi,
        "cpu_model": model.group(1).strip() if model else None,
        "cpu_hypervisor_flag": bool(flags and "hypervisor" in flags.group(1).split()),
        "hypervisor_sysfs": exists(root, "/sys/hypervisor"),
        "hypervisor_type": (read(root, "/sys/hypervisor/type") or "").strip() or None,
    }


def fire(obs):
    hits = []
    blob = " ".join(v.lower() for v in (obs.get("dmi") or {}).values() if v)
    kw = [k for k in VM_DMI if k in blob]
    if kw:
        hits.append(Hit("hw.dmi_vendor_vm", f"DMI contains {kw}"))
    if not obs.get("dmi_present") and obs.get("arch", "").lower() in ("x86_64", "amd64", "i686"):
        hits.append(Hit("hw.dmi_absent", "no /sys/class/dmi/id on x86"))
    if obs.get("cpu_hypervisor_flag"):
        hits.append(Hit("hw.cpu_hypervisor_flag", "cpuinfo flags include 'hypervisor'"))
    model = (obs.get("cpu_model") or "").lower()
    if any(k in model for k in ("qemu", "kvm", "virtual cpu", "common kvm")):
        hits.append(Hit("hw.cpu_model_virtual", f"cpu model '{obs['cpu_model']}'"))
    elif re.fullmatch(r"intel\(r\) xeon\(r\) processor( @ [\d.]+ghz)?", model) or "amd epyc processor" == model:
        hits.append(Hit("hw.cpu_model_masked", f"cpu model '{obs['cpu_model']}'"))
    if obs.get("hypervisor_sysfs"):
        hits.append(Hit("hw.hypervisor_sysfs", "/sys/hypervisor present"))
    return hits
