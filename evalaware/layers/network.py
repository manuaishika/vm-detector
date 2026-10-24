"""Layer 4 - network identity: MAC OUIs, interface names, hostname, resolvers, proxies."""

import re
import socket
from ..taxonomy import Hit, register
from .util import listdir, read

VM_OUI = {"08:00:27": "VirtualBox", "00:0c:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
          "00:15:5d": "Hyper-V", "52:54:00": "QEMU/KVM", "00:16:3e": "Xen", "00:1c:42": "Parallels"}

register("nt.mac_oui_vm", "network", "NIC MAC uses a hypervisor vendor OUI", {"vm": 0.7},
         "Randomise guest MACs from a real vendor range.")
register("nt.mac_firecracker", "network", "Firecracker-style locally-administered guest MAC (xx:fc:00:..)",
         {"vm": 0.7}, "Assign non-default guest MACs.")
register("nt.mac_docker", "network", "Docker bridge MAC (02:42:..)", {"container": 0.6},
         "Use host or macvlan networking, or a non-default MAC.")
register("nt.iface_container", "network", "veth*/docker*/br-* interface names", {"container": 0.5},
         "Rename interfaces inside the namespace.")
register("nt.hostname_random_hex", "network", "Hostname is 12 hex chars (docker default)",
         {"container": 0.4, "staged": 0.3}, "Give sandboxes a realistic hostname.")
register("nt.hostname_generic", "network", "Hostname is a placeholder (vm/localhost/sandbox/…)",
         {"staged": 0.3}, "Use a realistic hostname.", calibrated=False)
register("nt.public_dns_only", "network", "Only public resolvers (8.8.8.8 etc.) configured", {"staged": 0.15},
         "Use the resolver a real workstation/server would have.", calibrated=False)


def observe(root, env):
    ifaces = []
    for name in listdir(root, "/sys/class/net") or []:
        mac = (read(root, f"/sys/class/net/{name}/address") or "").strip()
        ifaces.append({"name": name, "mac": mac})
    resolv = read(root, "/etc/resolv.conf") or ""
    host = (read(root, "/etc/hostname") or "").strip() or socket.gethostname()
    return {
        "hostname": host,
        "ifaces": ifaces,
        "nameservers": re.findall(r"^nameserver\s+(\S+)", resolv, re.M),
        "proxy_env": any(k.lower().endswith("_proxy") for k in env),
    }


def fire(obs):
    hits = []
    for i in obs.get("ifaces", []):
        mac = i["mac"].lower()
        if mac in ("", "00:00:00:00:00:00"):
            continue
        if mac[:8] in VM_OUI:
            hits.append(Hit("nt.mac_oui_vm", f"{i['name']} {mac} ({VM_OUI[mac[:8]]})"))
        if re.match(r"^(02|aa):fc:00", mac):
            hits.append(Hit("nt.mac_firecracker", f"{i['name']} {mac}"))
        if mac.startswith("02:42:"):
            hits.append(Hit("nt.mac_docker", f"{i['name']} {mac}"))
    names = [i["name"] for i in obs.get("ifaces", []) if re.match(r"^(veth|docker|br-|cni)", i["name"])]
    if names:
        hits.append(Hit("nt.iface_container", f"interfaces {names}"))
    h = obs.get("hostname") or ""
    if re.fullmatch(r"[0-9a-f]{12}", h):
        hits.append(Hit("nt.hostname_random_hex", h))
    elif re.fullmatch(r"(localhost|vm|sandbox|container|ubuntu|debian|test|eval|agent|runner)\w{0,3}", h, re.I):
        hits.append(Hit("nt.hostname_generic", h))
    ns = obs.get("nameservers") or []
    if ns and all(n in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9") for n in ns):
        hits.append(Hit("nt.public_dns_only", f"resolvers {ns}"))
    return hits
