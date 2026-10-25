from pathlib import Path

from evalaware import dataset, harden
from evalaware.classify import classify
from evalaware.fingerprint import collect
from evalaware.taxonomy import REGISTRY

DATA = Path(__file__).resolve().parents[1] / "data"
SEED = [DATA / "reference", DATA / "measured"]


def _fake_root(tmp_path, files):
    for rel, body in files.items():
        p = tmp_path / rel.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return tmp_path


def test_empty_root_collects_without_error(tmp_path):
    fp = collect(root=tmp_path, env={}, live=False)
    assert set(fp.observations) == {"hardware", "kernel", "container", "network", "timing", "realism"}


def test_docker_markers_detected(tmp_path):
    root = _fake_root(tmp_path, {"/.dockerenv": "", "/proc/1/cgroup": "12:memory:/docker/abc123\n",
                                 "/etc/hostname": "9f1c2d3e4b5a\n"})
    v = classify(collect(root=root, env={}, live=False), layers=["container", "kernel", "network"])
    assert v.primary == "container"
    assert {"ct.dockerenv", "kn.cgroup_container_path", "nt.hostname_random_hex"} <= {h.name for h in v.hits}


def test_dmi_vendor_means_vm(tmp_path):
    root = _fake_root(tmp_path, {"/sys/class/dmi/id/sys_vendor": "VMware, Inc.\n",
                                 "/proc/cpuinfo": "model name : Intel Xeon\nflags : fpu hypervisor sse\n"})
    v = classify(collect(root=root, env={}, live=False), layers=["hardware"])
    assert v.primary == "vm" and "hw.dmi_vendor_vm" in {h.name for h in v.hits}


def test_noisy_or_is_monotone_in_evidence(tmp_path):
    one = classify(collect(root=_fake_root(tmp_path, {"/proc/cpuinfo": "flags : hypervisor\n"}), env={}, live=False))
    two_root = _fake_root(tmp_path / "b", {"/proc/cpuinfo": "flags : hypervisor\n", "/sys/class/dmi/id/sys_vendor": "QEMU\n"})
    two = classify(collect(root=two_root, env={}, live=False))
    assert two.boundary_scores["vm"] > one.boundary_scores["vm"]


def test_probs_sum_to_one():
    for rec in dataset.load_many(SEED):
        v = classify(dataset.fingerprint_of(rec))
        assert abs(sum(v.probs.values()) - 1) < 1e-3


def test_every_fired_tell_is_registered_and_has_a_fix():
    for rec in dataset.load_many(SEED):
        for h in classify(dataset.fingerprint_of(rec)).hits:
            assert h.name in REGISTRY
    assert all(s.remediation for s in REGISTRY.values())


def test_remediation_plan_sorted_by_weight():
    v = classify(dataset.fingerprint_of(dataset.load(DATA / "measured" / "host_before_dockerd.jsonl")[0]))
    w = [p["max_weight"] for p in harden.remediation_plan(v)]
    assert w == sorted(w, reverse=True) and w


def test_anonymize_strips_identifiers():
    fp = collect(live=False)
    fp.observations["network"]["hostname"] = "aishika-private-laptop"
    fp.observations["realism"]["user"] = "aishika"
    out = dataset.anonymize(fp)
    assert out.observations["network"]["hostname"] == "<redacted>"
    assert out.observations["realism"]["user"] == "<redacted>"
    assert fp.observations["realism"]["user"] == "aishika"  # original untouched


def test_container_host_is_not_a_container(tmp_path):
    """Regression (found by measurement): a VM running dockerd has docker0/veth interfaces and
    runtime overlay mounts in its mountinfo, but is not itself inside a container."""
    mi = ("22 1 253:0 / / rw,relatime - ext4 /dev/vda rw\n"
          "93 22 0:41 / /var/lib/docker/rootfs/abc rw - overlay overlay rw,lowerdir=/var/lib/docker/x\n")
    root = _fake_root(tmp_path, {"/proc/self/mountinfo": mi, "/sys/class/net/docker0/address": "02:42:11:22:33:44\n",
                                 "/sys/class/net/veth1a2b/address": "6a:11:22:33:44:55\n"})
    v = classify(collect(root=root, env={}, live=False), layers=["kernel", "network"])
    names = {h.name for h in v.hits}
    assert "kn.mount_runtime_path" not in names and "kn.overlay_root" not in names
    assert v.primary != "container"


def test_container_root_mount_leaks_runtime_path(tmp_path):
    mi = "93 62 0:41 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/3/fs\n"
    root = _fake_root(tmp_path, {"/proc/self/mountinfo": mi})
    names = {h.name for h in classify(collect(root=root, env={}, live=False), layers=["kernel"]).hits}
    assert {"kn.mount_runtime_path", "kn.overlay_root"} <= names
