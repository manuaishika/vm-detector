from pathlib import Path

from evalaware import dataset, harden
from evalaware.classify import classify
from evalaware.fingerprint import collect
from evalaware.taxonomy import REGISTRY

SEED = Path(__file__).resolve().parents[1] / "data" / "seed"


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
    for rec in dataset.load_many([SEED]):
        v = classify(dataset.fingerprint_of(rec))
        assert abs(sum(v.probs.values()) - 1) < 1e-3


def test_every_fired_tell_is_registered_and_has_a_fix():
    for rec in dataset.load_many([SEED]):
        for h in classify(dataset.fingerprint_of(rec)).hits:
            assert h.name in REGISTRY
    assert all(s.remediation for s in REGISTRY.values())


def test_remediation_plan_sorted_by_weight():
    v = classify(dataset.fingerprint_of(dataset.load(SEED / "measured_seed.jsonl")[0]))
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
