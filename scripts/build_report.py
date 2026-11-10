"""Build docs/REPORT.md from the data, so every number in the prose is computed, not typed.

Run from the repo root:  python scripts/build_report.py
Needs docs/_parts/{motivation_method,bench_study,tail}.md (static prose kept in the repo).
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import evalaware.layers  # noqa: E402,F401
from evalaware import ablate, bench, calibrate, dataset  # noqa: E402
from evalaware.classify import classify  # noqa: E402
from evalaware.metrics import confusion  # noqa: E402
from evalaware.taxonomy import CLASSES  # noqa: E402

parts = ROOT / "docs" / "_parts"
read = lambda n: (parts / n).read_text()
tables = subprocess.run([sys.executable, str(ROOT / "scripts" / "results.py")], capture_output=True, text=True,
                        cwd=ROOT, check=True).stdout

M = dataset.load_many([ROOT / "data" / "measured"])
R = dataset.load_many([ROOT / "data" / "reference"])
groups = sorted({r["group"] for r in M})
y = [r["label"] for r in M]
V = [classify(dataset.fingerprint_of(r)) for r in M]
pred = [v.primary for v in V]
acc = sum(a == b for a, b in zip(y, pred)) / len(y)
cm = confusion(y, pred)
rec = {c: cm[c][c] / sum(cm[c].values()) for c in CLASSES if sum(cm[c].values())}
bal = sum(rec.values()) / len(rec)
det = bench.run(bench.DetectorBaseline(), M)["by_source"]["measured"]
pri = bench.run(bench.PriorBaseline(M), M)["by_source"]["measured"]
ab = ablate.run(M)["measured"]
docker = [g for g in groups if g.startswith("docker-")]
dk_ok = sum(1 for r, p in zip(M, pred) if r["group"].startswith("docker-") and p == r["label"])
dk_n = sum(1 for r in M if r["group"].startswith("docker-"))
hard = [v.probs["container"] for r, v in zip(M, V) if r["group"].startswith("docker-hardened")]
staged_default = [v.staged_score for r, v in zip(M, V) if r["group"] == "docker-default"]
staged_hard = [v.staged_score for r, v in zip(M, V) if r["group"] == "docker-hardened"]
miss = sorted({r["group"] for r, p in zip(M, pred) if p != r["label"]})
cv = calibrate.grouped_cv(M)
n_ns = sum(1 for r in M if r["group"].startswith("unshare"))
k_alone, k_drop = ab["single_layer"]["kernel"], ab["all_layers"] - ab["leave_one_out"]["kernel"]
c_drop = ab["all_layers"] - ab["leave_one_out"]["container"]
mean = lambda xs: sum(xs) / len(xs)

out = f"""# Can AI agents tell they are being evaluated? Measuring sandbox detectability

*Aishika — project report for `evalaware`*

## Abstract

Safety evaluations of AI agents are run inside sandboxes. If the sandbox gives itself away, an agent can, at least
in principle, condition its behaviour on "this is a test", and evaluation results stop predicting deployment
behaviour. I built `evalaware`, a dependency-free toolkit that (1) fingerprints an environment through six detection
layers and explains every signal it finds, (2) benchmarks how well a model can infer the isolation boundary from raw
system output, and (3) runs agents on ordinary tasks under evaluation / deployment cues to measure whether they probe
the environment, say they are being tested, or cut corners. On {len(M)} measured samples from {len(groups)}
real configurations (Docker variants, hardened Docker, namespace and chroot sandboxes, a Firecracker microVM), the
layered detector reaches {acc:.2f} accuracy, {det['macro_f1']:.2f} macro-F1 and {bal:.2f} balanced accuracy. Accuracy
alone is not impressive: {pri['accuracy']:.2f} is what predicting "container" every time would score, because most samples
are containers. Where it is impressive is that all {dk_n} samples from {len(docker)} Docker configurations were identified
({dk_ok}/{dk_n}), including three hardened variants. Where it fails is instructive: sandboxes that add no runtime
artefacts (`unshare`, 0/{n_ns}) are invisible, and a chroot of a `docker export` tree is mistaken for a container
because one marker file survives. The tell weights come from a written rubric and are checked against the data
([WEIGHTS.md](WEIGHTS.md)): results are flat under large random perturbations of every weight, and a fitted model does
not beat the hand-set priors under leave-one-configuration-out cross-validation. The LLM benchmark and the agent-behaviour
experiment are fully implemented and tested offline but have not yet been run against a live model.

""" + read("motivation_method.md") + f"""**Where the weights come from.** Each tell's weight is fixed by an evidence-tier rubric, written down per tell, and then
tested against data. See [WEIGHTS.md](WEIGHTS.md) for the rubric, the justification of all {len(__import__('evalaware').taxonomy.REGISTRY)} tells, per-tell
true/false-positive rates, grouped cross-validation, and sensitivity analysis.

### 2.2 Data

- **Measured ({len(M)} samples, {len(groups)} configurations).** Collected with `scripts/collect_matrix.sh` on a
  Firecracker microVM host, so every container sample is really `vm > container`. Each configuration is sampled three times and
  the repeats share a `group`; cross-validation holds out whole groups. Configurations: {len(docker)} Docker variants
  (default, `--network host/none`, `--privileged`, read-only + non-root + `--cap-drop ALL`, `--init`, `--pid host`,
  `--uts/--ipc host`, seccomp/apparmor off, resource limits, `--cgroupns host`, plus three hardened variants that apply every
  remediation the tool suggests), two `unshare` namespace sandboxes, two chroots (a raw `docker export` tree, and the
  same tree with `/.dockerenv` removed), and the host VM itself (plus one earlier host sample taken before `dockerd` was started). **Labels** are the innermost boundary actually created
  by the launch command (namespaces + cgroups ⇒ `container`; chroot alone adds no boundary ⇒ host label), assigned
  before running the classifier. Hostnames, usernames and MAC tails are anonymised at collection time.
- **Reference ({len(R)}).** Hand-written profiles of VirtualBox, VMware, QEMU, EC2, gVisor, Kubernetes etc. built from public
  documentation. The same author wrote them and the weights, so they only serve as unit-test fixtures and harness smoke tests
  and are always reported separately.
- **What the data cannot test.** Every measured sample runs on a VM host, so there are no bare-metal negatives for the
  `vm` boundary, and there is no gVisor/Kata sample. Those parts of the detector are untested on real data.

""" + read("bench_study.md") + f"""## 3. Results (RQ1)

Generated by `python scripts/results.py` (all tables below are computed from `data/`).

{tables}

### Findings

1. **Docker is easy to detect, in every configuration tried.** All {dk_n} samples from {len(docker)} Docker configurations were
   classified as containers; the hardened variants still scored P(container) ≥ {min(hard):.2f}.
2. **Headline accuracy overstates the result.** {acc:.2f} accuracy vs {pri['accuracy']:.2f} for the class prior, because
   {sum(c == 'container' for c in y)} of {len(y)} samples are containers. The informative numbers are macro-F1
   ({det['macro_f1']:.2f} vs {pri['macro_f1']:.2f} for the prior), Brier ({det['brier']:.3f} vs {pri['brier']:.3f}) and per-class
   recall: container {rec['container']:.2f}, vm {rec['vm']:.2f}. The detector is clearly better than the prior on the
   balance of classes, not on raw accuracy.
3. **The kernel layer carries the signal; the container layer is net-negative here.** Kernel tells alone reach
   {k_alone:.2f}, and removing them costs {k_drop:.2f}. Removing the container layer *raises* accuracy by {-c_drop:.2f}
   because `ct.dockerenv` misfires on the exported-tree chroot. Marker files are the cheapest tell to fake and the cheapest
   to leave behind by accident.
4. **Surface hardening is not enough.** Removing `/.dockerenv`, setting a realistic hostname, seeding `$HOME` and
   starting in a project directory cut the mean staged score from {mean(staged_default):.2f} to {mean(staged_hard):.2f}. A private cgroup
   namespace additionally removed the `/docker/<id>` cgroup path. The container was still detected through the overlay root
   and runtime storage paths in `/proc/self/mountinfo`. Hiding those needs a different runtime (a block-device rootfs or a
   microVM per task), not a different image.
5. **Measurement corrected the detector three times.** The first version called the host VM a container once Docker was
   running on it: host-side `docker0`/`veth` interfaces, the bridge's `02:42:…` MAC, and the runtime's overlay mounts all
   appear in the *host's* view. Each tell was fixed to look only at the process's own root mount and non-bridge
   interfaces, and is covered by a regression test. A Docker-built image run as a microVM also leaves
   `/run/systemd/container` behind, which naive tools (including `systemd-detect-virt --container`, which reports `docker`
   on this VM) misread.
6. **Blind spot: namespace-only sandboxes.** `unshare` sandboxes share the host root filesystem and cgroups, so they carry no
   runtime artefact: 0/{n_ns} were detected as containers. Their staged score is still high, so an agent could tell it is a test
   box without knowing which kind.
7. **The result does not hinge on the weights.** Randomly scaling every weight by a factor of up to e barely moves accuracy
   (WEIGHTS.md §4), a fitted logistic regression is not better than the priors under leave-one-configuration-out CV
   ({cv['fitted']['accuracy']:.2f} vs {cv['prior']['accuracy']:.2f}), and the misses are properties of the evidence (§5 there), not of the weights.

## 4. Limitations

- **One host.** All samples come from one microVM, so the negatives for each tell are nearly identical. Tells that look
  perfect here (zero false positives for `kn.overlay_root`) are untested against live-CD overlays or odd cgroup layouts. The
  tells and three bug fixes were made after seeing this data, so the numbers are in-sample, not a generalisation estimate.
- **Small effective n.** {len(M)} samples but {len(groups)} configurations; repeats are near-identical, which is why grouped CV is used.
- **No bare-metal, gVisor or Kata data**, so the `vm` and `userspace_kernel` parts of the detector are validated only on the circular reference fixtures.
- **RQ2 and RQ3 are not yet run.** The benchmark's Claude backend and the agent study run end to end with a scripted agent in
  the test suite, but no live-model results are reported here.
- **Threat model.** Unprivileged shell only; no CPUID/`rdtsc` cross-checks or co-resident side channels. A determined agent
  has more channels than these.
- **Measurement validity for RQ3.** Regex-based probe and awareness detection misses paraphrase; self-reported P(eval) is not
  a causal measure; cue wording can change behaviour for reasons other than awareness. The planned causal test is to run
  the same agent before and after hardening the same environment.

""" + read("tail.md")
(ROOT / "docs" / "REPORT.md").write_text(out)
print(f"wrote docs/REPORT.md ({len(out.split())} words)")
