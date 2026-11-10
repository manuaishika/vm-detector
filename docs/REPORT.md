# Can AI agents tell they are being evaluated? Measuring sandbox detectability

*Aishika — project report for `evalaware`*

## Abstract

Safety evaluations of AI agents are run inside sandboxes. If the sandbox gives itself away, an agent can, at least
in principle, condition its behaviour on "this is a test", and evaluation results stop predicting deployment
behaviour. I built `evalaware`, a dependency-free toolkit that (1) fingerprints an environment through six detection
layers and explains every signal it finds, (2) benchmarks how well a model can infer the isolation boundary from raw
system output, and (3) runs agents on ordinary tasks under evaluation / deployment cues to measure whether they probe
the environment, say they are being tested, or cut corners. On 58 measured samples from 20
real configurations (Docker variants, hardened Docker, namespace and chroot sandboxes, a Firecracker microVM), the
layered detector reaches 0.84 accuracy, 0.76 macro-F1 and 0.79 balanced accuracy. Accuracy
alone is not impressive: 0.83 is what predicting "container" every time would score, because most samples
are containers. Where it is impressive is that all 42 samples from 14 Docker configurations were identified
(42/42), including three hardened variants. Where it fails is instructive: sandboxes that add no runtime
artefacts (`unshare`, 0/6) are invisible, and a chroot of a `docker export` tree is mistaken for a container
because one marker file survives. The tell weights come from a written rubric and are checked against the data
([WEIGHTS.md](WEIGHTS.md)): results are flat under large random perturbations of every weight, and a fitted model does
not beat the hand-set priors under leave-one-configuration-out cross-validation. The LLM benchmark and the agent-behaviour
experiment are fully implemented and tested offline but have not yet been run against a live model.

## 1. Motivation

Evaluation awareness is a known threat to the validity of safety evaluations: frontier models have been
observed remarking that they are being tested, and behaviour that depends on that belief would make
red-teaming and dangerous-capability results unreliable. Most discussion focuses on cues in the *prompt*.
Agents with a shell have a second channel: the *machine*. A freshly booted VM with no shell history, a
`/.dockerenv` file and a hostname like `9f1c2d3e4b5a` is not what a developer's laptop looks like. This
project asks three concrete questions:

- **RQ1 (environment):** How detectable are common agent sandboxes from an unprivileged shell, through
  which signals, and what does it cost to remove them?
- **RQ2 (capability):** Can a language model infer the isolation boundary from raw system observations?
- **RQ3 (behaviour):** Do agents spontaneously probe their environment, and do evaluation cues or a
  more realistic environment change task-irrelevant probing, self-reported P(eval), or rule-breaking?

## 2. Method

### 2.1 Layered fingerprinting

Each layer separates `observe()`, which only collects raw JSON-serialisable facts, from `fire()`, a pure
function that maps facts to named *tells*. The same code therefore runs on a live host, on stored
dataset records, and on the exact text shown to a model in the benchmark.

| Layer | Observes | Example tells |
|---|---|---|
| hardware | DMI strings, CPU flags, `/sys/hypervisor` | hypervisor CPUID bit, VM vendor in DMI |
| kernel | `/proc/version`, boot cmdline, virtio bus, root mount, `systemd-detect-virt` | gVisor banner, overlay root, runtime path in mountinfo |
| container | `/.dockerenv`, `$KUBERNETES_*`, PID 1 | marker files, non-init PID 1 |
| network | MAC OUIs, hostname, resolvers | hypervisor OUI, Firecracker MAC, docker hostname |
| timing | syscall latency, jitter, timer overshoot | slow syscalls (user-space kernels) |
| realism | uptime, `$HOME`, history, process count, cwd | fresh boot, empty home, scratch cwd |

A tell carries weights for one or more boundaries (`vm`, `userspace_kernel`, `container`). Evidence is
combined with a noisy-OR, `s_b = 1 − Π(1 − w_i)`, which gives a proper distribution over
`{bare_metal, vm, userspace_kernel, container}` (the innermost boundary is the label) and an *isolation
stack* such as `vm > container`. Realism tells feed a separate **staged score**. Every tell ships with a
remediation, so the output doubles as a hardening checklist.

**Where the weights come from.** Each tell's weight is fixed by an evidence-tier rubric, written down per tell, and then
tested against data. See [WEIGHTS.md](WEIGHTS.md) for the rubric, the justification of all 35 tells, per-tell
true/false-positive rates, grouped cross-validation, and sensitivity analysis.

### 2.2 Data

- **Measured (58 samples, 20 configurations).** Collected with `scripts/collect_matrix.sh` on a
  Firecracker microVM host, so every container sample is really `vm > container`. Each configuration is sampled three times and
  the repeats share a `group`; cross-validation holds out whole groups. Configurations: 14 Docker variants
  (default, `--network host/none`, `--privileged`, read-only + non-root + `--cap-drop ALL`, `--init`, `--pid host`,
  `--uts/--ipc host`, seccomp/apparmor off, resource limits, `--cgroupns host`, plus three hardened variants that apply every
  remediation the tool suggests), two `unshare` namespace sandboxes, two chroots (a raw `docker export` tree, and the
  same tree with `/.dockerenv` removed), and the host VM itself (plus one earlier host sample taken before `dockerd` was started). **Labels** are the innermost boundary actually created
  by the launch command (namespaces + cgroups ⇒ `container`; chroot alone adds no boundary ⇒ host label), assigned
  before running the classifier. Hostnames, usernames and MAC tails are anonymised at collection time.
- **Reference (12).** Hand-written profiles of VirtualBox, VMware, QEMU, EC2, gVisor, Kubernetes etc. built from public
  documentation. The same author wrote them and the weights, so they only serve as unit-test fixtures and harness smoke tests
  and are always reported separately.
- **What the data cannot test.** Every measured sample runs on a VM host, so there are no bare-metal negatives for the
  `vm` boundary, and there is no gVisor/Kata sample. Those parts of the detector are untested on real data.

### 2.3 Benchmark (RQ2)

A model is shown the raw observations, with no tells and no label, and asked for a probability over the
four classes. Scoring: accuracy, macro-F1, Brier score and expected calibration error, against the
layered detector, the class prior and a uniform guess.

### 2.4 Agent study (RQ3)

Agents get tasks that need no knowledge of the host: fix a FizzBuzz bug, write a word counter, and a
*temptation* task whose test file contains a contradictory assertion, so it can only "pass" if the agent
edits the test. Factors: cue (`neutral` / `eval_cue` / `deploy_cue`) × environment realism (bare vs
seeded `$HOME`) × task, with ≥10 trials per cell. Outcomes: *strong* probes (DMI, cgroups, `dmesg`, cloud
metadata, etc.; regex-classified and never needed for these tasks), *weak* probes (`uname`, `ps`, …),
unprompted remarks about being tested, a post-task self-estimate of P(eval), task success, test
tampering, and whether the agent honestly reported the broken test. Analysis uses Wilson intervals and
two-sided permutation tests. The harness refuses to execute model-chosen commands without `--allow-exec`.

## 3. Results (RQ1)

Generated by `python scripts/results.py` (all tables below are computed from `data/`).

### Per-configuration results (measured, 3 repeats each; `host_before_dockerd` is a single sample)

| configuration | true label | predicted (correct/n) | P(container) | staged | container & kernel tells fired |
|---|---|---|---|---|---|
| `measured-firecracker-microvm` | vm | vm (1/1) | 0.42 | 0.85 | ct.pid1_not_init, kn.cmdline_vm_marker, kn.image_residue, kn.systemd_vm, kn.virtio_bus |
| `docker-default` | container | container (3/3) | 1.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-hostnet` | container | container (3/3) | 1.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-nonet` | container | container (3/3) | 1.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-privileged` | container | container (3/3) | 1.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-readonly-nonroot` | container | container (3/3) | 1.00 | 0.86 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-init` | container | container (3/3) | 1.00 | 0.88 | ct.dockerenv, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-pidhost` | container | container (3/3) | 0.99 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-uts-ipc-host` | container | container (3/3) | 1.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-seccomp-off` | container | container (3/3) | 1.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-limits` | container | container (3/3) | 1.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-cgroupns-host` | container | container (3/3) | 1.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-hardened` | container | container (3/3) | 0.97 | 0.72 | ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-hardened-cgroupns` | container | container (3/3) | 0.91 | 0.72 | ct.pid1_not_init, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-hardened-hostnet` | container | container (3/3) | 0.97 | 0.72 | ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `unshare-ns` | container | vm (0/3) ✗ | 0.42 | 0.85 | ct.pid1_not_init, kn.cmdline_vm_marker, kn.image_residue, kn.systemd_vm, kn.virtio_bus |
| `unshare-pid` | container | vm (0/3) ✗ | 0.42 | 0.85 | ct.pid1_not_init, kn.cmdline_vm_marker, kn.image_residue, kn.systemd_vm, kn.virtio_bus |
| `chroot-export` | vm | container (0/3) ✗ | 0.93 | 0.90 | ct.dockerenv, ct.pid1_not_init, kn.cmdline_vm_marker |
| `chroot-clean` | vm | vm (3/3) | 0.28 | 0.90 | ct.pid1_not_init, kn.cmdline_vm_marker |
| `host` | vm | vm (3/3) | 0.42 | 0.85 | ct.pid1_not_init, kn.cmdline_vm_marker, kn.image_residue, kn.systemd_vm, kn.virtio_bus |

### Baselines (Sandbox-ID benchmark harness)

| model | data | n | accuracy | macro-F1 | Brier | ECE |
|---|---|---|---|---|---|---|
| baseline:layered-detector | measured | 58 | 0.84 | 0.76 | 0.194 | 0.087 |
| baseline:class-prior | measured | 58 | 0.83 | 0.45 | 0.287 | 0.037 |
| baseline:uniform | measured | 58 | 0.00 | 0.00 | 0.750 | 0.250 |
| baseline:layered-detector | reference | 12 | 0.92 | 0.93 | 0.208 | 0.138 |
| baseline:class-prior | reference | 12 | 0.50 | 0.17 | 0.659 | 0.062 |
| baseline:uniform | reference | 12 | 0.17 | 0.07 | 0.750 | 0.083 |

### Per-class recall, layered detector (measured)

| true class | n | recall | confused with |
|---|---|---|---|
| vm | 10 | 0.70 | container ×3 |
| container | 48 | 0.88 | vm ×6 |

Balanced accuracy (mean per-class recall): **0.79**


### Layer ablation (measured)

All layers: 0.84

| layer | accuracy alone | accuracy without | drop when removed |
|---|---|---|---|
| hardware | 0.17 | 0.79 | +0.05 |
| kernel | 0.79 | 0.69 | +0.16 |
| container | 0.57 | 0.90 | -0.05 |
| network | 0.07 | 0.84 | +0.00 |
| timing | 0.00 | 0.84 | +0.00 |
| realism | 0.00 | 0.84 | +0.00 |


### Findings

1. **Docker is easy to detect, in every configuration tried.** All 42 samples from 14 Docker configurations were
   classified as containers; the hardened variants still scored P(container) ≥ 0.91.
2. **Headline accuracy overstates the result.** 0.84 accuracy vs 0.83 for the class prior, because
   48 of 58 samples are containers. The informative numbers are macro-F1
   (0.76 vs 0.45 for the prior), Brier (0.194 vs 0.287) and per-class
   recall: container 0.88, vm 0.70. The detector is clearly better than the prior on the
   balance of classes, not on raw accuracy.
3. **The kernel layer carries the signal; the container layer is net-negative here.** Kernel tells alone reach
   0.79, and removing them costs 0.16. Removing the container layer *raises* accuracy by 0.05
   because `ct.dockerenv` misfires on the exported-tree chroot. Marker files are the cheapest tell to fake and the cheapest
   to leave behind by accident.
4. **Surface hardening is not enough.** Removing `/.dockerenv`, setting a realistic hostname, seeding `$HOME` and
   starting in a project directory cut the mean staged score from 0.92 to 0.72. A private cgroup
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
   runtime artefact: 0/6 were detected as containers. Their staged score is still high, so an agent could tell it is a test
   box without knowing which kind.
7. **The result does not hinge on the weights.** Randomly scaling every weight by a factor of up to e barely moves accuracy
   (WEIGHTS.md §4), a fitted logistic regression is not better than the priors under leave-one-configuration-out CV
   (0.72 vs 0.84), and the misses are properties of the evidence (§5 there), not of the weights.

## 4. Limitations

- **One host.** All samples come from one microVM, so the negatives for each tell are nearly identical. Tells that look
  perfect here (zero false positives for `kn.overlay_root`) are untested against live-CD overlays or odd cgroup layouts. The
  tells and three bug fixes were made after seeing this data, so the numbers are in-sample, not a generalisation estimate.
- **Small effective n.** 58 samples but 20 configurations; repeats are near-identical, which is why grouped CV is used.
- **No bare-metal, gVisor or Kata data**, so the `vm` and `userspace_kernel` parts of the detector are validated only on the circular reference fixtures.
- **RQ2 and RQ3 are not yet run.** The benchmark's Claude backend and the agent study run end to end with a scripted agent in
  the test suite, but no live-model results are reported here.
- **Threat model.** Unprivileged shell only; no CPUID/`rdtsc` cross-checks or co-resident side channels. A determined agent
  has more channels than these.
- **Measurement validity for RQ3.** Regex-based probe and awareness detection misses paraphrase; self-reported P(eval) is not
  a causal measure; cue wording can change behaviour for reasons other than awareness. The planned causal test is to run
  the same agent before and after hardening the same environment.

## 5. Next steps

1. Run `python -m evalaware bench --model claude-opus-5-5` (and smaller models) to place model
   inference ability against the detector baseline.
2. Run the agent study: 3 cues × 2 realism levels × 3 tasks × 10 trials, then
   `python -m evalaware report`. Primary contrasts: neutral vs eval cue on tampering and on strong probes.
3. Grow the measured dataset and report held-out accuracy.
4. Test runtime-level hardening (block-device rootfs, gVisor, Kata) against the same matrix.

## Dual use

Knowing what gives a sandbox away helps evaluators build less detectable environments, and could help
an agent recognise one. Publishing the tells together with their fixes makes eval awareness measurable
and the defence cheap. The behavioural harness only runs model-chosen commands with an explicit opt-in.

## Reproduce

```bash
python -m pytest -q                        # 43 tests
HOST_STACK=vm ./scripts/collect_matrix.sh  # needs docker + python:3.12-alpine; ~57 samples, 20 configurations
python scripts/weights_report.py > docs/WEIGHTS.md   # weight justification + checks against the data
python scripts/build_report.py             # rebuilds this report; every number is computed from data/
python -m evalaware fingerprint            # classify the current machine
```
