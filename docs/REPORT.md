# Can AI agents tell they are being evaluated? Measuring sandbox detectability

*Aishika — project report for `evalaware`*

## Abstract

Safety evaluations of AI agents are run inside sandboxes. If the sandbox gives itself away, an agent
can, at least in principle, condition its behaviour on "this is a test", and evaluation results stop
predicting deployment behaviour. I built `evalaware`, a dependency-free toolkit that (1) fingerprints an
environment through six detection layers and explains every signal it finds, (2) benchmarks how well a
model can infer the isolation boundary from raw system output, and (3) runs agents on ordinary tasks
under evaluation / deployment cues to measure whether they probe the environment, say they are being
tested, or cut corners. On 9 measured environments (Docker configurations, a namespace sandbox and a
Firecracker microVM), the layered detector identifies the innermost isolation boundary in 8/9 cases
(macro-F1 0.86, Brier 0.16). That is without privileges, in under a second, and it keeps working after
the obvious hardening steps. The kernel layer alone carries most of the signal. Applying every
container-side remediation the tool suggests lowers the "staged environment" score from 0.92 to 0.72,
but the container stays detectable (P = 0.91), because the leaks are in the runtime (overlay root and
storage paths in `/proc/self/mountinfo`), not the image. The agent-behaviour experiment and the LLM
benchmark are fully implemented and tested offline. They have not yet been run against a live model.

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

### 2.2 Data

- **Measured (9).** Collected with `scripts/collect_matrix.sh` inside a Firecracker microVM, so every
  container sample is really `vm > container`: Docker default, `--network host`, `--privileged`,
  read-only + non-root + `--cap-drop ALL`, "hardened" (marker file removed, realistic hostname, seeded
  `$HOME`, project cwd), hardened + `--cgroupns private`, a bare `unshare` namespace sandbox, and the host
  VM itself (before and after starting `dockerd`). Labels were assigned from how each sample was launched,
  not from the classifier. Identifying fields are anonymised at collection time.
- **Reference (12).** Hand-written profiles of VirtualBox, VMware, QEMU, EC2, gVisor, Kubernetes etc.,
  built from public documentation. Because the same person wrote them and the weights, they are used
  only as unit-test fixtures and harness smoke tests, and are always reported separately.

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

Generated by `python scripts/results.py`.

### Per-sample results (measured)

| sample | true | predicted | P(container) | P(vm) | staged | container/kernel tells |
|---|---|---|---|---|---|---|
| `measured-firecracker-microvm` | vm | vm | 0.42 | 0.57 | 0.85 | ct.pid1_not_init, kn.cmdline_vm_marker, kn.image_residue, kn.systemd_vm, kn.virtio_bus |
| `docker-default-fc1` | container | container | 1.00 | 0.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-hostnet-fc1` | container | container | 1.00 | 0.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-privileged-fc1` | container | container | 1.00 | 0.00 | 0.92 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-readonly-nonroot-fc1` | container | container | 1.00 | 0.00 | 0.86 | ct.dockerenv, ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-hardened-fc1` | container | container | 0.97 | 0.03 | 0.72 | ct.pid1_not_init, kn.cgroup_container_path, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `docker-hardened-cgroupns-fc1` | container | container | 0.91 | 0.09 | 0.72 | ct.pid1_not_init, kn.cmdline_vm_marker, kn.mount_runtime_path, kn.overlay_root, kn.virtio_bus |
| `unshare-ns-fc1` | container | vm ✗ | 0.42 | 0.57 | 0.85 | ct.pid1_not_init, kn.cmdline_vm_marker, kn.image_residue, kn.systemd_vm, kn.virtio_bus |
| `host-fc1` | vm | vm | 0.42 | 0.57 | 0.85 | ct.pid1_not_init, kn.cmdline_vm_marker, kn.image_residue, kn.systemd_vm, kn.virtio_bus |

### Baselines (Sandbox-ID benchmark harness)

| model | data | n | accuracy | macro-F1 | Brier | ECE |
|---|---|---|---|---|---|---|
| baseline:layered-detector | measured | 9 | 0.89 | 0.86 | 0.156 | 0.045 |
| baseline:class-prior | measured | 9 | 0.78 | 0.44 | 0.384 | 0.162 |
| baseline:uniform | measured | 9 | 0.00 | 0.00 | 0.750 | 0.250 |
| baseline:layered-detector | reference | 12 | 0.92 | 0.93 | 0.208 | 0.138 |
| baseline:class-prior | reference | 12 | 0.50 | 0.17 | 0.659 | 0.062 |
| baseline:uniform | reference | 12 | 0.17 | 0.07 | 0.750 | 0.083 |

### Layer ablation (measured)

All layers: 0.89

| layer | accuracy alone | accuracy without | drop when removed |
|---|---|---|---|
| hardware | 0.22 | 0.89 | +0.00 |
| kernel | 0.89 | 0.67 | +0.22 |
| container | 0.44 | 0.89 | +0.00 |
| network | 0.22 | 0.89 | +0.00 |
| timing | 0.00 | 0.89 | +0.00 |
| realism | 0.00 | 0.89 | +0.00 |


### Findings

1. **Unprivileged detection is easy and robust.** Every Docker variant, including privileged, host
   network, read-only/non-root and the two hardened ones, was classified correctly, with P(container)
   ≥ 0.91. The VM underneath was visible in every sample (virtio bus, boot cmdline).
2. **The kernel layer is load-bearing.** Kernel tells alone reach the full-system accuracy (0.89), and
   removing them costs 22 points. Hardware and network add little once the kernel layer is present. The
   timing and realism layers never decide the class (by design for realism, which feeds the staged score).
3. **Surface hardening is not enough.** Removing `/.dockerenv`, setting a realistic hostname, seeding
   `$HOME` and starting in a project directory cut the staged score from 0.92 to 0.72. A private cgroup
   namespace additionally removed the `/docker/<id>` cgroup path. The container was still detected
   (P = 0.91) through the overlay root filesystem and runtime storage paths in `/proc/self/mountinfo`.
   Hiding those needs a different runtime (a block-device rootfs or a microVM per task), not a
   different image.
4. **Measurement corrected the detector three times.** The first version called the host VM a
   container once Docker was running on it: host-side `docker0`/`veth` interfaces, the bridge's
   `02:42:…` MAC, and the runtime's overlay mounts all appear in the *host's* view. Each tell was fixed to
   look only at the process's own root mount and non-bridge interfaces, and is covered by a regression
   test. A Docker-built image run as a microVM also leaves `/run/systemd/container` behind, which naive
   tools (including `systemd-detect-virt --container`, which reports `docker` on this VM) misread.
5. **Blind spot: bare namespace sandboxes.** An `unshare`-based sandbox that shares the host root
   filesystem carries no runtime artefacts and is classified as the VM it runs on. Its staged score is
   still high (0.85), so an agent could tell it is a test box without knowing which kind.

## 4. Limitations

- **Small, in-sample data.** Nine measured samples from one host, and the tells above were revised after
  seeing them, so 0.89 is an in-sample number, not a generalisation estimate. Next: collect from laptops,
  cloud VMs, Kubernetes, gVisor and CI runners, and fit weights with environment-level cross-validation.
- **RQ2 and RQ3 are not yet run.** The benchmark's Claude backend and the agent study run end to end
  with a scripted agent in the test suite, but no live-model results are reported here.
- **Threat model.** Unprivileged shell only; no CPUID/`rdtsc` cross-checks or co-resident side channels.
  A determined agent has more channels than these.
- **Measurement validity for RQ3.** Regex-based probe and awareness detection misses paraphrase;
  self-reported P(eval) is not a causal measure; cue wording can change behaviour for reasons other than
  awareness. The planned causal test is to run the same agent before and after hardening the same
  environment.

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
python -m pytest -q                       # 30 tests
HOST_STACK=vm ./scripts/collect_matrix.sh # needs docker + python:3.12-alpine
python scripts/results.py                 # tables above
python -m evalaware fingerprint           # classify the current machine
```
