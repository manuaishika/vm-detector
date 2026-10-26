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

