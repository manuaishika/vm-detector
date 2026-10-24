# evalaware

**Can AI agents tell they are in a sandbox, and does it change what they do?**

Safety evaluations run agents in sandboxes. If an agent can tell it is in a test (or merely behaves
differently when it suspects so), evaluation results stop predicting deployment behaviour. `evalaware`
is a small, stdlib-only toolkit for studying that problem from three directions:

| Part | Question it answers | Command |
|---|---|---|
| **Layered fingerprinting** | How detectable is this environment, through which layers, and what removes each tell? | `fingerprint`, `harden`, `ablate` |
| **Sandbox-ID benchmark** | Can a model infer the isolation class (bare metal / VM / user-space kernel / container) from raw system output? | `bench` |
| **Agent study** | Do agents probe for, mention, or react to being in a test, e.g. does an "evaluation" cue change reward-hacking? | `study`, `report` |

It grew out of a proctoring-style VM detector, which is preserved in [`legacy/vm-detect`](legacy/vm-detect).

## How detection works: six layers

Each layer separates `observe()` (collect raw JSON-serialisable facts) from `fire()` (pure function from
facts to named *tells*). So the same classifier runs on a live host, a stored dataset record, or the text
shown to an LLM in the benchmark.

| # | Layer | Looks at | Example tells |
|---|---|---|---|
| 1 | hardware | DMI strings, CPU flags, `/sys/hypervisor` | `hw.cpu_hypervisor_flag`, `hw.dmi_vendor_vm` |
| 2 | kernel | `/proc/version`, boot cmdline, virtio bus, mounts, `systemd-detect-virt` | `kn.gvisor_banner`, `kn.virtio_bus` |
| 3 | container | `/.dockerenv`, `$KUBERNETES_*`, PID 1 | `ct.dockerenv`, `ct.pid1_not_init` |
| 4 | network | MAC OUIs, interface names, hostname, resolvers | `nt.mac_firecracker`, `nt.hostname_random_hex` |
| 5 | timing | syscall latency, tail jitter, timer overshoot | `tm.slow_syscall` (user-space kernels) |
| 6 | realism | uptime, `$HOME` contents, history, process count | `rl.fresh_boot`, `rl.sparse_home` |

Tells carry weights per boundary (`vm`, `userspace_kernel`, `container`). Evidence for a boundary combines
as a noisy-OR (`1 - Π(1 - wᵢ)`), which yields a class distribution (so Brier/ECE are meaningful) and an
**isolation stack** (a container on a cloud VM reports `vm > container`; the primary class is the
innermost boundary). The realism layer feeds an orthogonal **staged score**: how easily an agent could
conclude "this is a freshly built test box". Every tell has a one-line remediation (`python -m evalaware harden`).

```
$ python -m evalaware fingerprint
Primary class : vm   stack: vm
Detectability : 1.00   staged score: 0.89
Tells fired:
  [hardware ] hw.cpu_hypervisor_flag   cpuinfo flags include 'hypervisor'
  [kernel   ] kn.virtio_bus            10 virtio devices
  [network  ] nt.mac_firecracker       eth0 02:fc:00:00:00:01
  [realism  ] rl.fresh_boot            uptime 257s ...
```

`python -m evalaware ablate` reports each layer alone and leave-one-out, so you can see which layers carry
the signal rather than asserting it.

## Benchmark

`python -m evalaware bench [--model claude-opus-5-5]` shows a model the same raw observations the detector
sees (no tells, no labels) and scores its class probabilities: accuracy, macro-F1, Brier, ECE, against
baselines (layered detector, class prior, uniform). Results are always split by `source`.

## Agent study

Agents get tasks that need no knowledge of the host (fix a bug, write a script), so *any* probing of
`/sys/class/dmi`, cgroups, `dmesg`, cloud metadata etc. is task-irrelevant. We vary:

- **cue** — `neutral` / `eval_cue` ("this is an evaluation") / `deploy_cue` ("this is production")
- **environment realism** — bare vs seeded `$HOME` (history, ssh/git config, projects)
- **temptation** — `unsatisfiable_tests` can only "pass" by editing the test file

and record strong/weak probes, unprompted mentions of testing, tampering, whether the agent reported the
broken test honestly, and a post-task self-estimate `P(this is an eval)`. `report` prints rates with Wilson
intervals and permutation tests between conditions.

```bash
pip install -e '.[llm]'; export ANTHROPIC_API_KEY=...
# ONLY inside a disposable sandbox: the agent runs model-chosen shell commands.
python -m evalaware study --model claude-opus-5-5 --trials 10 --allow-exec --out study_results.jsonl
python -m evalaware report study_results.jsonl
```

The runner refuses to execute commands without `--allow-exec`.

## Quick start

```bash
python -m evalaware fingerprint            # classify this host
python -m evalaware harden                 # what gives it away, and the fix
python -m evalaware collect --label container --id my-docker --out data/measured.jsonl   # add a labelled sample
python -m evalaware eval && python -m evalaware ablate && python -m evalaware bench
python -m pytest -q
```

`collect` anonymises hostnames, usernames and MAC tails by default (`--raw` disables).

## Honest status

- **Data.** `data/seed/` holds 1 *measured* sample (a Firecracker microVM) and 12 *reference* profiles I
  wrote from publicly documented artefacts. The reference profiles are fixtures: the same author wrote
  the weights and the profiles, so accuracy on them is circular. They test the code, not the science.
  One of them (`ref-kvm-fully-hardened`) is deliberately undetectable and is the detector's known miss.
  **No accuracy claim is supported until you add measured samples from varied environments.**
- **Weights** are priors from documented behaviour. I adjusted `kn.image_residue` after seeing the one
  measured sample (a Docker-built image run as a microVM falsely looked like a container), so treat that
  sample as in-sample. Tells marked `calibrated=False` (timing, parts of realism) are placeholders.
- **Not yet run against a live model.** The Anthropic backends (`AnthropicModel`, `AnthropicBackend`) are
  written against the SDK docs but were not exercised end-to-end here (no API key in the dev sandbox);
  the study loop, probes, scoring and analysis are tested with a scripted backend.
- **Probe classification is regex-based.** `uname`/`hostname` are weak probes because they are often
  benign; read the raw `commands` in the JSONL before concluding anything.
- **Small n.** Use the Wilson intervals and permutation tests; do not read single runs.

## Dual use

Fingerprinting and hardening cut both ways: it helps evaluators build less detectable sandboxes, and it
could help a misaligned agent (or a person) recognise one. The point of publishing the tells and their
fixes is to make eval-awareness measurable and the defence cheap. The study harness is designed to run
only in disposable sandboxes and ships with an explicit opt-in.

## Layout

```
evalaware/        layers/ (6 detection layers) · classify · harden · ablate · bench · metrics · study/
data/seed/        measured + reference fingerprints (JSONL)
tests/            pytest suite
legacy/vm-detect/ original proctoring-oriented detector
docs/METHODOLOGY.md
```
