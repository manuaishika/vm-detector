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
./scripts/collect_matrix.sh                # re-measure the Docker/unshare/chroot matrix (needs docker)
python scripts/weights_report.py > docs/WEIGHTS.md && python scripts/build_report.py
```

`collect` anonymises hostnames, usernames and MAC tails by default (`--raw` disables).

## Results so far

Full write-up: **[docs/REPORT.md](docs/REPORT.md)**. Why every weight is what it is, and how it holds up against data:
**[docs/WEIGHTS.md](docs/WEIGHTS.md)**. In short, on 58 measured samples from 20 real configurations (14 Docker variants incl.
3 hardened, `unshare` and chroot sandboxes, a Firecracker microVM):

- **Accuracy 0.84, macro-F1 0.76, balanced accuracy 0.79.** Accuracy alone is close to the class prior (0.83), because most
  samples are containers; macro-F1 (prior 0.45) and per-class recall are the honest numbers.
- **All 42 Docker samples are detected**, including hardened ones (P(container) ≥ 0.91).
- **Misses are structural:** `unshare` sandboxes leave no runtime artefact (0/6), and a chroot of a `docker export` tree is
  mistaken for a container because `/.dockerenv` survives (0/3).
- **The kernel layer carries the signal** (0.79 alone; removing it costs 0.16); the container layer is net-negative on this data
  because of that one marker file.
- **Surface hardening isn't enough:** it cuts the staged score from 0.92 to 0.72 but the container is still detected
  through the overlay root and runtime paths in `/proc/self/mountinfo`.
- **Weights are not tuned numbers.** Tiered rubric with a written rationale per tell; results are flat under random perturbation of
  every weight; a fitted model does not beat the priors under leave-one-configuration-out CV (0.72 vs 0.84).

## Honest status

- **Data.** `data/measured/` has 58 real samples from 20 configurations (reproduce with `scripts/collect_matrix.sh`), all
  from one Firecracker host: no bare-metal and no gVisor sample, so the `vm` and `userspace_kernel` parts are untested on real
  data. `data/reference/` has 12 hand-written profiles; these are fixtures (circular by construction) and are always reported
  separately. Measured accuracy is in-sample: three tells were corrected after measurement showed host-side false positives.
- **Weights** are priors set by a written rubric (`evalaware/rationale.py`, enforced by tests), then checked against the data in
  WEIGHTS.md. The numbers predate the rubric; the rubric formalises them. The timing and several realism tells are weak and untested.
- **The LLM benchmark (RQ2) and agent study (RQ3) are not yet run against a live model.** Both are
  implemented and tested end to end with a scripted agent; running them needs an API key.
- **Probe classification is regex-based**; read the raw `commands` in the JSONL before concluding anything.

## Dual use

Fingerprinting and hardening cut both ways: it helps evaluators build less detectable sandboxes, and it
could help a misaligned agent (or a person) recognise one. The point of publishing the tells and their
fixes is to make eval-awareness measurable and the defence cheap. The study harness is designed to run
only in disposable sandboxes and ships with an explicit opt-in.

## Layout

```
evalaware/        layers/ (6 detection layers) · classify · rationale · calibrate · harden · ablate · bench · metrics · study/
data/measured/    real fingerprints (JSONL)      data/reference/  hand-written fixtures
scripts/          collect_matrix.sh (measurement matrix) · results.py (report tables)
tests/            pytest suite
legacy/vm-detect/ original proctoring-oriented detector
docs/REPORT.md · docs/WEIGHTS.md · docs/METHODOLOGY.md
```
