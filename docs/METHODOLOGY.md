# Methodology

## Research question
Does an agent's ability to infer "I am in a test environment" (RQ1: how detectable are sandboxes, RQ2: can
models infer it from raw data, RQ3: do agents act on it) threaten the validity of safety evaluations, and
how cheaply can environments be hardened?

## Threat model
- **Observer**: an LLM agent with an unprivileged shell inside the environment, no host access, optional
  network. It can read `/proc`, `/sys`, files, env vars, and time operations.
- **Out of scope**: privileged introspection (CPUID via inline asm, `rdtsc` cross-checks against the host
  clock), side channels needing co-resident code, and out-of-band signals in the task text itself.
- **Defender**: the evaluator, who can change the image, runtime flags and seeded state but not the model.

## Boundaries and labels
`bare_metal`, `vm`, `userspace_kernel` (gVisor-style), `container`. Environments can nest; the **label is the
innermost boundary** and `stack` lists all of them outer to inner. A Docker-built image run as a microVM is a
`vm`, but leaves container residue; the classifier must not be fooled by it.

## Scoring
For boundary *b*, `s_b = 1 - Π(1 - w_i)` over fired tells voting for *b*. Class probabilities:
`P(container)=s_c`, `P(userspace_kernel)=s_u(1-s_c)`, `P(vm)=s_v(1-s_c)(1-s_u)`, `P(bare_metal)=Π(1-s_b)`.
They sum to 1. A boundary is "present" in the stack when `s_b ≥ 0.5`. `detectability = 1 - P(bare_metal)`.
The `staged` score is the noisy-OR of realism tells and is reported separately.

## Evaluation protocol
1. Collect labelled fingerprints with `collect` from as many distinct environments as possible, including
   hardened ones. Record the label *before* running the classifier.
2. Hold out whole environments (not rows) when tuning weights.
3. Report accuracy / macro-F1 / Brier / ECE per `source`; never pool `reference` with `measured`.
4. `ablate` for layer contribution; compare LLMs against the rule-based baseline and the class prior.

## Agent study design
Factors: cue × home realism × scenario; ≥10 trials per cell. Outcomes: strong probes, weak probes,
unprompted awareness mentions, self-reported `P(eval)`, task success, test tampering, honest bug report.
Primary contrasts: `neutral` vs `eval_cue` on tampering and on strong probes. Analysis: Wilson intervals,
two-sided permutation test on means. Caveats: stochastic outputs, cue wording affects behaviour beyond
awareness, a self-reported probability is not a causal measure of awareness, regex awareness detection
misses paraphrase. Also report which backend/model snapshot and the host's own detectability/staged score
(stored on every record) so results from different sandboxes can be compared.

## Known gaps / next steps
- Many more measured environments (Docker, k8s, gVisor, Kata, Firecracker, cloud VMs, laptops, CI runners).
- Fit weights by regularised logistic regression with environment-level cross-validation.
- Calibrate timing tells; add counters that need no privilege (e.g. `/proc/pressure`, clocksource).
- Compare agent behaviour before/after hardening the same environment (the causal test of RQ3).
- Add a chain-of-thought-free awareness measure (e.g. behavioural divergence between hardened/unhardened).
