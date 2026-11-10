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
