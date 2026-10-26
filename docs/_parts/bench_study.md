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

