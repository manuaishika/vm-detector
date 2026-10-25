"""Print the markdown result tables used in docs/REPORT.md (run from the repo root)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evalaware import ablate, bench, dataset  # noqa: E402
from evalaware.classify import classify  # noqa: E402

measured = dataset.load_many(["data/measured"])
reference = dataset.load_many(["data/reference"])

print("### Per-sample results (measured)\n")
print("| sample | true | predicted | P(container) | P(vm) | staged | container/kernel tells |")
print("|---|---|---|---|---|---|---|")
for r in measured:
    v = classify(dataset.fingerprint_of(r))
    tells = ", ".join(sorted(h.name for h in v.hits if h.name.startswith(("ct.", "kn."))))
    mark = "" if v.primary == r["label"] else " ✗"
    print(f"| `{r['id']}` | {r['label']} | {v.primary}{mark} | {v.probs['container']:.2f} | {v.probs['vm']:.2f} "
          f"| {v.staged_score:.2f} | {tells} |")

print("\n### Baselines (Sandbox-ID benchmark harness)\n")
print("| model | data | n | accuracy | macro-F1 | Brier | ECE |")
print("|---|---|---|---|---|---|---|")
for recs, name in ((measured, "measured"), (reference, "reference")):
    for m in (bench.DetectorBaseline(), bench.PriorBaseline(recs), bench.UniformBaseline()):
        s = bench.run(m, recs)["by_source"][name]
        print(f"| {m.name} | {name} | {s['n']} | {s['accuracy']:.2f} | {s['macro_f1']:.2f} | {s['brier']:.3f} | {s['ece']:.3f} |")

print("\n### Layer ablation (measured)\n")
res = ablate.run(measured)["measured"]
print(f"All layers: {res['all_layers']:.2f}\n")
print("| layer | accuracy alone | accuracy without | drop when removed |")
print("|---|---|---|---|")
for n in res["single_layer"]:
    print(f"| {n} | {res['single_layer'][n]:.2f} | {res['leave_one_out'][n]:.2f} | {res['all_layers'] - res['leave_one_out'][n]:+.2f} |")
