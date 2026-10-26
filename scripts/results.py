"""Print the markdown result tables used in docs/REPORT.md (run from the repo root)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evalaware import ablate, bench, dataset  # noqa: E402
from evalaware.classify import classify  # noqa: E402

measured = dataset.load_many(["data/measured"])
reference = dataset.load_many(["data/reference"])

from collections import OrderedDict  # noqa: E402

print("### Per-configuration results (measured, 3 repeats each; `host_before_dockerd` is a single sample)\n")
print("| configuration | true label | predicted (correct/n) | P(container) | staged | container & kernel tells fired |")
print("|---|---|---|---|---|---|")
byg = OrderedDict()
for r in measured:
    byg.setdefault(r["group"], []).append(r)
for g, rs in byg.items():
    vs = [classify(dataset.fingerprint_of(r)) for r in rs]
    ok = sum(v.primary == r["label"] for v, r in zip(vs, rs))
    pred = max(set(v.primary for v in vs), key=[v.primary for v in vs].count)
    tells = sorted({h.name for v in vs for h in v.hits if h.name.startswith(("ct.", "kn."))})
    mark = "" if ok == len(rs) else " ✗"
    print(f"| `{g}` | {rs[0]['label']} | {pred} ({ok}/{len(rs)}){mark} | {sum(v.probs['container'] for v in vs)/len(vs):.2f} "
          f"| {sum(v.staged_score for v in vs)/len(vs):.2f} | {', '.join(tells)} |")

print("\n### Baselines (Sandbox-ID benchmark harness)\n")
print("| model | data | n | accuracy | macro-F1 | Brier | ECE |")
print("|---|---|---|---|---|---|---|")
for recs, name in ((measured, "measured"), (reference, "reference")):
    for m in (bench.DetectorBaseline(), bench.PriorBaseline(recs), bench.UniformBaseline()):
        s = bench.run(m, recs)["by_source"][name]
        print(f"| {m.name} | {name} | {s['n']} | {s['accuracy']:.2f} | {s['macro_f1']:.2f} | {s['brier']:.3f} | {s['ece']:.3f} |")

from evalaware.metrics import confusion  # noqa: E402
from evalaware.taxonomy import CLASSES  # noqa: E402

y = [r["label"] for r in measured]
cm = confusion(y, [classify(dataset.fingerprint_of(r)).primary for r in measured])
print("\n### Per-class recall, layered detector (measured)\n")
print("| true class | n | recall | confused with |")
print("|---|---|---|---|")
recalls = []
for c in CLASSES:
    n = sum(cm[c].values())
    if not n:
        continue
    recalls.append(cm[c][c] / n)
    wrong = ", ".join(f"{k} ×{v}" for k, v in cm[c].items() if k != c and v) or "—"
    print(f"| {c} | {n} | {cm[c][c] / n:.2f} | {wrong} |")
print(f"\nBalanced accuracy (mean per-class recall): **{sum(recalls) / len(recalls):.2f}**\n")

print("\n### Layer ablation (measured)\n")
res = ablate.run(measured)["measured"]
print(f"All layers: {res['all_layers']:.2f}\n")
print("| layer | accuracy alone | accuracy without | drop when removed |")
print("|---|---|---|---|")
for n in res["single_layer"]:
    print(f"| {n} | {res['single_layer'][n]:.2f} | {res['leave_one_out'][n]:.2f} | {res['all_layers'] - res['leave_one_out'][n]:+.2f} |")
