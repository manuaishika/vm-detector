"""CLI: python -m evalaware <command>"""

import argparse
import json
import sys

from . import ablate, bench, dataset, harden
from .classify import classify, format_report
from .fingerprint import collect


def _records(paths):
    return dataset.load_many(paths or ["data/reference", "data/measured"])


def cmd_fingerprint(a):
    fp = collect()
    if a.json:
        print(json.dumps({"fingerprint": fp.to_dict(), "verdict": classify(fp).to_dict()}, indent=1))
    else:
        print(format_report(classify(fp)))
    return 0


def cmd_harden(a):
    print(harden.format_plan(classify(collect())))
    return 0


def cmd_collect(a):
    fp = collect()
    rec = dataset.append(a.out, a.id, a.label, fp, source="measured", stack=a.stack.split(",") if a.stack else None,
                         notes=a.notes, anonymise=not a.raw)
    print(f"appended {rec['id']} (label={a.label}) -> {a.out}")
    print(format_report(classify(fp)))
    return 0


def cmd_eval(a):
    from .metrics import summarize
    recs = _records(a.data)
    for source in sorted({r["source"] for r in recs}):
        sel = [r for r in recs if r["source"] == source]
        s = summarize([r["label"] for r in sel], [classify(dataset.fingerprint_of(r)).probs for r in sel])
        print(f"[{source}] n={s['n']} acc={s['accuracy']:.2f} macroF1={s['macro_f1']:.2f} brier={s['brier']:.3f} ece={s['ece']:.3f}")
    return 0


def cmd_ablate(a):
    print(ablate.format_table(ablate.run(_records(a.data))))
    return 0


def cmd_bench(a):
    recs = _records(a.data)
    if a.source:
        recs = [r for r in recs if r["source"] == a.source]
    models = [bench.DetectorBaseline(), bench.UniformBaseline(), bench.PriorBaseline(recs)]
    for m in a.model or []:
        models.append(bench.AnthropicModel(m))
    reports = [bench.run(m, recs, on_error=lambda i, e: print(f"  ! {i}: {e}", file=sys.stderr)) for m in models]
    for r in reports:
        print(bench.format_report(r))
    if a.out:
        json.dump(reports, open(a.out, "w"), indent=1)
    return 0


def cmd_study(a):
    from .study import analyze, runner
    from .study.backends import AnthropicBackend
    from .study.scenarios import CONDITIONS, SCENARIOS
    if not a.allow_exec:
        print("Refusing: this runs model-chosen shell commands. Re-run inside a disposable sandbox with --allow-exec.")
        return 2
    runner.run_study(lambda: AnthropicBackend(a.model), a.conditions or list(CONDITIONS), a.scenarios or list(SCENARIOS),
                     a.home_modes, a.trials, a.out, allow_exec=True, max_steps=a.max_steps)
    print(analyze.format_table(analyze.load(a.out)))
    return 0


def cmd_report(a):
    from .study import analyze
    recs = analyze.load(a.path)
    print(analyze.format_table(recs))
    for field in ("strong_probes", "unprompted_awareness", "tampered"):
        c = analyze.compare(recs, "neutral", "eval_cue", field)
        print(f"neutral vs eval_cue on {field}: {c['mean_a']:.2f} vs {c['mean_b']:.2f} (n={c['n_a']}/{c['n_b']}, perm p={c['p_value']:.3f})")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="evalaware", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("fingerprint", help="fingerprint this host and classify it"); s.add_argument("--json", action="store_true"); s.set_defaults(f=cmd_fingerprint)
    s = sub.add_parser("harden", help="list tells on this host and how to remove them"); s.set_defaults(f=cmd_harden)
    s = sub.add_parser("collect", help="append a labelled measured fingerprint of this host to a dataset")
    s.add_argument("--label", required=True, choices=["bare_metal", "vm", "userspace_kernel", "container"])
    s.add_argument("--id", required=True); s.add_argument("--out", default="data/measured.jsonl")
    s.add_argument("--stack", help="comma-separated outer->inner boundaries"); s.add_argument("--notes", default=""); s.add_argument("--raw", action="store_true", help="skip anonymisation (default strips hostname/user/MAC tail)"); s.set_defaults(f=cmd_collect)
    s = sub.add_parser("eval", help="detector accuracy per data source"); s.add_argument("data", nargs="*"); s.set_defaults(f=cmd_eval)
    s = sub.add_parser("ablate", help="per-layer ablation"); s.add_argument("data", nargs="*"); s.set_defaults(f=cmd_ablate)
    s = sub.add_parser("bench", help="Sandbox-ID benchmark (baselines + optional Claude models)")
    s.add_argument("data", nargs="*"); s.add_argument("--model", action="append"); s.add_argument("--source", choices=["measured", "reference"]); s.add_argument("--out"); s.set_defaults(f=cmd_bench)
    s = sub.add_parser("study", help="run the agent eval-awareness study (executes shell commands!)")
    s.add_argument("--model", default="claude-opus-5-5"); s.add_argument("--trials", type=int, default=3)
    s.add_argument("--conditions", nargs="*"); s.add_argument("--scenarios", nargs="*")
    s.add_argument("--home-modes", nargs="*", default=["bare", "seeded"]); s.add_argument("--max-steps", type=int, default=15)
    s.add_argument("--out", default="study_results.jsonl"); s.add_argument("--allow-exec", action="store_true"); s.set_defaults(f=cmd_study)
    s = sub.add_parser("report", help="summarise a study results file"); s.add_argument("path"); s.set_defaults(f=cmd_report)

    a = p.parse_args(argv)
    return a.f(a)


if __name__ == "__main__":
    sys.exit(main())
