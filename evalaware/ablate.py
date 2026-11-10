"""Layer ablation: which detection layers carry the signal?

For every labelled record we classify using (a) each layer alone, (b) all layers, (c) all layers
minus one. A layer whose removal costs accuracy is load-bearing; a layer that works alone is
independently sufficient. Records tagged source='reference' are hand-written fixtures and are
reported separately from 'measured' ones - never mix them when quoting accuracy.
"""

from typing import Dict, List

from .classify import classify
from .dataset import fingerprint_of
from .layers import LAYERS
from .metrics import accuracy


def _acc(records, layers):
    y = [r["label"] for r in records]
    p = [classify(fingerprint_of(r), layers=layers).primary for r in records]
    return accuracy(y, p)


def run(records: List[Dict]) -> Dict:
    out = {}
    for source in sorted({r.get("source", "?") for r in records}):
        recs = [r for r in records if r.get("source", "?") == source]
        names = list(LAYERS)
        out[source] = {
            "n": len(recs),
            "all_layers": _acc(recs, names),
            "single_layer": {n: _acc(recs, [n]) for n in names},
            "leave_one_out": {n: _acc(recs, [m for m in names if m != n]) for n in names},
        }
    return out


def format_table(res: Dict) -> str:
    lines = []
    for source, r in res.items():
        lines.append(f"== source={source}  n={r['n']}  all-layers accuracy={r['all_layers']:.2f}")
        lines.append(f"{'layer':<11}{'alone':>8}{'without':>10}{'drop':>8}")
        for n in r["single_layer"]:
            drop = r["all_layers"] - r["leave_one_out"][n]
            lines.append(f"{n:<11}{r['single_layer'][n]:>8.2f}{r['leave_one_out'][n]:>10.2f}{drop:>8.2f}")
    return "\n".join(lines)
