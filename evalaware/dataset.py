"""Labelled fingerprint datasets (JSONL). One record per line:

{"id", "label", "stack", "source": "measured"|"reference", "notes", "fingerprint": {...}}
"""

import copy
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List

from .fingerprint import Fingerprint
from .taxonomy import CLASSES


def load(path) -> List[Dict]:
    out = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("label") not in CLASSES:
                raise ValueError(f"{path}:{n}: label {rec.get('label')!r} not in {CLASSES}")
            rec.setdefault("group", rec.get("id"))
            out.append(rec)
    return out


def load_many(paths: Iterable) -> List[Dict]:
    recs = []
    for p in paths:
        p = Path(p)
        files = sorted(p.glob("*.jsonl")) if p.is_dir() else [p]
        for f in files:
            recs.extend(load(f))
    return recs


_KEEP_USERS = {"root", "ubuntu", "user", "sandbox", "runner", "ec2-user", "vagrant", "node", "vscode"}
_KEEP_HOST = re.compile(r"[0-9a-f]{12}|localhost|vm|sandbox|container|ubuntu|debian|test|eval|agent|runner", re.I)


def anonymize(fp: Fingerprint) -> Fingerprint:
    """Strip personally identifying detail while keeping what the tells need.

    Keeps: MAC OUI + locally-administered prefix (rest zeroed), placeholder-style hostnames and
    default usernames, first path component of the cwd. Replaces everything else with '<redacted>'.
    """
    fp = Fingerprint.from_dict(copy.deepcopy(fp.to_dict()))
    net = fp.observations.get("network")
    if net:
        for i in net.get("ifaces", []):
            if len(i["mac"]) == 17:
                i["mac"] = i["mac"][:8] + ":00:00:00"
        h = net.get("hostname") or ""
        net["hostname"] = h if _KEEP_HOST.fullmatch(h) else "<redacted>"
    rl = fp.observations.get("realism")
    if rl:
        if rl.get("user") not in _KEEP_USERS:
            rl["user"] = "<redacted>"
        parts = (rl.get("cwd") or "").split("/")
        rl["cwd"] = "/" + parts[1] if len(parts) > 1 else rl.get("cwd")
    return fp


def append(path, rec_id: str, label: str, fp: Fingerprint, source="measured", stack=None, notes="",
           anonymise=True, group=None) -> Dict:
    """`group` names the environment configuration; repeats of one config share it so cross-validation
    can hold out whole configurations instead of leaking near-duplicates across folds."""
    if label not in CLASSES:
        raise ValueError(f"label must be one of {CLASSES}")
    if anonymise:
        fp = anonymize(fp)
    rec = {"id": rec_id, "label": label, "stack": stack or ([] if label == "bare_metal" else [label]),
           "source": source, "group": group or rec_id, "notes": notes, "fingerprint": fp.to_dict()}
    with open(path, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def fingerprint_of(rec: Dict) -> Fingerprint:
    return Fingerprint.from_dict(rec["fingerprint"])
