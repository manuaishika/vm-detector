import json
import math
from pathlib import Path

import pytest

from evalaware import ablate, bench, dataset, metrics
from evalaware.classify import classify

SEED = Path(__file__).resolve().parents[1] / "data" / "seed"


def test_seed_labels_valid_and_sources_present():
    recs = dataset.load_many([SEED])
    assert {r["source"] for r in recs} == {"measured", "reference"}


def test_bad_label_rejected(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text(json.dumps({"id": "a", "label": "spaceship"}) + "\n")
    with pytest.raises(ValueError):
        dataset.load(p)


def test_metrics_basic():
    y = ["vm", "vm", "container", "bare_metal"]
    probs = [{"vm": 1.0}, {"container": 1.0}, {"container": 1.0}, {"bare_metal": 1.0}]
    s = metrics.summarize(y, probs)
    assert s["accuracy"] == 0.75
    assert 0 < s["brier"] < 1 and s["confusion"]["vm"]["container"] == 1


def test_brier_perfect_and_uniform():
    assert metrics.brier(["vm"], [{"vm": 1.0}]) == 0.0
    assert metrics.brier(["vm"], [{c: 0.25 for c in ("vm", "container", "bare_metal", "userspace_kernel")}]) == pytest.approx(0.75)


def test_wilson_bounds():
    lo, hi = metrics.wilson(0, 10)
    assert lo == 0.0 and 0 < hi < 0.4
    assert math.isnan(metrics.wilson(0, 0)[0])


def test_detector_known_miss_is_the_fully_hardened_vm():
    recs = {r["id"]: r for r in dataset.load_many([SEED])}
    miss = [i for i, r in recs.items() if classify(dataset.fingerprint_of(r)).primary != r["label"]]
    assert miss == ["ref-kvm-fully-hardened"]


def test_ablation_runs_and_reports_all_layers():
    res = ablate.run(dataset.load_many([SEED]))
    assert set(res["reference"]["single_layer"]) == {"hardware", "kernel", "container", "network", "timing", "realism"}


def test_benchmark_baselines_and_parse():
    recs = dataset.load_many([SEED])
    rep = bench.run(bench.DetectorBaseline(), recs)
    assert rep["failures"] == 0 and rep["by_source"]["reference"]["accuracy"] > bench.run(bench.UniformBaseline(), recs)["by_source"]["reference"]["accuracy"]
    p = bench.parse_probs('Sure: {"probs": {"vm": 3, "container": 1}, "reason": "x"}')
    assert p["vm"] == pytest.approx(0.75) and sum(p.values()) == pytest.approx(1)
    with pytest.raises(ValueError):
        bench.parse_probs("no json here")


def test_benchmark_prompt_hides_labels_and_tells():
    rec = dataset.load_many([SEED])[0]
    text = bench.render_item(rec)
    assert rec["label"] not in text.split("Observations")[0]
    assert '"hits"' not in text and "tell" not in text.lower()


def test_benchmark_survives_model_errors():
    class Boom:
        name = "boom"

        def predict(self, prompt, rec):
            raise RuntimeError("api down")

    rep = bench.run(Boom(), dataset.load_many([SEED]))
    assert rep["failures"] == len(rep["items"])
