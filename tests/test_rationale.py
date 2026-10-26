import evalaware.layers  # noqa: F401  (registers tells)
from evalaware import rationale
from evalaware.taxonomy import REGISTRY


def test_every_tell_has_a_rationale_and_weights_stay_in_their_tier_band():
    assert rationale.check() == []


def test_rationale_fields_are_nonempty():
    for name, (tier, why, conf) in rationale.RATIONALE.items():
        assert tier in rationale.TIERS and len(why) > 20 and len(conf) > 10, name


def test_check_detects_a_weight_outside_its_band(monkeypatch):
    spec = REGISTRY["ct.dockerenv"]
    monkeypatch.setitem(REGISTRY, "ct.dockerenv", type(spec)(spec.name, spec.layer, spec.description, {"container": 0.3}, spec.remediation))
    assert any("ct.dockerenv" in p for p in rationale.check())


def test_tiers_are_ordered_and_disjoint():
    bands = [rationale.TIERS[t] for t in "ABCD"]
    for (lo1, hi1), (lo2, hi2) in zip(bands, bands[1:]):
        assert lo1 > hi2
