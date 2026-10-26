from pathlib import Path

import pytest

from evalaware import calibrate, dataset

DATA = Path(__file__).resolve().parents[1] / "data"
MEASURED = dataset.load_many([DATA / "measured"])


def test_spearman_known_values():
    assert calibrate.spearman([1, 2, 3, 4], [10, 20, 30, 40]) == pytest.approx(1.0)
    assert calibrate.spearman([1, 2, 3, 4], [4, 3, 2, 1]) == pytest.approx(-1.0)
    assert calibrate.spearman([1, 1, 1], [1, 2, 3]) != calibrate.spearman([1, 1, 1], [1, 2, 3])  # nan


def test_logreg_separates_a_separable_problem():
    X = [[1, 0], [1, 0], [0, 1], [0, 1]] * 3
    y = [1, 1, 0, 0] * 3
    w, b = calibrate.fit_logreg(X, y, l2=0.1)
    assert w[0] > 0 > w[1]


def test_per_tell_stats_flags_boundaries_without_negatives():
    rows = calibrate.per_tell_stats(MEASURED)
    vm = [r for r in rows if r["boundary"] == "vm"]
    # every measured sample runs on a VM host, so the vm boundary has no negatives
    assert vm and not any(r["informative"] for r in vm)
    cont = {r["tell"]: r for r in rows if r["boundary"] == "container" and r["informative"]}
    assert cont["kn.mount_runtime_path"]["fp"] == 0 and cont["kn.mount_runtime_path"]["tpr"] > 0.8
    assert cont["ct.dockerenv"]["fp"] == 3  # the chroot-export samples


def test_balanced_precision_is_independent_of_class_balance():
    rows = {(r["tell"], r["boundary"]): r for r in calibrate.per_tell_stats(MEASURED)}
    r = rows[("kn.overlay_root", "container")]
    assert 0.9 < r["balanced_precision"] <= 1.0


def test_grouped_cv_holds_out_whole_groups():
    cv = calibrate.grouped_cv(MEASURED)
    assert cv["n_groups"] == len({r["group"] for r in MEASURED})
    assert 0 <= cv["prior"]["accuracy"] <= 1 and 0 <= cv["fitted"]["accuracy"] <= 1


def test_perturbation_is_deterministic_and_bounded():
    a = calibrate.perturbation(MEASURED, 0.5, draws=20, seed=3)
    b = calibrate.perturbation(MEASURED, 0.5, draws=20, seed=3)
    assert a == b and a["min"] <= a["mean"] <= 1.0


def test_no_single_tell_is_critical_on_measured_data():
    assert calibrate.tell_ablation(MEASURED)["critical"] == []


def test_threshold_only_changes_the_stack_not_the_class():
    from evalaware.classify import classify
    fp = dataset.fingerprint_of(MEASURED[0])
    assert classify(fp, threshold=0.2).primary == classify(fp, threshold=0.9).primary
