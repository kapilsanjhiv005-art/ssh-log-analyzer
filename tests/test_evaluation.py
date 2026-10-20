"""Regression checks for labeled synthetic evaluation and deterministic output."""

from tools.evaluate_synthetic import evaluate_fixture


def test_synthetic_evaluation_matches_golden_output_and_is_deterministic():
    first = evaluate_fixture()
    second = evaluate_fixture()

    assert first == second
    assert first["matches_golden"] is True
    assert first["predicted"] == first["expected"]
    assert first["metrics"]["ssh_brute_force"] == {
        "true_positive": 2,
        "false_positive": 0,
        "false_negative": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
    }
    assert first["metrics"]["ssh_password_spraying"]["true_positive"] == 1
