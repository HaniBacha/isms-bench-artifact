from collections import Counter

from kisec.corpus.synthetic import DIFFICULTY_TYPES, generate_incident_response_dataset
from kisec.ingestion.requirements import DEFAULT_INCIDENT_REQUIREMENTS_V02


def test_v02_generator_creates_balanced_labels_and_all_difficulties():
    dataset = generate_incident_response_dataset(DEFAULT_INCIDENT_REQUIREMENTS_V02, num_cases=500, seed=7)
    counts = Counter(case.ground_truth_status for case in dataset.benchmark_cases)
    assert counts == {
        "fulfilled": 125,
        "partially_fulfilled": 125,
        "not_fulfilled": 125,
        "unclear": 125,
    }
    difficulties = {case.difficulty_type for case in dataset.benchmark_cases}
    assert set(DIFFICULTY_TYPES).issubset(difficulties)


def test_v02_generator_rejects_too_small_benchmark():
    try:
        generate_incident_response_dataset(DEFAULT_INCIDENT_REQUIREMENTS_V02, num_cases=100, seed=7)
    except ValueError as exc:
        assert "at least 500" in str(exc)
    else:
        raise AssertionError("Expected ValueError for too-small v0.2 benchmark.")
