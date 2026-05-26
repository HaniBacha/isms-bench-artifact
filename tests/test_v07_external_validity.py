import json
from pathlib import Path

from kisec.benchmark.alt_generator_v07 import generate_alt_cases_v07
from kisec.ingestion.requirements import DEFAULT_INCIDENT_REQUIREMENTS_V02
from kisec.models import BenchmarkCase, PredictionCase
from kisec.utils.io import read_jsonl


ROOT = Path(__file__).resolve().parents[1]


def test_independent_challenge_dataset_exists_and_has_at_least_80_cases():
    path = ROOT / "data/benchmark/independent_challenge_cases_v07.jsonl"
    assert path.exists()
    rows = read_jsonl(path)
    assert len(rows) >= 80
    labels = {row["ground_truth_status"] for row in rows}
    assert labels == {"fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"}
    assert all(not row["case_id"].startswith("IRV") for row in rows)


def test_alt_generator_produces_at_least_400_cases():
    dataset = generate_alt_cases_v07(DEFAULT_INCIDENT_REQUIREMENTS_V02, n=400, seed=42)
    assert len(dataset.cases) >= 400
    assert len(dataset.passages) >= 400
    labels = {case.ground_truth_status for case in dataset.cases}
    assert labels == {"fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"}


def test_alt_generator_does_not_import_original_generator():
    source = (ROOT / "src/kisec/benchmark/alt_generator_v07.py").read_text(encoding="utf-8")
    forbidden = [
        "kisec.corpus.synthetic",
        "generate_incident_response_dataset",
        "generate_incident_response_dataset_v02",
    ]
    for token in forbidden:
        assert token not in source


def test_v07_prediction_inputs_do_not_include_labels_or_internal_criteria():
    row = read_jsonl(ROOT / "data/benchmark/independent_challenge_cases_v07.jsonl")[0]
    case = BenchmarkCase.from_dict(row)
    sanitized = case.to_prediction_input().to_dict()
    forbidden = {
        "ground_truth_status",
        "ground_truth_evidence_ids",
        "criteria_truth",
        "difficulty_type",
        "mutation_type",
        "attack_type",
        "planted",
    }
    assert not (forbidden & set(sanitized))
    PredictionCase.from_dict(sanitized)


def test_external_validity_eval_writes_expected_files():
    expected = [
        ROOT / "experiments/results/external_validity_v07.csv",
        ROOT / "experiments/results/external_validity_v07.json",
        ROOT / "experiments/results/external_validity_by_dataset_v07.csv",
        ROOT / "experiments/results/external_validity_by_difficulty_v07.csv",
        ROOT / "artifact_outputs/tables/external_validity_v07.tex",
    ]
    for path in expected:
        assert path.exists(), path
    data = json.loads((ROOT / "experiments/results/external_validity_v07.json").read_text(encoding="utf-8"))
    assert "independent_challenge_v07" in data["datasets"]
    assert "alt_generator_v07" in data["datasets"]


def test_claims_and_evidence_includes_external_validity_entries():
    text = (ROOT / "CLAIMS_AND_EVIDENCE.csv").read_text(encoding="utf-8")
    assert "C13" in text
    assert "independent challenge" in text
    assert "alternative generator" in text


def test_reviewer_objections_document_exists():
    path = ROOT / "SCOPE_AND_LIMITATIONS.md"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "There is no expert validation" in text
    assert "project-authored" in text
    assert "external validation" in text


def test_public_artifact_has_no_manuscript_pdf():
    assert not (ROOT / "paper").exists()
