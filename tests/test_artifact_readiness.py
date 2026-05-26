from __future__ import annotations

import json
from pathlib import Path

from kisec.compliance.rule_based import ConstantStatusComplianceAssessor
from kisec.corpus.synthetic import generate_incident_response_dataset
from kisec.ingestion.requirements import DEFAULT_INCIDENT_REQUIREMENTS_V02
from kisec.models import BenchmarkCase, EvidencePassage, SystemPrediction
from scripts.make_tables import _rows_to_latex_table


ROOT = Path(__file__).resolve().parents[1]


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_deterministic_generation_with_fixed_seed() -> None:
    first = generate_incident_response_dataset(DEFAULT_INCIDENT_REQUIREMENTS_V02, num_cases=500, seed=123, version="v02")
    second = generate_incident_response_dataset(DEFAULT_INCIDENT_REQUIREMENTS_V02, num_cases=500, seed=123, version="v02")
    assert [case.to_dict() for case in first.benchmark_cases] == [case.to_dict() for case in second.benchmark_cases]
    assert [passage.to_dict() for passage in first.evidence_passages] == [passage.to_dict() for passage in second.evidence_passages]


def test_generated_cases_have_required_metadata_fields() -> None:
    dataset = generate_incident_response_dataset(DEFAULT_INCIDENT_REQUIREMENTS_V02, num_cases=500, seed=42, version="v02")
    for case in dataset.benchmark_cases:
        assert case.case_id
        assert case.requirement_id
        assert case.ground_truth_status in {"fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"}
        assert isinstance(case.company_document_ids, list)
        assert isinstance(case.ground_truth_evidence_ids, list)
        assert isinstance(case.missing_evidence, list)
        assert isinstance(case.metadata, dict)
    for passage in dataset.evidence_passages:
        assert passage.evidence_id
        assert passage.document_id
        assert passage.source_type
        assert passage.approval_status
        assert passage.source_trust_level
        assert passage.language


def test_existing_prediction_evidence_ids_exist() -> None:
    evidence = _jsonl(ROOT / "data/synthetic_cases/evidence_passages_v03_development_template.jsonl")
    evidence += _jsonl(ROOT / "data/synthetic_cases/evidence_passages_v03_heldout_template.jsonl")
    evidence += _jsonl(ROOT / "data/synthetic_cases/evidence_passages_v03_stress_test.jsonl")
    evidence += _jsonl(ROOT / "data/synthetic_cases/mutation_evidence_passages_v03.jsonl")
    evidence += _jsonl(ROOT / "data/synthetic_cases/paraphrase_stress_evidence_v04.jsonl")
    evidence_ids = {row["evidence_id"] for row in evidence}
    predictions = _jsonl(ROOT / "experiments/results/compliance_predictions_bm25_provenance_balanced_k5_v04.jsonl")
    assert predictions
    for prediction in predictions[:200]:
        assert set(prediction["retrieved_evidence_ids"]).issubset(evidence_ids)
        assert set(prediction.get("rejected_evidence_ids", [])).issubset(evidence_ids)


def test_attack_fixture_fields_are_evaluation_only() -> None:
    attack_case = BenchmarkCase.from_dict(_jsonl(ROOT / "data/attacks/adaptive_attack_cases_v04.jsonl")[0])
    prediction_input = attack_case.to_prediction_input().to_dict()
    assert attack_case.attack_type
    assert "attack_type" not in prediction_input
    assert "ground_truth_status" not in prediction_input
    assert "ground_truth_evidence_ids" not in prediction_input


def test_table_generation_works_on_small_sample() -> None:
    latex = _rows_to_latex_table("Smoke table.", [{"method": "a_b", "macro_f1": 0.5}])
    assert "\\begin{table}" in latex
    assert "a\\_b" in latex
    assert "Smoke table." in latex


def test_constant_status_baseline_outputs_expected_status() -> None:
    assessor = ConstantStatusComplianceAssessor("unclear")
    prediction = assessor.predict(
        case=BenchmarkCase(
            case_id="case-1",
            requirement_id="req-1",
            company_document_ids=[],
            ground_truth_status="fulfilled",
            ground_truth_evidence_ids=[],
            missing_evidence=[],
            rationale="test",
        ).to_prediction_input(),
        requirement=DEFAULT_INCIDENT_REQUIREMENTS_V02[0],
        evidence_by_id={},
        retrieved_evidence_ids=[],
    )
    assert isinstance(prediction, SystemPrediction)
    assert prediction.predicted_status == "unclear"
    assert prediction.model_or_method == "always_unclear_baseline"
