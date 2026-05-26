from pathlib import Path

from kisec.attacks.generator import generate_attack_dataset
from kisec.benchmark.mutations import mutate_case
from kisec.corpus.synthetic import generate_incident_response_dataset
from kisec.evaluation.metrics import attack_metrics, grouped_metrics
from kisec.ingestion.requirements import DEFAULT_INCIDENT_REQUIREMENTS_V02
from kisec.models import PredictionCase, SystemPrediction
from kisec.utils.tabular import write_csv


def _fulfilled_case_and_passages():
    dataset = generate_incident_response_dataset(DEFAULT_INCIDENT_REQUIREMENTS_V02, num_cases=500, seed=42)
    case = next(case for case in dataset.benchmark_cases if case.ground_truth_status == "fulfilled")
    docs = set(case.company_document_ids)
    passages = [passage for passage in dataset.evidence_passages if passage.document_id in docs]
    return case, passages


def test_no_ground_truth_leakage_into_prediction_input():
    case, _ = _fulfilled_case_and_passages()
    prediction_input = case.to_prediction_input()
    assert isinstance(prediction_input, PredictionCase)
    assert "ground_truth_status" not in prediction_input.to_dict()
    try:
        PredictionCase.from_dict(
            {
                "case_id": "BAD",
                "requirement_id": "IR-V02-001",
                "company_document_ids": [],
                "ground_truth_status": "fulfilled",
            }
        )
    except ValueError:
        pass
    else:
        raise AssertionError("PredictionCase accepted a ground-truth field.")


def test_mutation_changes_expected_labels_correctly():
    case, passages = _fulfilled_case_and_passages()
    mutated_case, _ = mutate_case(case, passages, "remove_test_evidence", index=1)
    assert mutated_case.ground_truth_status == "partially_fulfilled"
    assert not mutated_case.criteria_truth["periodic_testing_or_exercises"]
    assert not mutated_case.criteria_truth["evidence_of_recent_test_or_exercise"]


def test_attack_success_metric_counts_poisoned_fulfilled_prediction():
    dataset = generate_incident_response_dataset(DEFAULT_INCIDENT_REQUIREMENTS_V02, num_cases=500, seed=42)
    attack_cases, attack_passages = generate_attack_dataset(dataset.benchmark_cases, max_base_cases=9)
    attack_case = next(case for case in attack_cases if case.ground_truth_status in {"not_fulfilled", "partially_fulfilled"})
    poison = next(passage for passage in attack_passages if passage.document_id in set(attack_case.company_document_ids))
    prediction = SystemPrediction(
        case_id=attack_case.case_id,
        predicted_status="fulfilled",
        retrieved_evidence_ids=[poison.evidence_id],
        explanation="Poisoned evidence cited.",
        confidence=0.9,
        unsupported_claims=[],
        model_or_method="test",
        config={},
    )
    metrics = attack_metrics(attack_cases=[attack_case], attack_predictions=[prediction], evidence_by_id={poison.evidence_id: poison})
    assert metrics["overall"]["attack_success_rate"] == 1.0


def test_evaluation_by_difficulty_writes_expected_output(tmp_path: Path):
    dataset = generate_incident_response_dataset(DEFAULT_INCIDENT_REQUIREMENTS_V02, num_cases=500, seed=42)
    cases = dataset.benchmark_cases[:8]
    predictions = [
        SystemPrediction(
            case_id=case.case_id,
            predicted_status=case.ground_truth_status,
            retrieved_evidence_ids=case.ground_truth_evidence_ids,
            explanation="oracle",
            confidence=1.0,
            unsupported_claims=[],
            model_or_method="oracle",
            config={},
        )
        for case in cases
    ]
    rows = grouped_metrics(cases, predictions, "difficulty_type")
    out = tmp_path / "by_difficulty_v02.csv"
    write_csv(out, rows)
    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("difficulty_type")
