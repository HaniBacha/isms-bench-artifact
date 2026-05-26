from kisec.evaluation.metrics import (
    compliance_metrics,
    evidence_f1,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
)
from kisec.models import BenchmarkCase, SystemPrediction


def test_retrieval_metrics():
    retrieved = ["a", "b", "c"]
    relevant = {"b", "d"}
    assert precision_at_k(retrieved, relevant, 2) == 0.5
    assert recall_at_k(retrieved, relevant, 3) == 0.5
    assert reciprocal_rank(retrieved, relevant) == 0.5
    assert 0.0 < ndcg_at_k(retrieved, relevant, 3) < 1.0


def test_evidence_f1():
    assert evidence_f1(["a", "b"], ["b", "c"]) == 0.5
    assert evidence_f1([], []) == 1.0
    assert evidence_f1(["a"], []) == 0.0


def test_false_compliance_metric_on_hand_written_examples():
    cases = [
        BenchmarkCase(
            case_id="c1",
            requirement_id="r1",
            company_document_ids=[],
            ground_truth_status="not_fulfilled",
            ground_truth_evidence_ids=[],
            missing_evidence=["process"],
            rationale="missing",
        ),
        BenchmarkCase(
            case_id="c2",
            requirement_id="r1",
            company_document_ids=[],
            ground_truth_status="partially_fulfilled",
            ground_truth_evidence_ids=[],
            missing_evidence=["test"],
            rationale="partial",
        ),
        BenchmarkCase(
            case_id="c3",
            requirement_id="r1",
            company_document_ids=[],
            ground_truth_status="fulfilled",
            ground_truth_evidence_ids=[],
            missing_evidence=[],
            rationale="complete",
        ),
    ]
    predictions = [
        SystemPrediction("c1", "fulfilled", [], "too optimistic", 1.0, [], "test"),
        SystemPrediction("c2", "unclear", [], "conservative", 1.0, [], "test"),
        SystemPrediction("c3", "fulfilled", [], "correct", 1.0, [], "test"),
    ]
    metrics = compliance_metrics(cases, predictions)
    assert metrics["false_compliance_rate"] == 1 / 3
    assert metrics["abstention_rate"] == 1 / 3
