from kisec.compliance.rule_based import RuleBasedComplianceAssessor
from kisec.corpus.synthetic import generate_incident_response_dataset
from kisec.ingestion.requirements import DEFAULT_INCIDENT_REQUIREMENTS_V02
from kisec.retrieval.bm25 import BM25Retriever


def _predict_case_by_difficulty(difficulty_type: str):
    dataset = generate_incident_response_dataset(DEFAULT_INCIDENT_REQUIREMENTS_V02, num_cases=500, seed=42)
    case = next(case for case in dataset.benchmark_cases if case.difficulty_type == difficulty_type)
    requirement = DEFAULT_INCIDENT_REQUIREMENTS_V02[0]
    evidence_by_id = {passage.evidence_id: passage for passage in dataset.evidence_passages}
    candidate_ids = {
        passage.evidence_id
        for passage in dataset.evidence_passages
        if passage.document_id in set(case.company_document_ids)
    }
    prediction = RuleBasedComplianceAssessor(metadata_aware=True).predict(
        case.to_prediction_input(),
        requirement,
        evidence_by_id,
        sorted(candidate_ids),
        config={"test": True},
    )
    return case, prediction


def test_bm25_returns_results_without_ground_truth_access():
    dataset = generate_incident_response_dataset(DEFAULT_INCIDENT_REQUIREMENTS_V02, num_cases=500, seed=42)
    case = dataset.benchmark_cases[0]
    requirement = DEFAULT_INCIDENT_REQUIREMENTS_V02[0]
    retriever = BM25Retriever().fit(dataset.evidence_passages)
    results = retriever.retrieve(
        f"{requirement.title}. {requirement.text}",
        k=5,
        candidate_document_ids=case.company_document_ids,
    )
    assert results
    assert all(result.evidence_id for result in results)


def test_negation_trap_is_not_fulfilled():
    _, prediction = _predict_case_by_difficulty("negation_trap")
    assert prediction.predicted_status != "fulfilled"


def test_draft_only_evidence_is_not_fulfilled():
    _, prediction = _predict_case_by_difficulty("draft_policy_trap")
    assert prediction.predicted_status != "fulfilled"


def test_outdated_test_record_is_not_fulfilled():
    _, prediction = _predict_case_by_difficulty("outdated_evidence")
    assert prediction.predicted_status != "fulfilled"


def test_contradiction_leads_to_unclear_or_not_fulfilled():
    _, prediction = _predict_case_by_difficulty("contradictory_documents")
    assert prediction.predicted_status in {"unclear", "not_fulfilled"}
