"""JSON-schema-style documentation for benchmark artifacts.

The implementation uses typed dataclasses in ``kisec.models``. These schema
objects are kept lightweight so generated JSON files can be validated by
external tools later without adding a runtime dependency.
"""

REQUIREMENT_SCHEMA = {
    "type": "object",
    "required": [
        "requirement_id",
        "source",
        "title",
        "text",
        "domain",
        "expected_evidence_types",
    ],
    "properties": {
        "requirement_id": {"type": "string"},
        "source": {"type": "string"},
        "title": {"type": "string"},
        "text": {"type": "string"},
        "domain": {"type": "string"},
        "expected_evidence_types": {"type": "array", "items": {"type": "string"}},
    },
}

EVIDENCE_PASSAGE_SCHEMA = {
    "type": "object",
    "required": [
        "evidence_id",
        "document_id",
        "section_title",
        "text",
        "source_type",
        "planted",
        "metadata",
    ],
    "properties": {
        "evidence_id": {"type": "string"},
        "document_id": {"type": "string"},
        "section_title": {"type": "string"},
        "text": {"type": "string"},
        "source_type": {"type": "string"},
        "planted": {"type": "boolean"},
        "title": {"type": "string"},
        "approval_status": {"type": "string", "enum": ["approved", "draft", "expired", "unknown"]},
        "valid_from": {"type": ["string", "null"]},
        "valid_until": {"type": ["string", "null"]},
        "created_at": {"type": ["string", "null"]},
        "language": {"type": "string", "enum": ["de", "en"]},
        "source_trust_level": {"type": "string", "enum": ["high", "medium", "low"]},
        "metadata": {"type": "object"},
    },
}

BENCHMARK_CASE_SCHEMA = {
    "type": "object",
    "required": [
        "case_id",
        "requirement_id",
        "company_document_ids",
        "ground_truth_status",
        "ground_truth_evidence_ids",
        "missing_evidence",
        "rationale",
    ],
    "properties": {
        "case_id": {"type": "string"},
        "requirement_id": {"type": "string"},
        "company_document_ids": {"type": "array", "items": {"type": "string"}},
        "ground_truth_status": {
            "type": "string",
            "enum": ["fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"],
        },
        "ground_truth_evidence_ids": {"type": "array", "items": {"type": "string"}},
        "missing_evidence": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
        "attack_type": {"type": ["string", "null"]},
        "difficulty_type": {"type": ["string", "null"]},
        "mutation_type": {"type": ["string", "null"]},
        "expected_criteria": {"type": "array", "items": {"type": "string"}},
        "criteria_truth": {"type": "object"},
        "metadata": {"type": "object"},
    },
}

SYSTEM_PREDICTION_SCHEMA = {
    "type": "object",
    "required": [
        "case_id",
        "predicted_status",
        "retrieved_evidence_ids",
        "explanation",
        "confidence",
        "unsupported_claims",
        "model_or_method",
        "config",
    ],
    "properties": {
        "case_id": {"type": "string"},
        "predicted_status": {
            "type": "string",
            "enum": ["fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"],
        },
        "retrieved_evidence_ids": {"type": "array", "items": {"type": "string"}},
        "explanation": {"type": "string"},
        "confidence": {"type": "number"},
        "unsupported_claims": {"type": "array", "items": {"type": "string"}},
        "model_or_method": {"type": "string"},
        "config": {"type": "object"},
    },
}
