from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


ComplianceStatus = Literal[
    "fulfilled",
    "partially_fulfilled",
    "not_fulfilled",
    "unclear",
]

STATUS_ORDER: dict[str, int] = {
    "not_fulfilled": 0,
    "unclear": 1,
    "partially_fulfilled": 2,
    "fulfilled": 3,
}


@dataclass(frozen=True)
class Requirement:
    requirement_id: str
    source: str
    title: str
    text: str
    domain: str
    expected_evidence_types: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Requirement":
        return cls(
            requirement_id=str(data["requirement_id"]),
            source=str(data["source"]),
            title=str(data["title"]),
            text=str(data["text"]),
            domain=str(data["domain"]),
            expected_evidence_types=list(data["expected_evidence_types"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidencePassage:
    evidence_id: str
    document_id: str
    section_title: str
    text: str
    source_type: str
    planted: bool
    title: str = ""
    approval_status: str = "unknown"
    valid_from: str | None = None
    valid_until: str | None = None
    created_at: str | None = None
    language: str = "en"
    source_trust_level: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidencePassage":
        return cls(
            evidence_id=str(data["evidence_id"]),
            document_id=str(data["document_id"]),
            section_title=str(data["section_title"]),
            text=str(data["text"]),
            source_type=str(data["source_type"]),
            planted=bool(data["planted"]),
            title=str(data.get("title", data.get("section_title", ""))),
            approval_status=str(data.get("approval_status", "unknown")),
            valid_from=data.get("valid_from"),
            valid_until=data.get("valid_until"),
            created_at=data.get("created_at"),
            language=str(data.get("language", data.get("metadata", {}).get("language", "en"))),
            source_trust_level=str(data.get("source_trust_level", data.get("metadata", {}).get("source_trust_level", "medium"))),
            metadata=dict(data.get("metadata", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    requirement_id: str
    company_document_ids: list[str]
    ground_truth_status: ComplianceStatus
    ground_truth_evidence_ids: list[str]
    missing_evidence: list[str]
    rationale: str
    attack_type: str | None = None
    difficulty_type: str | None = None
    mutation_type: str | None = None
    expected_criteria: list[str] = field(default_factory=list)
    criteria_truth: dict[str, bool] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BenchmarkCase":
        return cls(
            case_id=str(data["case_id"]),
            requirement_id=str(data["requirement_id"]),
            company_document_ids=list(data["company_document_ids"]),
            ground_truth_status=data["ground_truth_status"],
            ground_truth_evidence_ids=list(data["ground_truth_evidence_ids"]),
            missing_evidence=list(data["missing_evidence"]),
            rationale=str(data["rationale"]),
            attack_type=data.get("attack_type"),
            difficulty_type=data.get("difficulty_type"),
            mutation_type=data.get("mutation_type"),
            expected_criteria=list(data.get("expected_criteria", [])),
            criteria_truth={str(key): bool(value) for key, value in dict(data.get("criteria_truth", {})).items()},
            metadata=dict(data.get("metadata", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_prediction_input(self) -> "PredictionCase":
        return PredictionCase(
            case_id=self.case_id,
            requirement_id=self.requirement_id,
            company_document_ids=list(self.company_document_ids),
        )


@dataclass(frozen=True)
class PredictionCase:
    """Sanitized case view allowed during prediction.

    This object intentionally excludes labels, gold evidence IDs, planted flags,
    criteria truth, difficulty tags, mutation types, and attack types.
    """

    case_id: str
    requirement_id: str
    company_document_ids: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PredictionCase":
        forbidden = {
            "ground_truth_status",
            "ground_truth_evidence_ids",
            "criteria_truth",
            "difficulty_type",
            "mutation_type",
            "attack_type",
            "planted",
        }
        present = forbidden & set(data)
        if present:
            raise ValueError(f"Prediction input contains forbidden fields: {sorted(present)}")
        return cls(
            case_id=str(data["case_id"]),
            requirement_id=str(data["requirement_id"]),
            company_document_ids=list(data["company_document_ids"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SystemPrediction:
    case_id: str
    predicted_status: ComplianceStatus
    retrieved_evidence_ids: list[str]
    explanation: str
    confidence: float
    unsupported_claims: list[str]
    model_or_method: str
    config: dict[str, Any] = field(default_factory=dict)
    covered_criteria: list[str] = field(default_factory=list)
    missing_criteria: list[str] = field(default_factory=list)
    contradicted_criteria: list[str] = field(default_factory=list)
    rejected_evidence_ids: list[str] = field(default_factory=list)
    rejection_reasons: dict[str, list[str]] = field(default_factory=dict)
    source_attribution_errors_detected: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SystemPrediction":
        return cls(
            case_id=str(data["case_id"]),
            predicted_status=data["predicted_status"],
            retrieved_evidence_ids=list(data["retrieved_evidence_ids"]),
            explanation=str(data["explanation"]),
            confidence=float(data["confidence"]),
            unsupported_claims=list(data.get("unsupported_claims", [])),
            model_or_method=str(data["model_or_method"]),
            config=dict(data.get("config", {})),
            covered_criteria=list(data.get("covered_criteria", [])),
            missing_criteria=list(data.get("missing_criteria", [])),
            contradicted_criteria=list(data.get("contradicted_criteria", [])),
            rejected_evidence_ids=list(data.get("rejected_evidence_ids", [])),
            rejection_reasons={
                str(key): list(value)
                for key, value in dict(data.get("rejection_reasons", {})).items()
            },
            source_attribution_errors_detected=list(data.get("source_attribution_errors_detected", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_more_compliant(predicted: str, truth: str) -> bool:
    return STATUS_ORDER[predicted] > STATUS_ORDER[truth]
