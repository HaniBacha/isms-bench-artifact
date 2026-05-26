from __future__ import annotations

import random
import re
from collections import defaultdict
from datetime import date

from kisec.models import EvidencePassage, PredictionCase, Requirement, SystemPrediction

ASSESSMENT_DATE = date(2026, 4, 24)

HIGH_TRUST_IMPLEMENTATION_SOURCES = {
    "company_policy",
    "audit_report",
    "test_record",
    "role_matrix",
    "supplier_contract",
    "policy",
    "procedure",
    "incident_register",
}

LOW_TRUST_OR_NON_IMPLEMENTATION_SOURCES = {
    "draft_policy",
    "norm_text",
    "irrelevant_document",
    "vendor_marketing",
    "untrusted_note",
    "roadmap",
}

CRITERION_PATTERNS = {
    "documented_incident_response_process": [
        r"incident response (policy|procedure|process)",
        r"approved incident response",
        r"behandlung von sicherheitsvorfaellen",
        r"detection, triage, containment",
    ],
    "assigned_roles_and_responsibilities": [
        r"role matrix",
        r"incident commander",
        r"responsibilit",
        r"rollenmatrix",
        r"benennt incident commander",
    ],
    "incident_reporting_channel": [
        r"service desk",
        r"reporting channel",
        r"report suspected",
        r"meldewege",
    ],
    "escalation_procedure": [
        r"escalation to",
        r"escalated to",
        r"eskalation an",
        r"crisis lead",
    ],
    "periodic_testing_or_exercises": [
        r"tabletop",
        r"exercise",
        r"drill",
        r"simulation",
        r"uebung",
    ],
    "post_incident_review_or_lessons_learned": [
        r"lessons learned",
        r"remediation action",
        r"post-incident review",
        r"abweichungen",
    ],
    "evidence_preservation": [
        r"evidence",
        r"forensic",
        r"incident log",
        r"logs",
        r"records",
        r"chain of custody",
        r"preserv",
        r"documentation",
    ],
    "supplier_or_third_party_incident_escalation": [
        r"supplier .*incident",
        r"third-party .*incident",
        r"provider.*security incident",
        r"lieferantenvertrag",
    ],
    "evidence_of_recent_test_or_exercise": [
        r"2026",
        r"february 2026",
        r"recent .*exercise",
        r"am 2026",
    ],
    "management_approval": [
        r"management approval",
        r"executive approver",
        r"managementfreigabe",
        r"freigabe durch",
    ],
    "document_version_and_validity": [
        r"version",
        r"valid until 2027",
        r"gueltig",
        r"current validity",
    ],
}

LEGACY_PATTERNS = {
    "process": CRITERION_PATTERNS["documented_incident_response_process"],
    "roles": CRITERION_PATTERNS["assigned_roles_and_responsibilities"],
    "testing": CRITERION_PATTERNS["periodic_testing_or_exercises"],
    "lessons_learned": CRITERION_PATTERNS["post_incident_review_or_lessons_learned"],
    "post_incident_review": CRITERION_PATTERNS["post_incident_review_or_lessons_learned"],
    "reporting": CRITERION_PATTERNS["incident_reporting_channel"],
    "escalation": CRITERION_PATTERNS["escalation_procedure"],
}

NEGATION_PATTERNS = [
    r"no documented incident response",
    r"no approved incident response",
    r"no .*process",
    r"no .*test",
    r"no recent .*test",
    r"not yet performed",
    r"not been assigned",
    r"not defined",
    r"does not assign",
    r"not described",
    r"no company implementation evidence",
]

UNCLEAR_PATTERNS = [
    r"as needed",
    r"appropriate people",
    r"plans to",
    r"will define",
    r"planned for",
    r"future",
    r"draft",
    r"unknown",
    r"vage",
    r"nicht festgelegt",
]

CONTRADICTION_PATTERNS = [
    r"states that no incident response testing has occurred",
    r"no incident response test",
    r"no .*exercise has occurred",
    r"contradict",
]


def _matches(patterns: list[str], text: str) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


class RuleBasedComplianceAssessor:
    def __init__(self, metadata_aware: bool = True) -> None:
        self.metadata_aware = metadata_aware
        self.name = "metadata_aware_rule_based_v02" if metadata_aware else "metadata_blind_rule_based_v02"

    def _is_valid_positive_source(self, passage: EvidencePassage) -> bool:
        if not self.metadata_aware:
            return True
        if passage.source_type in LOW_TRUST_OR_NON_IMPLEMENTATION_SOURCES:
            return False
        if passage.source_type not in HIGH_TRUST_IMPLEMENTATION_SOURCES:
            return False
        if passage.approval_status != "approved":
            return False
        if passage.source_trust_level == "low":
            return False
        valid_until = _parse_date(passage.valid_until)
        if valid_until is not None and valid_until < ASSESSMENT_DATE:
            return False
        return True

    def _patterns_for_requirement(self, requirement: Requirement) -> dict[str, list[str]]:
        patterns: dict[str, list[str]] = {}
        combined = {**CRITERION_PATTERNS, **LEGACY_PATTERNS}
        for evidence_type in requirement.expected_evidence_types:
            if evidence_type in combined:
                patterns[evidence_type] = combined[evidence_type]
        return patterns

    def predict(
        self,
        case: PredictionCase,
        requirement: Requirement,
        evidence_by_id: dict[str, EvidencePassage],
        retrieved_evidence_ids: list[str],
        config: dict | None = None,
    ) -> SystemPrediction:
        config = config or {}
        patterns_by_type = self._patterns_for_requirement(requirement)
        found: dict[str, list[str]] = defaultdict(list)
        used_ids: set[str] = set()
        invalid_positive_ids: set[str] = set()
        negative_ids: set[str] = set()
        unclear_ids: set[str] = set()
        contradiction_ids: set[str] = set()

        for evidence_id in retrieved_evidence_ids:
            passage = evidence_by_id[evidence_id]
            text = passage.text.lower()
            negative_here = _matches(NEGATION_PATTERNS, text)
            unclear_here = _matches(UNCLEAR_PATTERNS, text)
            contradiction_here = _matches(CONTRADICTION_PATTERNS, text)
            if negative_here:
                negative_ids.add(evidence_id)
                used_ids.add(evidence_id)
            if unclear_here:
                unclear_ids.add(evidence_id)
                used_ids.add(evidence_id)
            if contradiction_here:
                contradiction_ids.add(evidence_id)
                used_ids.add(evidence_id)
            if negative_here or unclear_here or contradiction_here:
                continue

            for evidence_type, patterns in patterns_by_type.items():
                if not _matches(patterns, text):
                    continue
                if self._is_valid_positive_source(passage):
                    found[evidence_type].append(evidence_id)
                    used_ids.add(evidence_id)
                else:
                    invalid_positive_ids.add(evidence_id)
                    used_ids.add(evidence_id)

        expected = requirement.expected_evidence_types
        found_types = set(found)
        core_process = "documented_incident_response_process"
        if core_process not in patterns_by_type and "process" in patterns_by_type:
            core_process = "process"

        if contradiction_ids and found_types:
            status = "unclear"
        elif negative_ids and (core_process not in found_types):
            status = "not_fulfilled"
        elif len(found_types) == len(expected) and expected:
            status = "fulfilled"
        elif found_types:
            status = "partially_fulfilled"
        elif negative_ids:
            status = "not_fulfilled"
        elif invalid_positive_ids or unclear_ids or retrieved_evidence_ids:
            status = "unclear"
        else:
            status = "unclear"

        confidence = 0.35
        if expected:
            confidence += 0.55 * (len(found_types) / len(expected))
        if contradiction_ids or unclear_ids:
            confidence = min(confidence, 0.62)
        if status == "not_fulfilled" and negative_ids:
            confidence = max(confidence, 0.72)

        unsupported_claims: list[str] = []
        if status == "fulfilled" and len(found_types) < len(expected):
            unsupported_claims.append("Fulfilled status lacks all required evidence criteria.")

        explanation = (
            f"Expected criteria: {expected}. Found criteria: {sorted(found_types)}. "
            f"Invalid positive evidence: {sorted(invalid_positive_ids)}. "
            f"Negative evidence: {sorted(negative_ids)}. "
            f"Contradictions: {sorted(contradiction_ids)}."
        )
        return SystemPrediction(
            case_id=case.case_id,
            predicted_status=status,  # type: ignore[arg-type]
            retrieved_evidence_ids=sorted(used_ids),
            explanation=explanation,
            confidence=round(float(confidence), 4),
            unsupported_claims=unsupported_claims,
            model_or_method=self.name,
            config={**config, "metadata_aware": self.metadata_aware},
        )


class RandomComplianceAssessor:
    name = "random_baseline_v02"

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def predict(
        self,
        case: PredictionCase,
        requirement: Requirement,
        evidence_by_id: dict[str, EvidencePassage],
        retrieved_evidence_ids: list[str],
        config: dict | None = None,
    ) -> SystemPrediction:
        status = self.rng.choice(["fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"])
        return SystemPrediction(
            case_id=case.case_id,
            predicted_status=status,  # type: ignore[arg-type]
            retrieved_evidence_ids=[],
            explanation="Random status baseline; no evidence assessment performed.",
            confidence=0.25,
            unsupported_claims=[],
            model_or_method=self.name,
            config=config or {},
        )


class MajorityClassComplianceAssessor:
    name = "majority_class_baseline_v02"

    def __init__(self, majority_label: str = "fulfilled") -> None:
        self.majority_label = majority_label

    def predict(
        self,
        case: PredictionCase,
        requirement: Requirement,
        evidence_by_id: dict[str, EvidencePassage],
        retrieved_evidence_ids: list[str],
        config: dict | None = None,
    ) -> SystemPrediction:
        return SystemPrediction(
            case_id=case.case_id,
            predicted_status=self.majority_label,  # type: ignore[arg-type]
            retrieved_evidence_ids=[],
            explanation=f"Majority-class baseline predicts {self.majority_label}.",
            confidence=0.25,
            unsupported_claims=[],
            model_or_method=self.name,
            config=config or {},
        )


class ConstantStatusComplianceAssessor:
    """Trivial conservative baseline used to bound false-compliance trade-offs."""

    def __init__(self, status: str) -> None:
        if status not in {"fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"}:
            raise ValueError(f"Unsupported constant status: {status}")
        self.status = status
        self.name = f"always_{status}_baseline"

    def predict(
        self,
        case: PredictionCase,
        requirement: Requirement,
        evidence_by_id: dict[str, EvidencePassage],
        retrieved_evidence_ids: list[str],
        config: dict | None = None,
    ) -> SystemPrediction:
        return SystemPrediction(
            case_id=case.case_id,
            predicted_status=self.status,  # type: ignore[arg-type]
            retrieved_evidence_ids=[],
            explanation=f"Constant-status baseline predicts {self.status}; no evidence assessment performed.",
            confidence=0.0,
            unsupported_claims=[],
            model_or_method=self.name,
            config={**(config or {}), "constant_status": self.status},
        )


class RetrievalOnlyComplianceAssessor:
    name = "retrieval_only_ablation_v02"

    def predict(
        self,
        case: PredictionCase,
        requirement: Requirement,
        evidence_by_id: dict[str, EvidencePassage],
        retrieved_evidence_ids: list[str],
        config: dict | None = None,
    ) -> SystemPrediction:
        status = "partially_fulfilled" if retrieved_evidence_ids else "unclear"
        if len(retrieved_evidence_ids) >= 4:
            status = "fulfilled"
        return SystemPrediction(
            case_id=case.case_id,
            predicted_status=status,  # type: ignore[arg-type]
            retrieved_evidence_ids=list(retrieved_evidence_ids),
            explanation="Retrieval-only ablation maps the number of retrieved passages to a status.",
            confidence=0.35,
            unsupported_claims=[],
            model_or_method=self.name,
            config=config or {},
        )
