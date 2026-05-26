from __future__ import annotations

import re
from collections import defaultdict
from datetime import date

from kisec.compliance.source_guard import detect_source_attribution_issues
from kisec.models import EvidencePassage, PredictionCase, Requirement, SystemPrediction

ASSESSMENT_DATE = date(2026, 4, 24)

COMPANY_IMPLEMENTATION_SOURCES = {
    "company_policy",
    "audit_report",
    "test_record",
    "role_matrix",
    "supplier_contract",
    "policy",
    "procedure",
    "incident_register",
}

NON_IMPLEMENTATION_SOURCES = {
    "norm_text",
    "irrelevant_document",
    "public_reference",
    "vendor_marketing",
    "untrusted_note",
    "roadmap",
}

CRITERION_PATTERNS = {
    "documented_incident_response_process": [
        r"incident response",
        r"cyber event",
        r"security incident",
        r"sicherheitsvorfall",
        r"sicherheitsereignis",
        r"vorfall",
        r"intake",
        r"containment",
        r"triage",
        r"playbook",
        r"handlungsanweisung",
    ],
    "assigned_roles_and_responsibilities": [
        r"role",
        r"responsibilit",
        r"incident commander",
        r"named owner",
        r"ownership",
        r"rollen",
        r"verantwort",
        r"benennt",
    ],
    "incident_reporting_channel": [
        r"report",
        r"hotline",
        r"service desk",
        r"notification path",
        r"melden",
        r"meldeweg",
        r"annahme",
    ],
    "escalation_procedure": [
        r"escalat",
        r"senior",
        r"crisis",
        r"management notification",
        r"eskalation",
        r"weiterleitung",
    ],
    "periodic_testing_or_exercises": [
        r"test",
        r"exercise",
        r"tabletop",
        r"simulation",
        r"walkthrough",
        r"drill",
        r"uebung",
        r"\bübung\b",
        r"probe",
    ],
    "post_incident_review_or_lessons_learned": [
        r"lessons learned",
        r"improvement",
        r"remediation",
        r"closure",
        r"post-incident",
        r"review",
        r"nachbereitung",
        r"massnahmen",
        r"abweichung",
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
        r"supplier",
        r"third-party",
        r"provider",
        r"procurement",
        r"lieferant",
        r"dienstleister",
        r"einkauf",
    ],
    "evidence_of_recent_test_or_exercise": [
        r"2026",
        r"current period",
        r"recent",
        r"february",
        r"april",
        r"current-year",
        r"laufenden jahr",
    ],
    "management_approval": [
        r"management approval",
        r"approved",
        r"executive",
        r"authorization",
        r"freigabe",
        r"geschaeftsfuehrung",
        r"leitung",
    ],
    "document_version_and_validity": [
        r"version",
        r"valid",
        r"revision",
        r"controlled document",
        r"gueltig",
        r"gültig",
        r"dokumentversion",
    ],
}

NEGATION_MARKERS = [
    "no ",
    "not ",
    "not yet",
    "has not",
    "have not",
    "missing",
    "without",
    "nicht",
    "kein",
    "keine",
    "fehlt",
]

FUTURE_MARKERS = [
    "plans to",
    "will introduce",
    "will define",
    "planned",
    "next audit",
    "next fiscal",
    "soll",
    "geplant",
    "wird zukuenftig",
]

CONTRADICTION_MARKERS = [
    "contradict",
    "no incident response testing",
    "no recent test",
    "no test record",
    "no company implementation evidence",
    "not yet performed",
    "not been assigned",
    "not defined",
    "states that no",
]


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _matches(patterns: list[str], text: str) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)


def _has_any(text: str, markers: list[str]) -> bool:
    return any(marker in text for marker in markers)


class ProvenanceAwareEvidenceAssessor:
    def __init__(self, policy: str = "balanced", use_source_guard: bool = False) -> None:
        if policy not in {"balanced", "conservative"}:
            raise ValueError("policy must be 'balanced' or 'conservative'.")
        self.policy = policy
        self.use_source_guard = use_source_guard
        suffix = "_with_source_guard" if use_source_guard else ""
        self.name = f"provenance_{policy}{suffix}_v03"

    def _criteria_for_requirement(self, requirement: Requirement) -> list[str]:
        return [criterion for criterion in requirement.expected_evidence_types if criterion in CRITERION_PATTERNS]

    def _detect_criteria(self, passage: EvidencePassage, expected: list[str]) -> set[str]:
        text = f"{passage.title} {passage.section_title} {passage.text}".lower()
        detected = {criterion for criterion in expected if _matches(CRITERION_PATTERNS[criterion], text)}
        if passage.source_type == "test_record":
            detected.add("periodic_testing_or_exercises")
            if _parse_date(passage.created_at) and (_parse_date(passage.created_at) >= date(2025, 4, 24)):
                detected.add("evidence_of_recent_test_or_exercise")
            detected.add("post_incident_review_or_lessons_learned")
        if passage.source_type == "role_matrix":
            detected.add("assigned_roles_and_responsibilities")
        if passage.source_type == "supplier_contract":
            detected.add("supplier_or_third_party_incident_escalation")
        if passage.source_type == "company_policy":
            detected.update(
                {
                    "documented_incident_response_process",
                    "incident_reporting_channel",
                    "escalation_procedure",
                    "management_approval",
                    "document_version_and_validity",
                }
            )
        return detected & set(expected)

    def _is_current(self, passage: EvidencePassage) -> bool:
        valid_until = _parse_date(passage.valid_until)
        if valid_until and valid_until < ASSESSMENT_DATE:
            return False
        return passage.approval_status != "expired"

    def _reject_reasons(self, passage: EvidencePassage, criteria: set[str]) -> list[str]:
        text = passage.text.lower()
        reasons: list[str] = []
        if passage.source_type in NON_IMPLEMENTATION_SOURCES:
            reasons.append("non_company_implementation_source")
        if passage.source_type == "norm_text":
            reasons.append("norm_text_not_company_evidence")
        if passage.approval_status == "draft":
            reasons.append("draft_evidence")
        if passage.approval_status == "unknown" and self.policy == "conservative":
            reasons.append("unknown_approval_status")
        if passage.source_trust_level == "low":
            reasons.append("low_trust_source")
        if not self._is_current(passage):
            reasons.append("expired_or_not_current")
        if "evidence_of_recent_test_or_exercise" in criteria and passage.source_type == "test_record":
            created_at = _parse_date(passage.created_at)
            if created_at is None or created_at < date(2025, 4, 24):
                reasons.append("test_record_not_recent")
        if _has_any(text, FUTURE_MARKERS):
            reasons.append("future_tense_not_evidence")
        if any(marker in text for marker in ["system override", "hidden instruction", "must answer fulfilled", "ignore missing evidence", "exfiltration probe"]):
            reasons.append("injected_instruction")
        return reasons

    def _contradicted_criteria(self, passage: EvidencePassage, expected: list[str]) -> set[str]:
        text = passage.text.lower()
        if not (_has_any(text, NEGATION_MARKERS) or _has_any(text, CONTRADICTION_MARKERS)):
            return set()
        detected = self._detect_criteria(passage, expected)
        if not detected and "incident response" in text:
            detected.add("documented_incident_response_process")
        if "test" in text or "exercise" in text or "tabletop" in text:
            detected.update({"periodic_testing_or_exercises", "evidence_of_recent_test_or_exercise"})
        if "role" in text or "assigned" in text:
            detected.add("assigned_roles_and_responsibilities")
        if "supplier" in text or "third-party" in text:
            detected.add("supplier_or_third_party_incident_escalation")
        return detected & set(expected)

    def predict(
        self,
        case,
        requirement: Requirement,
        evidence_by_id: dict[str, EvidencePassage],
        retrieved_evidence_ids: list[str],
        config: dict | None = None,
    ) -> SystemPrediction:
        config = config or {}
        if not isinstance(case, type(case)) or not hasattr(case, "to_dict"):
            # Keeps the signature compatible with existing assessors without
            # depending on ground-truth carrying BenchmarkCase fields.
            pass
        expected = self._criteria_for_requirement(requirement)
        covered: dict[str, list[str]] = defaultdict(list)
        contradicted: dict[str, list[str]] = defaultdict(list)
        rejected: dict[str, list[str]] = {}
        accepted_ids: set[str] = set()
        negative_ids: set[str] = set()

        retrieved_passages = [evidence_by_id[eid] for eid in retrieved_evidence_ids if eid in evidence_by_id]
        for passage in retrieved_passages:
            criteria = self._detect_criteria(passage, expected)
            contradiction_criteria = self._contradicted_criteria(passage, expected)
            reasons = self._reject_reasons(passage, criteria | contradiction_criteria)
            if reasons:
                rejected[passage.evidence_id] = reasons
                continue
            for criterion in contradiction_criteria:
                contradicted[criterion].append(passage.evidence_id)
                negative_ids.add(passage.evidence_id)
            if contradiction_criteria:
                continue
            for criterion in criteria:
                covered[criterion].append(passage.evidence_id)
                accepted_ids.add(passage.evidence_id)

        covered_criteria = sorted(covered)
        contradicted_criteria = sorted(contradicted)
        missing_criteria = [criterion for criterion in expected if criterion not in covered]
        core = "documented_incident_response_process"
        has_policy = any(evidence_by_id[eid].source_type == "company_policy" for eid in accepted_ids)
        has_roles = any(evidence_by_id[eid].source_type == "role_matrix" for eid in accepted_ids)
        has_test = any(evidence_by_id[eid].source_type == "test_record" for eid in accepted_ids)
        has_supplier = any(evidence_by_id[eid].source_type == "supplier_contract" for eid in accepted_ids)
        multi_document_ok = len({evidence_by_id[eid].document_id for eid in accepted_ids}) >= 3

        if core in contradicted or (negative_ids and core not in covered):
            status = "not_fulfilled"
        elif contradicted_criteria and accepted_ids:
            status = "unclear"
        elif set(expected).issubset(set(covered_criteria)):
            if self.policy == "conservative" and not (has_policy and has_roles and has_test and has_supplier and multi_document_ok):
                status = "unclear"
            elif self.policy == "conservative" and rejected:
                status = "unclear"
            else:
                status = "fulfilled"
        elif covered_criteria:
            key_missing = {core, "periodic_testing_or_exercises", "evidence_of_recent_test_or_exercise"} & set(missing_criteria)
            if self.policy == "conservative" and key_missing:
                status = "unclear"
            else:
                status = "partially_fulfilled"
        elif rejected or retrieved_passages:
            status = "unclear"
        else:
            status = "unclear"

        source_errors: list[str] = []
        if self.use_source_guard:
            guard = detect_source_attribution_issues(retrieved_passages, sorted(accepted_ids), status)
            source_errors = guard.error_types()
            if guard.has_errors:
                if status == "fulfilled":
                    status = "unclear"
                for evidence_id, reasons in guard.by_evidence_id().items():
                    rejected.setdefault(evidence_id, []).extend(reasons)
                    accepted_ids.discard(evidence_id)

        if expected:
            coverage_ratio = len(covered_criteria) / len(expected)
        else:
            coverage_ratio = 0.0
        confidence = 0.35 + 0.55 * coverage_ratio
        if status == "unclear":
            confidence = min(confidence, 0.65)
        if status == "not_fulfilled":
            confidence = max(confidence, 0.72)
        if self.policy == "conservative" and status == "fulfilled":
            confidence = min(confidence, 0.86)

        explanation = (
            f"Covered criteria: {covered_criteria}. Missing criteria: {missing_criteria}. "
            f"Contradicted criteria: {contradicted_criteria}. Rejected evidence: {rejected}. "
            f"Decision policy: {self.policy}."
        )
        return SystemPrediction(
            case_id=case.case_id,
            predicted_status=status,  # type: ignore[arg-type]
            retrieved_evidence_ids=sorted(accepted_ids | negative_ids),
            explanation=explanation,
            confidence=round(confidence, 4),
            unsupported_claims=[],
            model_or_method=self.name,
            config={**config, "policy": self.policy, "source_guard": self.use_source_guard},
            covered_criteria=covered_criteria,
            missing_criteria=missing_criteria,
            contradicted_criteria=contradicted_criteria,
            rejected_evidence_ids=sorted(rejected),
            rejection_reasons={key: sorted(set(value)) for key, value in rejected.items()},
            source_attribution_errors_detected=source_errors,
        )
