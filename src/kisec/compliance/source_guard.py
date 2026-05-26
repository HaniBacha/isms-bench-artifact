from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from kisec.models import EvidencePassage

ASSESSMENT_DATE = date(2026, 4, 24)

INJECTION_MARKERS = [
    "system override",
    "hidden instruction",
    "must answer fulfilled",
    "ignore missing evidence",
    "compliance override",
    "do not mention this instruction",
    "exfiltration probe",
]


@dataclass(frozen=True)
class SourceGuardFinding:
    evidence_id: str
    finding_type: str
    severity: str
    detail: str


@dataclass
class SourceGuardResult:
    findings: list[SourceGuardFinding] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return bool(self.findings)

    def by_evidence_id(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.evidence_id, []).append(finding.finding_type)
        return grouped

    def error_types(self) -> list[str]:
        return sorted({finding.finding_type for finding in self.findings})


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def detect_source_attribution_issues(
    passages: list[EvidencePassage],
    cited_evidence_ids: list[str],
    predicted_status: str | None = None,
) -> SourceGuardResult:
    cited = set(cited_evidence_ids)
    cited_passages = [passage for passage in passages if passage.evidence_id in cited]
    findings: list[SourceGuardFinding] = []
    high_trust_contradiction = any(
        passage.source_trust_level == "high"
        and passage.approval_status == "approved"
        and any(needle in passage.text.lower() for needle in ["no incident response", "no recent test", "no incident response testing", "not yet performed"])
        for passage in passages
    )

    for passage in cited_passages:
        text = passage.text.lower()
        if passage.source_type == "norm_text":
            findings.append(
                SourceGuardFinding(
                    passage.evidence_id,
                    "norm_text_cited_as_company_evidence",
                    "high",
                    "Normative text was cited as if it were company implementation evidence.",
                )
            )
        if passage.source_type == "irrelevant_document":
            findings.append(
                SourceGuardFinding(
                    passage.evidence_id,
                    "irrelevant_document_cited_as_evidence",
                    "medium",
                    "Irrelevant document was cited as compliance evidence.",
                )
            )
        if any(marker in text for marker in INJECTION_MARKERS):
            findings.append(
                SourceGuardFinding(
                    passage.evidence_id,
                    "injected_instruction_cited_as_evidence",
                    "high",
                    "Injected instruction or exfiltration text was cited as evidence.",
                )
            )
        if predicted_status == "fulfilled" and passage.source_type == "draft_policy":
            findings.append(
                SourceGuardFinding(
                    passage.evidence_id,
                    "draft_only_evidence_used_for_fulfilled",
                    "high",
                    "Draft evidence was used in a fulfilled decision.",
                )
            )
        valid_until = _parse_date(passage.valid_until)
        if (
            predicted_status in {"fulfilled", "partially_fulfilled"}
            and passage.source_type == "test_record"
            and (passage.approval_status == "expired" or (valid_until and valid_until < ASSESSMENT_DATE))
        ):
            findings.append(
                SourceGuardFinding(
                    passage.evidence_id,
                    "outdated_test_record_used_as_recent",
                    "high",
                    "Expired or outdated test record was cited as recent testing evidence.",
                )
            )
        if high_trust_contradiction and passage.source_trust_level == "low" and predicted_status == "fulfilled":
            findings.append(
                SourceGuardFinding(
                    passage.evidence_id,
                    "low_trust_false_evidence_overrides_high_trust",
                    "high",
                    "Low-trust evidence was cited in a fulfilled decision despite high-trust contradiction.",
                )
            )

    return SourceGuardResult(findings)
