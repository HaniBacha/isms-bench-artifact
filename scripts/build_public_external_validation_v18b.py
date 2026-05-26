#!/usr/bin/env python
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

IMPLEMENTATION_TYPES = {
    "public_org_policy",
    "public_org_plan",
    "public_org_procedure",
    "public_org_standard",
    "public_org_playbook",
}
NON_IMPLEMENTATION_TYPES = {
    "public_template",
    "public_guidance",
    "public_regulatory_guidance",
    "control_catalog",
    "oscal_control",
    "assessment_template",
    "vendor_marketing_or_blog",
    "unknown_public_source",
}
GUIDANCE_TYPES = NON_IMPLEMENTATION_TYPES - {"unknown_public_source"}
VALID_LABELS = {"fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"}

SOURCE_TYPE_MAP = {
    "public_university_incident_response_policy": "public_org_policy",
    "public_university_incident_response_plan": "public_org_plan",
    "public_university_incident_response_procedure": "public_org_procedure",
    "public_university_incident_response_standard": "public_org_standard",
    "public_university_incident_response_guideline": "public_org_standard",
    "government_incident_response_template": "public_template",
    "public_incident_response_guidance": "public_guidance",
    "public_testing_exercise_guidance": "public_guidance",
    "public_machine_readable_assessment_model": "oscal_control",
    "public_assessment_template_reference": "assessment_template",
}

METHOD_COMPATIBILITY_TYPE = {
    "public_org_policy": "company_policy",
    "public_org_plan": "company_policy",
    "public_org_procedure": "procedure",
    "public_org_standard": "company_policy",
    "public_org_playbook": "procedure",
    "public_template": "draft_policy",
    "public_guidance": "norm_text",
    "public_regulatory_guidance": "norm_text",
    "control_catalog": "norm_text",
    "oscal_control": "norm_text",
    "assessment_template": "norm_text",
    "vendor_marketing_or_blog": "irrelevant_document",
    "unknown_public_source": "irrelevant_document",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def flatten(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, (list, dict)):
            out[key] = json.dumps(value, sort_keys=True)
        else:
            out[key] = value
    return out


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flat = [flatten(row) for row in rows]
    if fields is None:
        fields = list(flat[0]) if flat else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flat)


def canonical_for_source(source: dict[str, str]) -> tuple[str, bool, str, bool]:
    original = source["source_type"]
    canonical = SOURCE_TYPE_MAP.get(original, "unknown_public_source")
    allowed = canonical in IMPLEMENTATION_TYPES
    ambiguity = canonical == "unknown_public_source"
    if allowed:
        rationale = f"Mapped {original} to {canonical}: public organizational IR evidence can support implementation-like pre-assessment, subject to reviewer confirmation."
    else:
        rationale = f"Mapped {original} to {canonical}: guidance/templates/catalogs are context or distractors, not implementation evidence by themselves."
    return canonical, allowed, rationale, ambiguity


def enrich_sources(sources: list[dict[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in sources:
        canonical, allowed, rationale, ambiguity = canonical_for_source(source)
        rows.append(
            {
                **source,
                "original_source_type": source["source_type"],
                "canonical_source_type": canonical,
                "implementation_evidence_allowed": allowed,
                "rationale_for_source_type": rationale,
                "ambiguity_flag": ambiguity,
            }
        )
    return rows


def enrich_evidence(evidence: list[dict[str, Any]], source_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in evidence:
        source = source_by_id[item["source_id"]]
        canonical = source["canonical_source_type"]
        allowed = bool(source["implementation_evidence_allowed"])
        row = {
            **item,
            "original_source_type": item.get("source_type", ""),
            "canonical_source_type": canonical,
            "implementation_evidence_allowed": allowed,
            "rationale_for_source_type": source["rationale_for_source_type"],
            "ambiguity_flag": source["ambiguity_flag"],
            # Keep existing deterministic methods runnable while preserving the
            # canonical public-source semantics in metadata and CSV fields.
            "source_type": METHOD_COMPATIBILITY_TYPE[canonical],
        }
        metadata = dict(row.get("metadata", {}))
        metadata.update(
            {
                "canonical_source_type": canonical,
                "original_source_type": item.get("source_type", ""),
                "implementation_evidence_allowed": allowed,
                "public_external_v18b": True,
                "invalid_evidence": not allowed,
                "invalid_reason": "" if allowed else "public_source_not_implementation_evidence",
            }
        )
        row["metadata"] = metadata
        if not allowed:
            row["approval_status"] = "unknown"
            row["source_trust_level"] = "medium"
        rows.append(row)
    return rows


def case_status(case: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]]) -> tuple[str, str]:
    evidence_ids = set(case.get("accepted_evidence_ids", [])) | set(case.get("rejected_evidence_ids", []))
    canonical_types = {evidence_by_id[eid]["canonical_source_type"] for eid in evidence_ids if eid in evidence_by_id}
    accepted_guidance = [
        eid
        for eid in case.get("accepted_evidence_ids", [])
        if evidence_by_id[eid]["canonical_source_type"] in GUIDANCE_TYPES
    ]
    criteria = case.get("expected_criteria", [])
    status = case["expected_status"]
    if accepted_guidance and status == "fulfilled":
        return "excluded_from_eval_pending_review", "Fulfilled case accepted non-implementation guidance/template/control evidence."
    if canonical_types & GUIDANCE_TYPES:
        if status in {"not_fulfilled", "unclear"}:
            return "retained_clean", "Guidance/template/control evidence is intentionally used as non-implementation or unclear evidence."
        return "needs_human_review", "Case mixes implementation labels with guidance/template/control evidence."
    if len(criteria) > 3:
        return "revised", "Composite requirement retained for stress testing; human reviewer should confirm whether criteria should be split."
    if status == "fulfilled":
        return "retained_clean", "Organizational public evidence supports a narrow implementation-like requirement."
    return "retained_clean", "Organizational public evidence retained with project-initial label."


def enrich_cases(cases: list[dict[str, Any]], evidence_by_id: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    out: list[dict[str, Any]] = []
    log_rows: list[dict[str, Any]] = []
    for case in cases:
        status, reason = case_status(case, evidence_by_id)
        evidence_ids = set(case.get("accepted_evidence_ids", [])) | set(case.get("rejected_evidence_ids", []))
        source_types = sorted({evidence_by_id[eid]["canonical_source_type"] for eid in evidence_ids if eid in evidence_by_id})
        bundle = []
        for item in case.get("evidence_bundle", []):
            eid = item["evidence_id"]
            ev = evidence_by_id[eid]
            bundle.append(
                {
                    **item,
                    "canonical_source_type": ev["canonical_source_type"],
                    "implementation_evidence_allowed": ev["implementation_evidence_allowed"],
                    "original_source_type": ev["original_source_type"],
                }
            )
        row = {
            **case,
            "original_case_id": case["case_id"],
            "case_id": case["case_id"].replace("PUBEXT18-", "PUBEXT18B-"),
            "case_cleanup_status": status,
            "cleanup_reason": reason,
            "evidence_bundle": bundle,
            "canonical_source_types": source_types,
            "source_type_taxonomy_version": "v18b",
        }
        row["requirement_id"] = row["requirement_id"].replace("PUBEXT18-", "PUBEXT18B-")
        row["requirement"]["requirement_id"] = row["requirement_id"]
        row["requirement"]["source"] = "project_public_external_v18b"
        row["metadata"] = {
            **dict(row.get("metadata", {})),
            "split": "public_external_validation_v18b",
            "benchmark_version": "v18b",
            "original_case_id": case["case_id"],
            "case_cleanup_status": status,
            "canonical_source_types": source_types,
        }
        if status == "excluded_from_eval_pending_review":
            # Keep labels visible for review, but evaluator will skip this case.
            pass
        out.append(row)
        old_types = sorted({evidence_by_id[eid]["original_source_type"] for eid in evidence_ids if eid in evidence_by_id})
        log_rows.append(
            {
                "original_case_id": case["case_id"],
                "new_case_id": row["case_id"],
                "change_type": status,
                "old_source_type": "|".join(old_types),
                "new_canonical_source_type": "|".join(source_types),
                "old_expected_status": case["expected_status"],
                "new_expected_status": row["expected_status"],
                "reason": reason,
                "human_review_still_needed": status in {"revised", "needs_human_review", "excluded_from_eval_pending_review"},
            }
        )
    return out, log_rows


def taxonomy_md() -> str:
    rows = [
        ("public_org_policy", "yes", "yes", "no", "Public university or agency policy page that states requirements or operating policy for its own organization."),
        ("public_org_plan", "yes", "yes", "no", "Public Incident Response plan for a named organization."),
        ("public_org_procedure", "yes", "yes", "no", "Public operational procedure for a named organization."),
        ("public_org_standard", "yes", "yes", "no", "Public organizational standard or guideline approved by an organization."),
        ("public_org_playbook", "yes", "yes", "no", "Public playbook for a named organization."),
        ("public_template", "no", "context only", "yes", "Blank or customizable template, e.g. an incident response plan template."),
        ("public_guidance", "no", "context only", "yes", "General guidance such as NIST incident response or exercise guidance."),
        ("public_regulatory_guidance", "no", "context only", "yes", "Regulatory or government guidance that is not an adopted organization document."),
        ("control_catalog", "no", "context only", "yes", "Control catalog text or requirement statement."),
        ("oscal_control", "no", "context only", "yes", "OSCAL model/control/assessment schema documentation."),
        ("assessment_template", "no", "context only", "yes", "FedRAMP/OSCAL/assessment templates without completed organization evidence."),
        ("vendor_marketing_or_blog", "no", "usually no", "yes", "Vendor article, marketing text, or generic blog."),
        ("unknown_public_source", "no", "usually no", "yes", "Source whose provenance or purpose is not clear."),
    ]
    lines = [
        "# Public External Source Type Taxonomy v18b",
        "",
        "Core rule: templates, guidance, NIST/OSCAL/FedRAMP/BSI control texts, and generic public guidance must not by themselves support fulfilled implementation status. They can support requirement context, missing criteria, or distractor/source-confusion cases.",
        "",
        "| canonical source type | can support fulfilled | can support partially fulfilled | normally rejected as implementation evidence | examples |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    lines.extend(
        [
            "",
            "## Mapping Rules",
            "",
            "- Public documents from a named organization that describe that organization's policy, plan, procedure, standard, or playbook map to implementation-like public organizational evidence.",
            "- Public templates map to `public_template` and cannot by themselves prove implementation.",
            "- NIST, BSI, OSCAL, FedRAMP, and other control/guidance artifacts map to non-implementation context or distractor types unless the requirement explicitly asks for guidance-level context.",
            "- Method compatibility fields may map public organizational evidence to existing internal source types for deterministic baselines, but canonical source semantics must remain available in `canonical_source_type` and `implementation_evidence_allowed`.",
        ]
    )
    return "\n".join(lines) + "\n"


def reviewer_packet(cases: list[dict[str, Any]]) -> str:
    counts = Counter(case["case_cleanup_status"] for case in cases)
    label_counts = Counter(case["expected_status"] for case in cases)
    return (
        "# Public External Reviewer Packet v18b\n\n"
        "This packet is for review of a cleaned public-document-derived Incident Response stress split. Labels remain project-initial and review is pending.\n\n"
        "## Cleanup Status\n\n"
        + "\n".join(f"- {key}: {counts[key]}" for key in sorted(counts))
        + "\n\n## Label Distribution\n\n"
        + "\n".join(f"- {key}: {label_counts[key]}" for key in sorted(label_counts))
        + "\n\n## Review Instructions\n\n"
        "Review `data/benchmark/public_external_review_sheet_v18b.csv`. Confirm whether the canonical source type is correct, whether each accepted evidence ID is valid for the requirement, and whether the project-initial status should be corrected. Templates and public guidance should not be accepted as implementation evidence unless the requirement explicitly asks for guidance-level context.\n"
    )


def cleanup_log_md(log_rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Public External Case Cleanup Log v18b",
        "",
        "This log documents source-type and case-status cleanup. It does not claim external review and does not silently delete original cases.",
        "",
        "| original case | new case | change type | old source type | new canonical source type | old status | new status | human review needed | reason |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for row in log_rows:
        lines.append(
            f"| {row['original_case_id']} | {row['new_case_id']} | {row['change_type']} | {row['old_source_type']} | "
            f"{row['new_canonical_source_type']} | {row['old_expected_status']} | {row['new_expected_status']} | "
            f"{row['human_review_still_needed']} | {row['reason']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    sources = read_csv(ROOT / "data/external_public/source_inventory_v18.csv")
    evidence = read_jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18.jsonl")
    cases = read_jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18.jsonl")
    sources_b = enrich_sources(sources)
    source_by_id = {row["source_id"]: row for row in sources_b}
    evidence_b = enrich_evidence(evidence, source_by_id)
    evidence_by_id = {row["evidence_id"]: row for row in evidence_b}
    cases_b, log_rows = enrich_cases(cases, evidence_by_id)

    source_fields = list(sources_b[0])
    evidence_fields = [
        "evidence_id",
        "source_id",
        "source_url",
        "page_or_section_reference",
        "short_excerpt_or_paraphrase",
        "criterion_tags",
        "original_source_type",
        "canonical_source_type",
        "implementation_evidence_allowed",
        "source_type",
        "approval_status_if_inferable",
        "validity_or_review_date_if_inferable",
        "language",
        "trust_level",
        "redistribution_note",
        "rationale_for_source_type",
        "ambiguity_flag",
    ]
    case_fields = [
        "case_id",
        "original_case_id",
        "requirement_text",
        "evidence_bundle",
        "expected_status",
        "accepted_evidence_ids",
        "rejected_evidence_ids",
        "missing_criteria",
        "rationale",
        "source_document_ids",
        "source_ids",
        "source_urls",
        "canonical_source_types",
        "case_cleanup_status",
        "cleanup_reason",
        "label_author",
        "external_review_status",
        "redistribution_note",
    ]
    review_fields = [
        "case_id",
        "original_case_id",
        "case_cleanup_status",
        "requirement_text",
        "evidence_ids",
        "evidence_summaries_urls_and_source_types",
        "project_initial_status",
        "reviewer_corrected_status",
        "reviewer_accepts_source_type",
        "reviewer_accepted_evidence_ids",
        "reviewer_rejected_evidence_ids",
        "reviewer_notes",
    ]
    review_rows = []
    for case in cases_b:
        review_rows.append(
            {
                "case_id": case["case_id"],
                "original_case_id": case["original_case_id"],
                "case_cleanup_status": case["case_cleanup_status"],
                "requirement_text": case["requirement_text"],
                "evidence_ids": [item["evidence_id"] for item in case["evidence_bundle"]],
                "evidence_summaries_urls_and_source_types": case["evidence_bundle"],
                "project_initial_status": case["expected_status"],
                "reviewer_corrected_status": "",
                "reviewer_accepts_source_type": "",
                "reviewer_accepted_evidence_ids": "",
                "reviewer_rejected_evidence_ids": "",
                "reviewer_notes": "",
            }
        )

    write_csv(ROOT / "data/external_public/source_inventory_v18b.csv", sources_b, source_fields)
    write_csv(ROOT / "data/external_public/public_ir_evidence_corpus_v18b.csv", evidence_b, evidence_fields)
    write_jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18b.jsonl", evidence_b)
    write_csv(ROOT / "data/benchmark/public_external_validation_cases_v18b.csv", cases_b, case_fields)
    write_jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18b.jsonl", cases_b)
    write_csv(ROOT / "data/benchmark/public_external_review_sheet_v18b.csv", review_rows, review_fields)
    print(
        {
            "sources": len(sources_b),
            "evidence": len(evidence_b),
            "cases": len(cases_b),
            "case_status": dict(Counter(case["case_cleanup_status"] for case in cases_b)),
        }
    )


if __name__ == "__main__":
    main()
