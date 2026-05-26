#!/usr/bin/env python
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

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
VALID_CASE_TYPES = {
    "public_org_evidence_validation",
    "public_source_confusion_stress",
    "public_template_guidance_stress",
    "public_unclear_evidence_stress",
}
SUSPICIOUS_FULFILLED = {"PUBEXT18B-006", "PUBEXT18B-009", "PUBEXT18B-010", "PUBEXT18B-011", "PUBEXT18B-012"}


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


def evidence_ids(case: dict[str, Any]) -> list[str]:
    return [item["evidence_id"] for item in case.get("evidence_bundle", [])]


def case_type(case: dict[str, Any]) -> str:
    canonical = set(case.get("canonical_source_types", []))
    if canonical & {"public_template", "assessment_template"}:
        return "public_template_guidance_stress"
    if canonical & {"public_guidance", "public_regulatory_guidance", "control_catalog", "oscal_control", "vendor_marketing_or_blog", "unknown_public_source"}:
        return "public_source_confusion_stress"
    if case["expected_status"] == "unclear":
        return "public_unclear_evidence_stress"
    return "public_org_evidence_validation"


def split_evidence(case: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]]) -> tuple[list[str], list[str], list[str]]:
    all_ids = evidence_ids(case)
    accepted = list(case.get("accepted_evidence_ids", []))
    rejected = list(case.get("rejected_evidence_ids", []))
    status = case["expected_status"]

    supporting = list(dict.fromkeys(accepted + rejected + all_ids))
    sufficient: list[str]
    if status == "fulfilled":
        sufficient = [
            eid
            for eid in accepted
            if evidence_by_id[eid]["canonical_source_type"] not in NON_IMPLEMENTATION_TYPES
            and evidence_by_id[eid]["implementation_evidence_allowed"]
        ]
    elif status == "partially_fulfilled":
        sufficient = [
            eid
            for eid in accepted
            if evidence_by_id[eid]["canonical_source_type"] not in NON_IMPLEMENTATION_TYPES
            and evidence_by_id[eid]["implementation_evidence_allowed"]
        ]
    else:
        sufficient = []

    context = [eid for eid in supporting if eid not in set(sufficient)]
    return supporting, sufficient, context


def priority_for_case(case: dict[str, Any], supporting: list[str]) -> tuple[str, str, str]:
    cid = case["case_id"]
    status = case["expected_status"]
    ctype = case["case_type"]
    criteria_count = case["criteria_count"]
    if status == "unclear" and supporting:
        return (
            "high",
            "unclear_case_with_supporting_evidence",
            "Is the supporting evidence insufficient enough to justify unclear rather than partial or not_fulfilled?",
        )
    if status == "not_fulfilled" and ctype in {"public_source_confusion_stress", "public_template_guidance_stress"}:
        return (
            "high",
            "not_fulfilled_source_confusion_or_template_guidance",
            "Confirm that the public guidance/template/control material must not count as organizational implementation evidence.",
        )
    if cid == "PUBEXT18B-039":
        return (
            "high",
            "previously_missing_priority_entry",
            "Confirm the unclear label and evidence sufficiency for this previously missing priority case.",
        )
    if cid in SUSPICIOUS_FULFILLED:
        return (
            "high" if cid in {"PUBEXT18B-006", "PUBEXT18B-010"} else "medium",
            "fulfilled_case_secondary_review_flag",
            "Confirm that the fulfilled label is supported despite short paraphrase or composite-evidence concerns.",
        )
    if criteria_count > 2:
        return (
            "medium",
            "composite_requirement",
            "Confirm whether this composite requirement should remain as one stress case or be split.",
        )
    return (
        "low",
        "straightforward_public_org_case",
        "Confirm expected status and evidence sufficiency.",
    )


def convert_case(case: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    row = dict(case)
    row["original_case_id"] = case.get("original_case_id", case["case_id"])
    # Preserve the v18b case identifiers so review notes and previous audits
    # remain directly traceable. The file/schema version is recorded separately.
    row["case_id"] = case["case_id"]
    row["requirement_id"] = case["requirement_id"]
    row["requirement"] = dict(case["requirement"])
    row["requirement"]["requirement_id"] = row["requirement_id"]
    row["requirement"]["source"] = "project_public_external_v18c"
    row["metadata"] = dict(case.get("metadata", {}))
    row["metadata"]["benchmark_version"] = "v18c"
    row["metadata"]["split"] = "public_external_validation_v18c"
    row["source_type_taxonomy_version"] = "v18c"
    row["case_schema_version"] = "v18c"
    row["criterion_operator"] = "all"
    row["criteria_count"] = len(case.get("expected_criteria", []))
    row["composite_requirement"] = row["criteria_count"] > 2
    row["case_type"] = case_type(case)
    supporting, sufficient, context = split_evidence(case, evidence_by_id)
    row["supporting_evidence_ids"] = supporting
    row["sufficient_evidence_ids"] = sufficient
    row["insufficient_or_context_evidence_ids"] = context
    # Keep legacy fields unchanged for existing evaluators; new fields clarify
    # that accepted evidence is not always sufficient implementation evidence.
    return row


def review_row(case: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    priority, reason, question = priority_for_case(case, case["supporting_evidence_ids"])
    source_types = sorted(case.get("canonical_source_types", []))
    implementation_allowed = sorted(
        {
            str(evidence_by_id[eid]["implementation_evidence_allowed"]).lower()
            for eid in case["supporting_evidence_ids"]
            if eid in evidence_by_id
        }
    )
    return {
        "case_id": case["case_id"],
        "original_case_id": case.get("original_case_id", ""),
        "project_initial_status": case["expected_status"],
        "priority": priority,
        "priority_reason": reason,
        "suggested_human_question": question,
        "case_type": case["case_type"],
        "composite_requirement": case["composite_requirement"],
        "criteria_count": case["criteria_count"],
        "requirement_text": case["requirement_text"],
        "expected_criteria": case.get("expected_criteria", []),
        "missing_criteria": case.get("missing_criteria", []),
        "canonical_source_type": source_types,
        "implementation_evidence_allowed": implementation_allowed,
        "supporting_evidence_ids": case["supporting_evidence_ids"],
        "sufficient_evidence_ids": case["sufficient_evidence_ids"],
        "insufficient_or_context_evidence_ids": case["insufficient_or_context_evidence_ids"],
        "source_urls": case.get("source_urls", []),
        "rationale": case.get("rationale", ""),
        "reviewer_agrees_with_status": "",
        "reviewer_corrected_status": "",
        "reviewer_accepts_source_type": "",
        "reviewer_accepts_evidence_sufficiency": "",
        "reviewer_corrected_supporting_evidence_ids": "",
        "reviewer_corrected_sufficient_evidence_ids": "",
        "reviewer_notes": "",
        "copyright_or_confidentiality_flag": "",
    }


def main() -> None:
    case_path = ROOT / "data/benchmark/public_external_validation_cases_v18b.jsonl"
    evidence_path = ROOT / "data/external_public/public_ir_evidence_corpus_v18b.jsonl"
    if not case_path.exists() or not evidence_path.exists():
        raise SystemExit("Run scripts/build_public_external_validation_v18b.py before v18c.")
    evidence = read_jsonl(evidence_path)
    evidence_by_id = {row["evidence_id"]: row for row in evidence}
    cases = [convert_case(case, evidence_by_id) for case in read_jsonl(case_path)]
    review_rows = [review_row(case, evidence_by_id) for case in cases]

    case_fields = [
        "case_id",
        "original_case_id",
        "requirement_text",
        "evidence_bundle",
        "expected_status",
        "accepted_evidence_ids",
        "supporting_evidence_ids",
        "sufficient_evidence_ids",
        "insufficient_or_context_evidence_ids",
        "rejected_evidence_ids",
        "missing_criteria",
        "criterion_operator",
        "case_type",
        "composite_requirement",
        "criteria_count",
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
    write_jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18c.jsonl", cases)
    write_csv(ROOT / "data/benchmark/public_external_validation_cases_v18c.csv", cases, case_fields)
    write_csv(ROOT / "data/benchmark/public_external_review_sheet_v18c.csv", review_rows)
    write_csv(
        ROOT / "data/benchmark/public_external_human_review_priority_v18c.csv",
        [
            {
                "case_id": row["case_id"],
                "original_case_id": row["original_case_id"],
                "expected_status": row["project_initial_status"],
                "priority": row["priority"],
                "reason": row["priority_reason"],
                "case_type": row["case_type"],
                "composite_requirement": row["composite_requirement"],
                "suggested_human_question": row["suggested_human_question"],
            }
            for row in review_rows
        ],
    )

    priority_counts = Counter(row["priority"] for row in review_rows)
    unclear_supporting = sum(1 for case in cases if case["expected_status"] == "unclear" and case["supporting_evidence_ids"])
    labels_changed = 0

    print(
        {
            "cases": len(cases),
            "priority": dict(priority_counts),
            "labels_changed": labels_changed,
            "unclear_cases_with_supporting_evidence": unclear_supporting,
        }
    )


if __name__ == "__main__":
    main()
