#!/usr/bin/env python
from __future__ import annotations

import ast
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LABEL_ORDER = {"not_fulfilled": 0, "unclear": 1, "partially_fulfilled": 2, "fulfilled": 3}
METHODS = ["metadata_aware", "provenance_balanced", "provenance_conservative", "provenance_conservative_with_guard"]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_list(value: str) -> list[str]:
    if not value:
        return []
    try:
        parsed = ast.literal_eval(value)
        return list(parsed) if isinstance(parsed, list) else [str(parsed)]
    except Exception:
        return []


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def is_false_compliance(predicted: str, truth: str) -> bool:
    return LABEL_ORDER[predicted] > LABEL_ORDER[truth]


def categorize(case: dict[str, Any], wrong_preds: list[dict[str, str]], evidence_by_id: dict[str, dict[str, Any]]) -> list[str]:
    expected = case["expected_status"]
    criteria = case.get("expected_criteria", [])
    canonical_types = set(case.get("canonical_source_types", []))
    missing = set(case.get("missing_criteria", []))
    categories: list[str] = []
    if canonical_types & {"public_template", "assessment_template"}:
        categories.append("template_guidance_confusion")
    if canonical_types & {"public_guidance", "public_regulatory_guidance", "control_catalog", "oscal_control"}:
        categories.append("public_guidance_used_as_org_evidence")
    if canonical_types & {"public_template", "public_guidance", "public_regulatory_guidance", "control_catalog", "oscal_control", "assessment_template"}:
        categories.append("policy_vs_implementation_confusion")
    if len(criteria) > 3:
        categories.append("requirement_too_composite")
    if any(case.get("case_cleanup_status") == value for value in ["revised", "needs_human_review", "excluded_from_eval_pending_review"]):
        categories.append("label_too_strict")
    evidence_ids = set(case.get("accepted_evidence_ids", [])) | set(case.get("rejected_evidence_ids", []))
    if any(evidence_by_id[eid].get("validity_or_review_date_if_inferable") == "unknown" for eid in evidence_ids if eid in evidence_by_id):
        categories.append("missing_metadata")
    if any(len(evidence_by_id[eid].get("short_excerpt_or_paraphrase", "").split()) < 12 for eid in evidence_ids if eid in evidence_by_id):
        categories.append("paraphrase_too_short")
    if expected == "unclear" and any(row["predicted_status"] == "fulfilled" for row in wrong_preds):
        categories.append("method_overtrusts_policy")
    if any(row["predicted_status"] == "unclear" and expected != "unclear" for row in wrong_preds):
        categories.append("method_overabstains")
    if any(missing) and any(row["predicted_status"] == "fulfilled" for row in wrong_preds):
        categories.append("genuine_generalization_failure")
    if not categories:
        categories.append("genuine_generalization_failure")
    priority = [
        "template_guidance_confusion",
        "public_guidance_used_as_org_evidence",
        "policy_vs_implementation_confusion",
        "requirement_too_composite",
        "missing_metadata",
        "paraphrase_too_short",
        "label_too_strict",
        "method_overtrusts_policy",
        "method_overabstains",
        "genuine_generalization_failure",
    ]
    return sorted(set(categories), key=lambda item: priority.index(item) if item in priority else 999)


def main() -> None:
    cases = read_jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18b.jsonl")
    eval_cases = {case["case_id"]: case for case in cases if case.get("case_cleanup_status") in {"retained_clean", "revised"}}
    evidence = read_jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18b.jsonl")
    evidence_by_id = {item["evidence_id"]: item for item in evidence}
    preds = read_csv(ROOT / "experiments/results/public_external_validation_predictions_v18b.csv")
    preds_by_case: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for pred in preds:
        preds_by_case[pred["case_id"]][pred["method"]] = pred

    rows: list[dict[str, Any]] = []
    priority_rows: list[dict[str, Any]] = []
    category_counter: Counter[str] = Counter()
    method_counter: Counter[str] = Counter()
    misclassified_cases: set[str] = set()

    for case_id, case in sorted(eval_cases.items()):
        expected = case["expected_status"]
        wrong = [row for row in preds_by_case[case_id].values() if row["predicted_status"] != expected]
        if not wrong:
            continue
        misclassified_cases.add(case_id)
        categories = categorize(case, wrong, evidence_by_id)
        category_counter[categories[0]] += 1
        for row in wrong:
            method_counter[row["method"]] += 1
        pred_map = {method: preds_by_case[case_id].get(method, {}).get("predicted_status", "") for method in METHODS}
        false_map = {method: bool(preds_by_case[case_id].get(method) and is_false_compliance(preds_by_case[case_id][method]["predicted_status"], expected)) for method in METHODS}
        abstain_map = {method: bool(preds_by_case[case_id].get(method) and preds_by_case[case_id][method]["predicted_status"] == "unclear") for method in METHODS}
        used_map = {method: parse_list(preds_by_case[case_id].get(method, {}).get("retrieved_evidence_ids", "")) for method in METHODS}
        rows.append(
            {
                "case_id": case_id,
                "original_case_id": case.get("original_case_id", ""),
                "case_cleanup_status": case.get("case_cleanup_status", ""),
                "expected_status": expected,
                **{f"predicted_{method}": pred_map[method] for method in METHODS},
                "false_compliance_by_method": json.dumps(false_map, sort_keys=True),
                "abstention_by_method": json.dumps(abstain_map, sort_keys=True),
                "evidence_ids_used_by_method": json.dumps(used_map, sort_keys=True),
                "canonical_source_types": "|".join(case.get("canonical_source_types", [])),
                "requirement_criteria": "|".join(case.get("expected_criteria", [])),
                "missing_criteria": "|".join(case.get("missing_criteria", [])),
                "likely_error_type": categories[0],
                "all_error_categories": "|".join(categories),
                "rationale": case.get("rationale", ""),
            }
        )
        high = any(false_map.values()) or categories[0] in {"template_guidance_confusion", "public_guidance_used_as_org_evidence"}
        priority = "high" if high else ("medium" if case.get("case_cleanup_status") == "revised" or "requirement_too_composite" in categories else "low")
        if categories[0] in {"template_guidance_confusion", "public_guidance_used_as_org_evidence"}:
            question = "Should this case remain a non-implementation/template-guidance stress case, and is the project-initial label correct?"
        elif "requirement_too_composite" in categories:
            question = "Should the requirement be split into narrower cases before review?"
        else:
            question = "Does the public evidence support the expected status under the canonical source type?"
        priority_rows.append(
            {
                "case_id": case_id,
                "original_case_id": case.get("original_case_id", ""),
                "expected_status": expected,
                "priority": priority,
                "reason": "|".join(categories),
                "suggested_human_question": question,
            }
        )

    write_csv(ROOT / "experiments/results/public_external_error_analysis_v18b.csv", rows)
    write_csv(ROOT / "data/benchmark/public_external_human_review_priority_v18b.csv", priority_rows)

    previous = read_csv(ROOT / "experiments/results/public_external_error_analysis_v18.csv")
    previous_primary = Counter(row["likely_error_type"] for row in previous)
    lines = [
        "# Public External Error Analysis v18b",
        "",
        f"- Evaluable cases: {len(eval_cases)}",
        f"- Misclassified cases by at least one method: {len(misclassified_cases)}",
        f"- Misclassified method-case pairs: {sum(method_counter.values())}",
        "",
        "## Primary Error Categories",
        "",
    ]
    for key, value in category_counter.most_common():
        lines.append(f"- {key}: {value}")
    lines += [
        "",
        "## v18 vs v18b Primary Error Category Comparison",
        "",
        "| category | v18 | v18b |",
        "|---|---:|---:|",
    ]
    for key in sorted(set(previous_primary) | set(category_counter)):
        lines.append(f"| {key} | {previous_primary[key]} | {category_counter[key]} |")
    lines += ["", "## Misclassified Cases", ""]
    for row in rows:
        lines.append(f"### {row['case_id']} ({row['expected_status']})")
        lines.append(f"- Predictions: metadata-aware={row['predicted_metadata_aware']}, provenance-balanced={row['predicted_provenance_balanced']}, provenance-conservative={row['predicted_provenance_conservative']}, guarded={row['predicted_provenance_conservative_with_guard']}")
        lines.append(f"- Cleanup status: {row['case_cleanup_status']}")
        lines.append(f"- Primary error type: {row['likely_error_type']}")
        lines.append(f"- Categories: {row['all_error_categories']}")
        lines.append(f"- Canonical source types: {row['canonical_source_types']}")
        lines.append("")
    (ROOT / "experiments/results/public_external_error_analysis_v18b.md").write_text("\n".join(lines), encoding="utf-8")

    pr_counts = Counter(row["priority"] for row in priority_rows)
    audit = [
        "# Public External Label Audit v18b",
        "",
        "All labels remain project-initial and external review remains pending. v18b fixes source-type taxonomy and case-status tracking, but does not claim reviewer validation.",
        "",
        "## Review Priority Counts",
        "",
    ]
    for key in ["high", "medium", "low"]:
        audit.append(f"- {key}: {pr_counts[key]}")
    audit += ["", "## Cases", ""]
    for row in priority_rows:
        audit.append(f"### {row['case_id']} ({row['priority']})")
        audit.append(f"- Expected status: {row['expected_status']}")
        audit.append(f"- Reason: {row['reason']}")
        audit.append(f"- Human question: {row['suggested_human_question']}")
        audit.append("")
    print({"misclassified_cases": len(misclassified_cases), "method_case_pairs": sum(method_counter.values()), "primary_categories": dict(category_counter), "review_priority": dict(pr_counts)})


if __name__ == "__main__":
    main()
