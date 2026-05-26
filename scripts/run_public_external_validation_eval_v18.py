#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.compliance.provenance_assessor import ProvenanceAwareEvidenceAssessor
from kisec.compliance.rule_based import RuleBasedComplianceAssessor
from kisec.evaluation.metrics import compliance_metrics, prediction_rows
from kisec.models import BenchmarkCase, EvidencePassage, Requirement, SystemPrediction
from kisec.retrieval.factory import make_retriever
from kisec.utils.io import read_jsonl, write_json, write_jsonl
from kisec.utils.tabular import write_csv


METHODS = [
    ("metadata_aware", RuleBasedComplianceAssessor(metadata_aware=True)),
    ("provenance_balanced", ProvenanceAwareEvidenceAssessor(policy="balanced")),
    ("provenance_conservative", ProvenanceAwareEvidenceAssessor(policy="conservative")),
    (
        "provenance_conservative_with_guard",
        ProvenanceAwareEvidenceAssessor(policy="conservative", use_source_guard=True),
    ),
]

INVALID_SOURCE_TYPES = {"norm_text", "public_reference", "draft_policy", "irrelevant_document", "untrusted_note"}


def _requirement_for_case(raw_case: dict[str, Any], case: BenchmarkCase) -> Requirement:
    requirement = raw_case.get("requirement", {})
    return Requirement(
        requirement_id=case.requirement_id,
        source="public_external_validation_v18",
        title=str(requirement.get("title", "Public-document Incident Response evidence pre-assessment")),
        text=str(raw_case.get("requirement_text", requirement.get("text", ""))),
        domain="Incident Management",
        expected_evidence_types=list(case.expected_criteria),
    )


def _quality_metrics(
    cases: list[BenchmarkCase],
    predictions: list[SystemPrediction],
    evidence_by_id: dict[str, EvidencePassage],
) -> dict[str, float]:
    if not predictions:
        return {
            "source_attribution_failure_rate": 0.0,
            "unsafe_evidence_acceptance_rate": 0.0,
            "residual_grounding_risk": 0.0,
        }
    case_by_id = {case.case_id: case for case in cases}
    source_errors = 0
    unsafe = 0
    residual = 0.0
    for pred in predictions:
        case = case_by_id[pred.case_id]
        gold = set(case.ground_truth_evidence_ids)
        source_error_here = bool(pred.source_attribution_errors_detected)
        unsafe_here = False
        for evidence_id in pred.retrieved_evidence_ids:
            passage = evidence_by_id.get(evidence_id)
            if passage is None:
                continue
            invalid = bool(
                passage.metadata.get("invalid_evidence")
                or passage.source_type in INVALID_SOURCE_TYPES
                or passage.approval_status in {"draft", "expired"}
                or (passage.source_trust_level == "low" and evidence_id not in gold)
            )
            unsafe_here = unsafe_here or invalid
            source_error_here = source_error_here or bool(invalid and evidence_id not in gold)
        false_fulfilled = pred.predicted_status == "fulfilled" and case.ground_truth_status != "fulfilled"
        source_errors += int(source_error_here)
        unsafe += int(unsafe_here)
        residual += 1.0 * float(false_fulfilled) + 0.55 * float(unsafe_here) + 0.45 * float(source_error_here)
    total = len(predictions)
    return {
        "source_attribution_failure_rate": source_errors / total,
        "unsafe_evidence_acceptance_rate": unsafe / total,
        "residual_grounding_risk": residual / total,
    }


def _load() -> tuple[list[dict[str, Any]], list[BenchmarkCase], list[EvidencePassage]]:
    case_path = ROOT / "data/benchmark/public_external_validation_cases_v18.jsonl"
    evidence_path = ROOT / "data/external_public/public_ir_evidence_corpus_v18.jsonl"
    if not case_path.exists() or not evidence_path.exists():
        raise SystemExit("v18 public external data missing. Run scripts/build_public_external_validation_v18.py first.")
    raw_cases = read_jsonl(case_path)
    cases = [BenchmarkCase.from_dict(row) for row in raw_cases]
    passages = [EvidencePassage.from_dict(row) for row in read_jsonl(evidence_path)]
    return raw_cases, cases, passages


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate public-document-derived external validation split v18.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument(
        "--include-llm",
        action="store_true",
        help="Reserved for a real API LLM pass. The default deterministic run makes no provider calls.",
    )
    args = parser.parse_args()

    raw_cases, cases, passages = _load()
    raw_by_id = {row["case_id"]: row for row in raw_cases}
    evidence_by_id = {passage.evidence_id: passage for passage in passages}
    retriever = make_retriever("bm25").fit(passages)

    rows: list[dict[str, Any]] = []
    all_prediction_rows: list[dict[str, Any]] = []
    for method_name, assessor in METHODS:
        predictions: list[SystemPrediction] = []
        for case in cases:
            requirement = _requirement_for_case(raw_by_id[case.case_id], case)
            results = retriever.retrieve(
                f"{requirement.title}. {requirement.text}",
                k=args.k,
                candidate_document_ids=case.company_document_ids,
            )
            predictions.append(
                assessor.predict(
                    case.to_prediction_input(),
                    requirement,
                    evidence_by_id,
                    [result.evidence_id for result in results],
                    config={"seed": args.seed, "k": args.k, "split": "public_external_validation_v18"},
                )
            )
        metrics = compliance_metrics(cases, predictions)
        metrics.update(_quality_metrics(cases, predictions, evidence_by_id))
        rows.append({"method": method_name, **metrics})
        pred_rows = prediction_rows(cases, predictions)
        for row in pred_rows:
            row["method"] = method_name
        all_prediction_rows.extend(pred_rows)
        write_jsonl(
            ROOT / f"experiments/results/public_external_validation_predictions_{method_name}_v18.jsonl",
            [pred.to_dict() for pred in predictions],
        )

    llm_note = "LLM methods were not run; deterministic v18 evaluator makes no provider calls by default."
    if args.include_llm:
        has_key = bool(os.environ.get("JGU_API_KEY") or os.environ.get("KI_CHAT_API_KEY"))
        llm_note = (
            "LLM execution was requested but is intentionally not implemented in this evaluator to avoid unplanned provider calls. "
            f"API key present: {'yes' if has_key else 'no'}."
        )

    out_csv = ROOT / "experiments/results/public_external_validation_v18.csv"
    write_csv(out_csv, rows)
    write_csv(ROOT / "experiments/results/public_external_validation_predictions_v18.csv", all_prediction_rows)
    write_json(
        ROOT / "experiments/results/public_external_validation_v18.json",
        {"seed": args.seed, "k": args.k, "num_cases": len(cases), "num_evidence": len(passages), "llm_note": llm_note, "rows": rows},
    )

    analysis = [
        "# Public External Validation Analysis v18",
        "",
        f"- Cases: {len(cases)}",
        f"- Evidence passages: {len(passages)}",
        "- Label status: project-initial; external review pending.",
        f"- LLM status: {llm_note}",
        "",
        "## Results",
        "",
    ]
    for row in rows:
        analysis.append(
            f"- {row['method']}: Macro-F1={row['macro_f1']:.3f}, false compliance={row['false_compliance_rate']:.3f}, "
            f"abstention={row['abstention_rate']:.3f}, unsafe evidence={row['unsafe_evidence_acceptance_rate']:.3f}, "
            f"source attribution failure={row['source_attribution_failure_rate']:.3f}, residual grounding risk={row['residual_grounding_risk']:.3f}, "
            f"Evidence-F1={row['evidence_f1']:.3f}"
        )
    analysis.extend(
        [
            "",
            "## Interpretation",
            "",
            "This split reduces document-generation dependence because the evidence passages are derived from real public incident-response plans, policies, templates, and assessment/provenance references. It does not remove label-author dependence: expected statuses and evidence decisions are project-initial and require independent review before being described as validation evidence.",
        ]
    )
    (ROOT / "experiments/results/public_external_validation_analysis_v18.md").write_text(
        "\n".join(analysis) + "\n",
        encoding="utf-8",
    )
    print({"cases": len(cases), "methods": len(rows), "output": str(out_csv.relative_to(ROOT))})


if __name__ == "__main__":
    main()
