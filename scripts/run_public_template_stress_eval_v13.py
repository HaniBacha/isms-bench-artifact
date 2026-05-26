#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.compliance.provenance_assessor import ProvenanceAwareEvidenceAssessor
from kisec.compliance.rule_based import RuleBasedComplianceAssessor
from kisec.evaluation.metrics import compliance_metrics
from kisec.ingestion.requirements import load_requirements
from kisec.models import BenchmarkCase, EvidencePassage, SystemPrediction
from kisec.retrieval.factory import make_retriever
from kisec.utils.io import read_jsonl, write_json, write_jsonl
from kisec.utils.tabular import write_csv


METHODS = [
    ("metadata_aware", RuleBasedComplianceAssessor(metadata_aware=True)),
    ("provenance_balanced", ProvenanceAwareEvidenceAssessor(policy="balanced")),
    ("provenance_conservative", ProvenanceAwareEvidenceAssessor(policy="conservative")),
]


def _source_metrics(cases: list[BenchmarkCase], predictions: list[SystemPrediction], evidence_by_id: dict[str, EvidencePassage]) -> dict[str, float]:
    if not predictions:
        return {
            "source_attribution_failure_rate": 0.0,
            "unsafe_evidence_acceptance_rate": 0.0,
            "false_evidence_acceptance_rate": 0.0,
            "norm_company_confusion_rate": 0.0,
            "residual_attack_risk_score": 0.0,
        }
    case_by_id = {case.case_id: case for case in cases}
    source_errors = 0
    unsafe = 0
    false_evidence = 0
    norm_confusion = 0
    residual = 0.0
    for pred in predictions:
        case = case_by_id[pred.case_id]
        invalid_here = False
        source_error_here = bool(pred.source_attribution_errors_detected)
        norm_here = False
        for evidence_id in pred.retrieved_evidence_ids:
            passage = evidence_by_id.get(evidence_id)
            if not passage:
                continue
            invalid = bool(
                passage.metadata.get("invalid_evidence")
                or passage.source_type in {"norm_text", "public_reference", "draft_policy", "untrusted_note", "irrelevant_document"}
                or passage.approval_status in {"draft", "expired"}
            )
            invalid_here = invalid_here or invalid
            source_error_here = source_error_here or invalid
            norm_here = norm_here or passage.source_type in {"norm_text", "public_reference"}
        false_fulfilled = pred.predicted_status == "fulfilled" and case.ground_truth_status != "fulfilled"
        source_errors += int(source_error_here)
        unsafe += int(invalid_here)
        false_evidence += int(invalid_here and pred.predicted_status in {"partially_fulfilled", "fulfilled"})
        norm_confusion += int(norm_here and pred.predicted_status in {"partially_fulfilled", "fulfilled"})
        residual += 1.0 * float(false_fulfilled) + 0.55 * float(invalid_here) + 0.45 * float(source_error_here)
    total = len(predictions)
    return {
        "source_attribution_failure_rate": source_errors / total,
        "unsafe_evidence_acceptance_rate": unsafe / total,
        "false_evidence_acceptance_rate": false_evidence / total,
        "norm_company_confusion_rate": norm_confusion / total,
        "residual_attack_risk_score": residual / total,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate public/template-derived source-confusion stress set.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--k", type=int, default=5)
    args = parser.parse_args()

    cases_path = ROOT / "data/benchmark/public_template_stress_v13.jsonl"
    evidence_path = ROOT / "data/synthetic_cases/public_template_stress_evidence_v13.jsonl"
    if not cases_path.exists() or not evidence_path.exists():
        raise SystemExit("Public-template stress data missing. Run scripts/build_public_template_stress_v13.py first.")
    cases = [BenchmarkCase.from_dict(row) for row in read_jsonl(cases_path)]
    passages = [EvidencePassage.from_dict(row) for row in read_jsonl(evidence_path)]
    requirements_by_id = {item.requirement_id: item for item in load_requirements(ROOT / "data/processed/requirements_v03.json")}
    retriever = make_retriever("bm25").fit(passages)
    evidence_by_id = {passage.evidence_id: passage for passage in passages}
    rows: list[dict[str, Any]] = []
    for method_name, assessor in METHODS:
        predictions: list[SystemPrediction] = []
        for case in cases:
            requirement = requirements_by_id[case.requirement_id]
            results = retriever.retrieve(f"{requirement.title}. {requirement.text}", k=args.k, candidate_document_ids=case.company_document_ids)
            predictions.append(
                assessor.predict(
                    case.to_prediction_input(),
                    requirement,
                    evidence_by_id,
                    [result.evidence_id for result in results],
                    config={"seed": args.seed, "k": args.k, "public_template_stress_v13": True},
                )
            )
        metrics = compliance_metrics(cases, predictions)
        metrics.update(_source_metrics(cases, predictions, evidence_by_id))
        rows.append({"method": method_name, **metrics})
        write_jsonl(ROOT / f"experiments/results/public_template_stress_predictions_{method_name}_v13.jsonl", [pred.to_dict() for pred in predictions])
    write_csv(ROOT / "experiments/results/public_template_stress_v13.csv", rows)
    write_json(ROOT / "experiments/results/public_template_stress_v13.json", {"seed": args.seed, "k": args.k, "rows": rows})
    analysis = ["# Public Template Stress Analysis v1.3", ""]
    analysis.append("This stress set uses public-source URLs and locally generated surrogate snippets. It tests source confusion and unsafe evidence acceptance, not full real-world compliance performance.")
    analysis.append("")
    for row in rows:
        analysis.append(
            f"- {row['method']}: source attribution failure={row['source_attribution_failure_rate']:.3f}, "
            f"unsafe acceptance={row['unsafe_evidence_acceptance_rate']:.3f}, abstention={row['abstention_rate']:.3f}, "
            f"residual risk={row['residual_attack_risk_score']:.3f}"
        )
    (ROOT / "experiments/results/public_template_stress_analysis_v13.md").write_text("\n".join(analysis) + "\n", encoding="utf-8")
    print({"cases": len(cases), "methods": len(rows), "output": "experiments/results/public_template_stress_v13.csv"})


if __name__ == "__main__":
    main()
