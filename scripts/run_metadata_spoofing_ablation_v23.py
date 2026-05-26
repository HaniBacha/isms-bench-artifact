#!/usr/bin/env python
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.compliance.provenance_assessor import ProvenanceAwareEvidenceAssessor
from kisec.compliance.rule_based import RuleBasedComplianceAssessor
from kisec.evaluation.metrics import compliance_metrics, prediction_rows
from kisec.ingestion.requirements import load_requirements
from kisec.models import BenchmarkCase, EvidencePassage
from kisec.retrieval.factory import make_retriever
from kisec.utils.io import read_jsonl, write_json, write_jsonl
from kisec.utils.tabular import write_csv


IMPLEMENTATION_SOURCES = {
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


def _load_v04() -> tuple[list[BenchmarkCase], list[EvidencePassage]]:
    cases: list[BenchmarkCase] = []
    passages: list[EvidencePassage] = []
    for split in ["development_template", "heldout_template", "stress_test"]:
        cases.extend(
            BenchmarkCase.from_dict(row)
            for row in read_jsonl(ROOT / f"data/benchmark/benchmark_cases_v03_{split}.jsonl")
        )
        passages.extend(
            EvidencePassage.from_dict(row)
            for row in read_jsonl(ROOT / f"data/synthetic_cases/evidence_passages_v03_{split}.jsonl")
        )
    cases.extend(BenchmarkCase.from_dict(row) for row in read_jsonl(ROOT / "data/benchmark/mutation_cases_v03.jsonl"))
    passages.extend(EvidencePassage.from_dict(row) for row in read_jsonl(ROOT / "data/synthetic_cases/mutation_evidence_passages_v03.jsonl"))
    cases.extend(BenchmarkCase.from_dict(row) for row in read_jsonl(ROOT / "data/benchmark/paraphrase_stress_cases_v04.jsonl"))
    passages.extend(EvidencePassage.from_dict(row) for row in read_jsonl(ROOT / "data/synthetic_cases/paraphrase_stress_evidence_v04.jsonl"))
    return cases, passages


def _is_metadata_susceptible(passage: EvidencePassage) -> bool:
    return (
        passage.source_type in NON_IMPLEMENTATION_SOURCES
        or passage.approval_status in {"draft", "expired", "unknown"}
        or passage.source_trust_level == "low"
        or (passage.valid_until is not None and passage.valid_until < "2026-04-24")
        or (passage.created_at is not None and passage.created_at < "2025-04-24")
        or bool(passage.metadata.get("invalid_evidence"))
    )


def _select_cases(cases: list[BenchmarkCase], passages: list[EvidencePassage], max_cases: int) -> list[BenchmarkCase]:
    by_doc: dict[str, list[EvidencePassage]] = {}
    for passage in passages:
        by_doc.setdefault(passage.document_id, []).append(passage)
    selected: list[BenchmarkCase] = []
    for case in sorted(cases, key=lambda item: item.case_id):
        if case.ground_truth_status == "fulfilled":
            continue
        case_passages = [p for doc_id in case.company_document_ids for p in by_doc.get(doc_id, [])]
        if any(_is_metadata_susceptible(passage) for passage in case_passages):
            selected.append(case)
        if len(selected) >= max_cases:
            break
    return selected


def _with_meta(passage: EvidencePassage, **updates) -> EvidencePassage:
    metadata = dict(passage.metadata)
    metadata.update(updates.pop("metadata_updates", {}))
    return replace(passage, metadata=metadata, **updates)


def _spoof_approval(passage: EvidencePassage) -> EvidencePassage:
    if passage.approval_status in {"draft", "unknown", "expired"}:
        return _with_meta(
            passage,
            approval_status="approved",
            valid_until=passage.valid_until or "2027-12-31",
            metadata_updates={"metadata_spoof": "approval_status"},
        )
    return passage


def _spoof_validity(passage: EvidencePassage) -> EvidencePassage:
    if passage.valid_until is None or passage.valid_until < "2026-04-24" or passage.created_at is None or passage.created_at < "2025-04-24":
        return _with_meta(
            passage,
            approval_status="approved" if passage.approval_status in {"draft", "unknown", "expired"} else passage.approval_status,
            valid_until="2027-12-31",
            created_at="2026-04-01",
            metadata_updates={"metadata_spoof": "validity_date"},
        )
    return passage


def _spoof_source_type(passage: EvidencePassage) -> EvidencePassage:
    if passage.source_type not in IMPLEMENTATION_SOURCES:
        return _with_meta(
            passage,
            source_type="company_policy",
            approval_status="approved",
            valid_until="2027-12-31",
            source_trust_level="high",
            metadata_updates={"metadata_spoof": "source_type"},
        )
    return passage


def _spoof_trust_and_approver(passage: EvidencePassage) -> EvidencePassage:
    if passage.source_trust_level != "high" or passage.approval_status != "approved":
        return _with_meta(
            passage,
            approval_status="approved",
            source_trust_level="high",
            valid_until=passage.valid_until or "2027-12-31",
            metadata_updates={"approver": "Executive Board", "metadata_spoof": "trust_and_approver"},
        )
    return passage


def _strip_metadata(passage: EvidencePassage) -> EvidencePassage:
    return replace(
        passage,
        approval_status="unknown",
        valid_from=None,
        valid_until=None,
        created_at=None,
        source_trust_level="medium",
        metadata={"metadata_spoof": "missing_metadata"},
    )


VARIANTS: dict[str, Callable[[EvidencePassage], EvidencePassage]] = {
    "baseline": lambda passage: passage,
    "approval_spoof": _spoof_approval,
    "validity_spoof": _spoof_validity,
    "source_type_spoof": _spoof_source_type,
    "trust_approver_spoof": _spoof_trust_and_approver,
    "missing_metadata": _strip_metadata,
}


METHODS = [
    ("metadata_aware", RuleBasedComplianceAssessor(metadata_aware=True)),
    ("provenance_balanced", ProvenanceAwareEvidenceAssessor(policy="balanced")),
    ("provenance_conservative", ProvenanceAwareEvidenceAssessor(policy="conservative")),
    (
        "provenance_conservative_with_guard",
        ProvenanceAwareEvidenceAssessor(policy="conservative", use_source_guard=True),
    ),
]


def _mutate_passages(passages: list[EvidencePassage], variant: str) -> list[EvidencePassage]:
    transform = VARIANTS[variant]
    return [transform(passage) for passage in passages]


def _predict(
    cases: list[BenchmarkCase],
    passages: list[EvidencePassage],
    method_name: str,
    assessor,
    seed: int,
):
    requirements = {item.requirement_id: item for item in load_requirements(ROOT / "data/processed/requirements_v03.json")}
    retriever = make_retriever("bm25").fit(passages)
    evidence_by_id = {passage.evidence_id: passage for passage in passages}
    predictions = []
    for case in cases:
        requirement = requirements[case.requirement_id]
        query = f"{requirement.title}. {requirement.text}"
        retrieved_ids = [
            result.evidence_id
            for result in retriever.retrieve(query, k=5, candidate_document_ids=case.company_document_ids)
        ]
        predictions.append(
            assessor.predict(
                case=case.to_prediction_input(),
                requirement=requirement,
                evidence_by_id=evidence_by_id,
                retrieved_evidence_ids=retrieved_ids,
                config={"retrieval_method": "bm25", "k": 5, "seed": seed, "metadata_spoofing_ablation": True},
            )
        )
    return predictions


def main() -> None:
    parser = argparse.ArgumentParser(description="Run metadata-spoofing/corruption ablation.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-cases", type=int, default=50)
    args = parser.parse_args()

    all_cases, all_passages = _load_v04()
    cases = _select_cases(all_cases, all_passages, args.max_cases)
    case_ids = {case.case_id for case in cases}
    doc_ids = {doc_id for case in cases for doc_id in case.company_document_ids}
    passages = [passage for passage in all_passages if passage.document_id in doc_ids]

    rows: list[dict] = []
    detail: dict[str, dict] = {"case_ids": sorted(case_ids), "variants": {}}
    for variant in VARIANTS:
        variant_passages = _mutate_passages(passages, variant)
        detail["variants"][variant] = {}
        for method_name, assessor in METHODS:
            predictions = _predict(cases, variant_passages, method_name, assessor, seed=args.seed)
            metrics = compliance_metrics(cases, predictions)
            case_by_id = {case.case_id: case for case in cases}
            false_fulfilled = sum(
                1
                for pred in predictions
                if pred.predicted_status == "fulfilled" and case_by_id[pred.case_id].ground_truth_status != "fulfilled"
            ) / len(predictions)
            row = {
                "variant": variant,
                "method": method_name,
                "num_cases": metrics["num_cases"],
                "macro_f1": metrics["macro_f1"],
                "false_compliance_rate": metrics["false_compliance_rate"],
                "false_fulfilled_rate": false_fulfilled,
                "abstention_rate": metrics["abstention_rate"],
                "risk_weighted_error": metrics["risk_weighted_error"],
                "fulfilled_prediction_rate": sum(1 for pred in predictions if pred.predicted_status == "fulfilled") / len(predictions),
            }
            rows.append(row)
            detail["variants"][variant][method_name] = {"metrics": row}
            write_jsonl(
                ROOT / f"experiments/results/metadata_spoofing_predictions_{variant}_{method_name}_v23.jsonl",
                [prediction.to_dict() for prediction in predictions],
            )
            write_csv(
                ROOT / f"experiments/results/metadata_spoofing_predictions_{variant}_{method_name}_v23.csv",
                prediction_rows(cases, predictions),
            )

    write_csv(ROOT / "experiments/results/metadata_spoofing_ablation_v23.csv", rows)
    write_json(ROOT / "experiments/results/metadata_spoofing_ablation_v23.json", detail)

    baseline = {(row["variant"], row["method"]): row for row in rows}
    lines = [
        "# Metadata-Spoofing/Corruption Ablation v23",
        "",
        f"Evaluated {len(cases)} non-fulfilled or uncertain cases selected for metadata-sensitive evidence defects.",
        "The ablation mutates metadata fields only; evidence text and labels are unchanged. Results are diagnostic and do not model a full attacker feedback loop.",
        "",
        "| Variant | Method | Macro-F1 | False compliance | False fulfilled | Abstention | Fulfilled pred. | Risk-weighted error |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['variant']} | {row['method']} | {row['macro_f1']:.3f} | {row['false_compliance_rate']:.3f} | "
            f"{row['false_fulfilled_rate']:.3f} | {row['abstention_rate']:.3f} | {row['fulfilled_prediction_rate']:.3f} | "
            f"{row['risk_weighted_error']:.3f} |"
        )
    lines.extend(["", "## Interpretation", ""])
    for method_name, _ in METHODS:
        base = baseline[("baseline", method_name)]["false_compliance_rate"]
        worst = max(
            (row for row in rows if row["method"] == method_name),
            key=lambda item: item["false_compliance_rate"],
        )
        lines.append(
            f"- `{method_name}`: baseline false compliance {base:.3f}; worst spoofed variant "
            f"`{worst['variant']}` reaches {worst['false_compliance_rate']:.3f}."
        )
    lines.append("")
    lines.append("False compliance follows the paper's ordinal definition, where `unclear` can be more compliant than `not_fulfilled`. The stricter `false_fulfilled_rate` column separates full false-fulfilled outcomes from conservative uncertainty.")
    lines.append("")
    lines.append("Metadata spoofing is therefore a direct threat to provenance-aware assessment. The result should be reported as a diagnostic stress test, not as evidence of real-world robustness.")
    (ROOT / "experiments/results/metadata_spoofing_ablation_v23.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
