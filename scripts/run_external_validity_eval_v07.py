#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.compliance.provenance_assessor import ProvenanceAwareEvidenceAssessor
from kisec.compliance.rule_based import RuleBasedComplianceAssessor
from kisec.evaluation.metrics import attack_metrics, compliance_metrics, grouped_metrics
from kisec.ingestion.requirements import load_requirements
from kisec.models import BenchmarkCase, EvidencePassage, SystemPrediction
from kisec.retrieval.factory import make_retriever
from kisec.utils.io import read_json, read_jsonl, write_json, write_jsonl
from kisec.utils.tabular import write_csv


METHODS = [
    ("metadata_aware", RuleBasedComplianceAssessor(metadata_aware=True)),
    ("provenance_balanced", ProvenanceAwareEvidenceAssessor(policy="balanced")),
    ("provenance_conservative", ProvenanceAwareEvidenceAssessor(policy="conservative")),
    (
        "provenance_conservative_with_source_guard",
        ProvenanceAwareEvidenceAssessor(policy="conservative", use_source_guard=True),
    ),
]

INVALID_SOURCE_TYPES = {"norm_text", "irrelevant_document", "public_reference", "draft_policy"}


def _load_cases(path: str) -> list[BenchmarkCase]:
    return [BenchmarkCase.from_dict(row) for row in read_jsonl(ROOT / path)]


def _load_passages(path: str) -> list[EvidencePassage]:
    return [EvidencePassage.from_dict(row) for row in read_jsonl(ROOT / path)]


def _load_original_v04_non_attack() -> tuple[list[BenchmarkCase], list[EvidencePassage]]:
    cases: list[BenchmarkCase] = []
    passages: list[EvidencePassage] = []
    for split in ["development_template", "heldout_template", "stress_test"]:
        cases.extend(_load_cases(f"data/benchmark/benchmark_cases_v03_{split}.jsonl"))
        passages.extend(_load_passages(f"data/synthetic_cases/evidence_passages_v03_{split}.jsonl"))
    cases.extend(_load_cases("data/benchmark/mutation_cases_v03.jsonl"))
    passages.extend(_load_passages("data/synthetic_cases/mutation_evidence_passages_v03.jsonl"))
    cases.extend(_load_cases("data/benchmark/paraphrase_stress_cases_v04.jsonl"))
    passages.extend(_load_passages("data/synthetic_cases/paraphrase_stress_evidence_v04.jsonl"))
    return cases, passages


def _augment_with_public_distractors(cases: list[BenchmarkCase], distractors: list[EvidencePassage], split_name: str) -> list[BenchmarkCase]:
    distractor_docs = sorted({passage.document_id for passage in distractors})
    augmented: list[BenchmarkCase] = []
    for case in cases:
        metadata = dict(case.metadata)
        metadata["split"] = split_name
        metadata["public_template_distractors_added"] = True
        augmented.append(
            replace(
                case,
                case_id=f"{case.case_id}__PUBDIST",
                company_document_ids=sorted(set(case.company_document_ids) | set(distractor_docs)),
                metadata=metadata,
            )
        )
    return augmented


def _predict(cases: list[BenchmarkCase], passages: list[EvidencePassage], requirements_by_id: dict[str, Any], assessor, k: int, seed: int) -> list[SystemPrediction]:
    retriever = make_retriever("bm25").fit(passages)
    evidence_by_id = {passage.evidence_id: passage for passage in passages}
    predictions: list[SystemPrediction] = []
    for case in cases:
        requirement = requirements_by_id[case.requirement_id]
        query = f"{requirement.title}. {requirement.text}"
        results = retriever.retrieve(query, k=k, candidate_document_ids=case.company_document_ids)
        predictions.append(
            assessor.predict(
                case.to_prediction_input(),
                requirement,
                evidence_by_id,
                [result.evidence_id for result in results],
                config={"retrieval_method": "bm25", "k": k, "seed": seed, "external_validity_v07": True},
            )
        )
    return predictions


def _source_quality_metrics(
    cases: list[BenchmarkCase],
    predictions: list[SystemPrediction],
    evidence_by_id: dict[str, EvidencePassage],
) -> dict[str, float]:
    if not predictions:
        return {
            "source_attribution_failure_rate": 0.0,
            "unsafe_evidence_acceptance_rate": 0.0,
            "residual_attack_risk_score": 0.0,
        }
    case_by_id = {case.case_id: case for case in cases}
    source_failures = 0
    unsafe_acceptances = 0
    residual = 0.0
    for pred in predictions:
        case = case_by_id[pred.case_id]
        gold = set(case.ground_truth_evidence_ids)
        invalid_cited = False
        source_failure = bool(pred.source_attribution_errors_detected)
        for evidence_id in pred.retrieved_evidence_ids:
            passage = evidence_by_id.get(evidence_id)
            if passage is None:
                continue
            invalid = (
                passage.source_type in INVALID_SOURCE_TYPES
                or passage.metadata.get("invalid_evidence")
                or passage.metadata.get("poisoned")
                or (passage.source_trust_level == "low" and evidence_id not in gold)
            )
            if invalid:
                invalid_cited = True
                if evidence_id not in gold or passage.source_type in {"norm_text", "public_reference", "irrelevant_document"}:
                    source_failure = True
        if source_failure:
            source_failures += 1
        if invalid_cited:
            unsafe_acceptances += 1
        false_fulfilled = pred.predicted_status == "fulfilled" and case.ground_truth_status in {"not_fulfilled", "partially_fulfilled", "unclear"}
        residual += 1.0 * float(false_fulfilled) + 0.55 * float(invalid_cited) + 0.45 * float(source_failure)
    total = len(predictions)
    return {
        "source_attribution_failure_rate": source_failures / total,
        "unsafe_evidence_acceptance_rate": unsafe_acceptances / total,
        "residual_attack_risk_score": residual / total,
    }


def _normal_dataset_rows(
    *,
    dataset_name: str,
    cases: list[BenchmarkCase],
    passages: list[EvidencePassage],
    requirements_by_id,
    k: int,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    difficulty_rows: list[dict[str, Any]] = []
    outputs: dict[str, Any] = {}
    evidence_by_id = {passage.evidence_id: passage for passage in passages}
    for method_name, assessor in METHODS:
        predictions = _predict(cases, passages, requirements_by_id, assessor, k, seed)
        metrics = compliance_metrics(cases, predictions)
        metrics.update(_source_quality_metrics(cases, predictions, evidence_by_id))
        row = {"dataset": dataset_name, "method": method_name, **metrics}
        rows.append(row)
        outputs[method_name] = metrics
        for group_row in grouped_metrics(cases, predictions, "difficulty_type"):
            quality = _source_quality_metrics(
                [case for case in cases if (case.difficulty_type or "none") == group_row["difficulty_type"]],
                [pred for pred in predictions if (next(c for c in cases if c.case_id == pred.case_id).difficulty_type or "none") == group_row["difficulty_type"]],
                evidence_by_id,
            )
            difficulty_rows.append({"dataset": dataset_name, "method": method_name, **group_row, **quality})
        write_jsonl(
            ROOT / f"experiments/results/external_validity_predictions_{dataset_name}_{method_name}_v07.jsonl",
            [prediction.to_dict() for prediction in predictions],
        )
    return rows, difficulty_rows, outputs


def _attack_dataset_rows(
    *,
    dataset_name: str,
    attack_cases: list[BenchmarkCase],
    attack_passages: list[EvidencePassage],
    clean_cases: list[BenchmarkCase],
    clean_passages: list[EvidencePassage],
    requirements_by_id,
    k: int,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    by_type_rows: list[dict[str, Any]] = []
    outputs: dict[str, Any] = {}
    all_passages = clean_passages + attack_passages
    evidence_by_id = {passage.evidence_id: passage for passage in all_passages}
    for method_name, assessor in METHODS:
        clean_predictions = _predict(clean_cases, clean_passages, requirements_by_id, assessor, k, seed)
        clean_by_case_id = {prediction.case_id: prediction for prediction in clean_predictions}
        attack_predictions = _predict(attack_cases, all_passages, requirements_by_id, assessor, k, seed)
        attack = attack_metrics(attack_cases, attack_predictions, evidence_by_id, clean_by_case_id)
        classification = compliance_metrics(attack_cases, attack_predictions)
        row = {
            "dataset": dataset_name,
            "method": method_name,
            **classification,
            **attack["overall"],
        }
        rows.append(row)
        outputs[method_name] = {"classification": classification, "attack": attack["overall"]}
        for by_type in attack["by_attack_type"]:
            by_type_rows.append({"dataset": dataset_name, "method": method_name, **by_type})
        write_jsonl(
            ROOT / f"experiments/results/external_validity_predictions_{dataset_name}_{method_name}_v07.jsonl",
            [prediction.to_dict() for prediction in attack_predictions],
        )
    return rows, by_type_rows, outputs


def _write_latex_table(rows: list[dict[str, Any]]) -> None:
    selected = [
        row
        for row in rows
        if row["dataset"]
        in {
            "original_synthetic_v04",
            "independent_challenge_v07",
            "alt_generator_v07",
            "adaptive_attack_cases_v04",
        }
        and row["method"] in {"metadata_aware", "provenance_balanced", "provenance_conservative"}
    ]
    dataset_labels = {
        "original_synthetic_v04": "Original v0.4",
        "independent_challenge_v07": "Independent",
        "alt_generator_v07": "Alt. generator",
        "adaptive_attack_cases_v04": "Adaptive attack",
    }
    method_labels = {
        "metadata_aware": "Metadata",
        "provenance_balanced": "Prov.-bal.",
        "provenance_conservative": "Prov.-cons.",
    }
    lines = [
        "\\begin{table}[t]",
        "\\centering",
        "\\footnotesize",
        "\\caption{External-validity stress checks in v0.7. These checks reduce but do not eliminate generator-dependence concerns.}",
        "\\label{tab:external-validity-v07}",
        "\\resizebox{\\linewidth}{!}{%",
        "\\begin{tabular}{llrrrr}",
        "\\toprule",
        "Dataset & Method & Macro-F1 & False comp. & Abstain & Residual risk \\\\",
        "\\midrule",
    ]
    for row in selected:
        lines.append(
            f"{dataset_labels.get(row['dataset'], row['dataset'])} & "
            f"{method_labels.get(row['method'], row['method'])} & "
            f"{float(row.get('macro_f1', 0.0)):.3f} & "
            f"{float(row.get('false_compliance_rate', 0.0)):.3f} & "
            f"{float(row.get('abstention_rate', 0.0)):.3f} & "
            f"{float(row.get('residual_attack_risk_score', 0.0)):.3f} \\\\"
        )
    lines.extend(["\\bottomrule", "\\end{tabular}%", "}", "\\end{table}", ""])
    path = ROOT / "artifact_outputs/tables/external_validity_v07.tex"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run v0.7 external-validity stress evaluation.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--k", type=int, default=5)
    args = parser.parse_args()

    requirements_by_id = {req.requirement_id: req for req in load_requirements(ROOT / "data/processed/requirements_v03.json")}
    distractors = _load_passages("data/benchmark/public_template_distractors_v07.jsonl")

    original_cases, original_passages = _load_original_v04_non_attack()
    independent_cases = _load_cases("data/benchmark/independent_challenge_cases_v07.jsonl")
    independent_passages = _load_passages("data/synthetic_cases/independent_challenge_evidence_v07.jsonl")
    alt_cases = _load_cases("data/benchmark/alt_generator_cases_v07.jsonl")
    alt_passages = _load_passages("data/synthetic_cases/alt_generator_evidence_v07.jsonl")
    para_cases = _load_cases("data/benchmark/paraphrase_stress_cases_v04.jsonl")
    para_passages = _load_passages("data/synthetic_cases/paraphrase_stress_evidence_v04.jsonl")
    attack_cases = _load_cases("data/attacks/adaptive_attack_cases_v04.jsonl")
    attack_passages = _load_passages("data/attacks/adaptive_attack_evidence_passages_v04.jsonl")

    datasets = [
        ("original_synthetic_v04", original_cases, original_passages),
        ("independent_challenge_v07", independent_cases, independent_passages),
        ("alt_generator_v07", alt_cases, alt_passages),
        ("paraphrase_stress_v04", para_cases, para_passages),
        (
            "independent_challenge_plus_public_template_distractors_v07",
            _augment_with_public_distractors(independent_cases, distractors, "independent_plus_public_template_v07"),
            independent_passages + distractors,
        ),
        (
            "alt_generator_plus_public_template_distractors_v07",
            _augment_with_public_distractors(alt_cases, distractors, "alt_plus_public_template_v07"),
            alt_passages + distractors,
        ),
    ]

    all_rows: list[dict[str, Any]] = []
    by_difficulty: list[dict[str, Any]] = []
    outputs: dict[str, Any] = {}
    for dataset_name, cases, passages in datasets:
        rows, diff_rows, metrics = _normal_dataset_rows(
            dataset_name=dataset_name,
            cases=cases,
            passages=passages,
            requirements_by_id=requirements_by_id,
            k=args.k,
            seed=args.seed,
        )
        all_rows.extend(rows)
        by_difficulty.extend(diff_rows)
        outputs[dataset_name] = metrics

    attack_rows, by_attack_type, attack_outputs = _attack_dataset_rows(
        dataset_name="adaptive_attack_cases_v04",
        attack_cases=attack_cases,
        attack_passages=attack_passages,
        clean_cases=original_cases,
        clean_passages=original_passages,
        requirements_by_id=requirements_by_id,
        k=args.k,
        seed=args.seed,
    )
    all_rows.extend(attack_rows)
    outputs["adaptive_attack_cases_v04"] = attack_outputs

    distractor_row = {
        "dataset": "public_template_distractors_v07",
        "method": "not_applicable_distractor_corpus",
        "num_cases": 0,
        "num_distractor_passages": len(distractors),
        "macro_f1": "",
        "false_compliance_rate": "",
        "abstention_rate": "",
        "false_non_compliance_rate": "",
        "source_attribution_failure_rate": "",
        "unsafe_evidence_acceptance_rate": "",
        "residual_attack_risk_score": "",
        "risk_weighted_error": "",
    }
    all_rows.append(distractor_row)
    outputs["public_template_distractors_v07"] = {
        "num_distractor_passages": len(distractors),
        "note": "Dataloader corpus only; evaluated when added to independent and alternative candidate pools.",
    }

    write_csv(ROOT / "experiments/results/external_validity_v07.csv", all_rows)
    write_csv(ROOT / "experiments/results/external_validity_by_dataset_v07.csv", all_rows)
    write_csv(ROOT / "experiments/results/external_validity_by_difficulty_v07.csv", by_difficulty)
    write_csv(ROOT / "experiments/results/external_validity_by_attack_type_v07.csv", by_attack_type)
    write_json(
        ROOT / "experiments/results/external_validity_v07.json",
        {
            "seed": args.seed,
            "k": args.k,
            "methods": [name for name, _ in METHODS],
            "datasets": outputs,
            "summary_rows": all_rows,
        },
    )
    _write_latex_table(all_rows)
    print({"rows": len(all_rows), "difficulty_rows": len(by_difficulty), "attack_type_rows": len(by_attack_type)})


if __name__ == "__main__":
    main()
