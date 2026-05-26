#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.compliance.rule_based import (
    ConstantStatusComplianceAssessor,
    MajorityClassComplianceAssessor,
    RandomComplianceAssessor,
    RetrievalOnlyComplianceAssessor,
    RuleBasedComplianceAssessor,
)
from kisec.compliance.provenance_assessor import ProvenanceAwareEvidenceAssessor
from kisec.evaluation.metrics import (
    compliance_metrics,
    confusion_rows,
    grouped_metrics,
    prediction_rows,
)
from kisec.ingestion.requirements import load_requirements
from kisec.models import BenchmarkCase, EvidencePassage, SystemPrediction
from kisec.retrieval.factory import make_retriever
from kisec.utils.io import read_jsonl, write_json, write_jsonl
from kisec.utils.tabular import write_csv


def _default_paths(version: str, requirements: str, evidence: str, cases: str) -> tuple[str, str, str]:
    if version in {"v03", "v04"}:
        if requirements == "data/processed/requirements.json":
            requirements = "data/processed/requirements_v03.json"
        return requirements, evidence, cases
    if version != "v02":
        return requirements, evidence, cases
    if requirements == "data/processed/requirements.json":
        requirements = "data/processed/requirements_v02.json"
    if evidence == "data/synthetic_cases/evidence_passages.jsonl":
        evidence = "data/synthetic_cases/evidence_passages_v02.jsonl"
    if cases == "data/benchmark/benchmark_cases.jsonl":
        cases = "data/benchmark/benchmark_cases_v02.jsonl"
    return requirements, evidence, cases


def _load_cases_and_passages(version: str, cases_path: str, evidence_path: str) -> tuple[list[BenchmarkCase], list[EvidencePassage]]:
    if version in {"v03", "v04"}:
        cases: list[BenchmarkCase] = []
        passages: list[EvidencePassage] = []
        for split in ["development_template", "heldout_template", "stress_test"]:
            split_cases = ROOT / f"data/benchmark/benchmark_cases_v03_{split}.jsonl"
            split_evidence = ROOT / f"data/synthetic_cases/evidence_passages_v03_{split}.jsonl"
            if split_cases.exists() and split_evidence.exists():
                cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(split_cases))
                passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(split_evidence))
        mutation_cases_path = ROOT / "data/benchmark/mutation_cases_v03.jsonl"
        mutation_evidence_path = ROOT / "data/synthetic_cases/mutation_evidence_passages_v03.jsonl"
        if mutation_cases_path.exists() and mutation_evidence_path.exists():
            cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(mutation_cases_path))
            passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(mutation_evidence_path))
        if version == "v04":
            para_cases_path = ROOT / "data/benchmark/paraphrase_stress_cases_v04.jsonl"
            para_evidence_path = ROOT / "data/synthetic_cases/paraphrase_stress_evidence_v04.jsonl"
            if para_cases_path.exists() and para_evidence_path.exists():
                cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(para_cases_path))
                passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(para_evidence_path))
        return cases, passages
    cases = [BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / cases_path)]
    passages = [EvidencePassage.from_dict(item) for item in read_jsonl(ROOT / evidence_path)]
    if version == "v02":
        mutation_cases_path = ROOT / "data/benchmark/mutation_cases_v02.jsonl"
        mutation_evidence_path = ROOT / "data/synthetic_cases/mutation_evidence_passages_v02.jsonl"
        if mutation_cases_path.exists() and mutation_evidence_path.exists():
            cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(mutation_cases_path))
            passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(mutation_evidence_path))
    return cases, passages


def _retrieved_ids_for_case(
    case: BenchmarkCase,
    requirement_text: str,
    retrievers: dict[str, object],
    retrieval_method: str,
    k: int,
) -> list[str]:
    if retrieval_method == "oracle":
        return list(case.ground_truth_evidence_ids)
    if retrieval_method == "none":
        return []
    retriever = retrievers[retrieval_method]
    results = retriever.retrieve(requirement_text, k=k, candidate_document_ids=case.company_document_ids)
    return [result.evidence_id for result in results]


def run_predictions(
    cases: list[BenchmarkCase],
    requirements_by_id,
    passages: list[EvidencePassage],
    retrieval_method: str,
    k: int,
    assessor,
    seed: int = 42,
) -> list[SystemPrediction]:
    retrievers = {}
    if retrieval_method not in {"oracle", "none"}:
        retrievers[retrieval_method] = make_retriever(retrieval_method).fit(passages)
    evidence_by_id = {passage.evidence_id: passage for passage in passages}
    predictions: list[SystemPrediction] = []
    for case in cases:
        requirement = requirements_by_id[case.requirement_id]
        query = f"{requirement.title}. {requirement.text}"
        retrieved_ids = _retrieved_ids_for_case(case, query, retrievers, retrieval_method, k)
        predictions.append(
            assessor.predict(
                case=case.to_prediction_input(),
                requirement=requirement,
                evidence_by_id=evidence_by_id,
                retrieved_evidence_ids=retrieved_ids,
                config={"retrieval_method": retrieval_method, "k": k, "seed": seed},
            )
        )
    return predictions


def _majority_label(cases: list[BenchmarkCase]) -> str:
    counts = Counter(case.ground_truth_status for case in cases)
    return counts.most_common(1)[0][0]


def _mutation_drop(cases: list[BenchmarkCase], predictions: list[SystemPrediction]) -> float:
    base_pairs = [(case, pred) for case, pred in zip(cases, predictions) if not case.mutation_type]
    mutation_pairs = [(case, pred) for case, pred in zip(cases, predictions) if case.mutation_type]
    if not base_pairs or not mutation_pairs:
        return 0.0
    base_metrics = compliance_metrics([case for case, _ in base_pairs], [pred for _, pred in base_pairs])
    mutation_metrics = compliance_metrics([case for case, _ in mutation_pairs], [pred for _, pred in mutation_pairs])
    return base_metrics["macro_f1"] - mutation_metrics["macro_f1"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate compliance status classification.")
    parser.add_argument("--method", choices=["bm25", "tfidf", "dense"], default="bm25")
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--version", choices=["v01", "v02", "v03", "v04"], default="v01")
    parser.add_argument("--requirements", default="data/processed/requirements.json")
    parser.add_argument("--evidence", default="data/synthetic_cases/evidence_passages.jsonl")
    parser.add_argument("--cases", default="data/benchmark/benchmark_cases.jsonl")
    args = parser.parse_args()

    args.requirements, args.evidence, args.cases = _default_paths(args.version, args.requirements, args.evidence, args.cases)
    requirements_by_id = {item.requirement_id: item for item in load_requirements(ROOT / args.requirements)}
    cases, passages = _load_cases_and_passages(args.version, args.cases, args.evidence)

    if args.version in {"v03", "v04"}:
        baseline_specs = [
            ("random", "none", RandomComplianceAssessor(args.seed)),
            ("majority", "none", MajorityClassComplianceAssessor(_majority_label(cases))),
            ("always_unclear", "none", ConstantStatusComplianceAssessor("unclear")),
            ("always_not_fulfilled", "none", ConstantStatusComplianceAssessor("not_fulfilled")),
            ("bm25_metadata_blind_rules", "bm25", RuleBasedComplianceAssessor(metadata_aware=False)),
            ("bm25_metadata_aware_rules", "bm25", RuleBasedComplianceAssessor(metadata_aware=True)),
            ("tfidf_metadata_aware_rules", "tfidf", RuleBasedComplianceAssessor(metadata_aware=True)),
            ("oracle_retrieval_metadata_aware_rules", "oracle", RuleBasedComplianceAssessor(metadata_aware=True)),
            ("bm25_provenance_balanced", "bm25", ProvenanceAwareEvidenceAssessor(policy="balanced")),
            ("bm25_provenance_conservative", "bm25", ProvenanceAwareEvidenceAssessor(policy="conservative")),
            (
                "bm25_provenance_conservative_source_guard",
                "bm25",
                ProvenanceAwareEvidenceAssessor(policy="conservative", use_source_guard=True),
            ),
            ("oracle_retrieval_provenance_balanced", "oracle", ProvenanceAwareEvidenceAssessor(policy="balanced")),
        ]
    elif args.version == "v02":
        baseline_specs = [
            ("random", "none", RandomComplianceAssessor(args.seed)),
            ("majority_class", "none", MajorityClassComplianceAssessor(_majority_label(cases))),
            ("always_unclear", "none", ConstantStatusComplianceAssessor("unclear")),
            ("always_not_fulfilled", "none", ConstantStatusComplianceAssessor("not_fulfilled")),
            ("bm25_metadata_aware", "bm25", RuleBasedComplianceAssessor(metadata_aware=True)),
            ("bm25_metadata_blind", "bm25", RuleBasedComplianceAssessor(metadata_aware=False)),
            ("tfidf_metadata_aware", "tfidf", RuleBasedComplianceAssessor(metadata_aware=True)),
            ("oracle_metadata_aware", "oracle", RuleBasedComplianceAssessor(metadata_aware=True)),
            ("retrieval_only_bm25", "bm25", RetrievalOnlyComplianceAssessor()),
        ]
    else:
        baseline_specs = [(args.method, args.method, RuleBasedComplianceAssessor(metadata_aware=True))]

    summary_rows = []
    all_outputs = {}
    primary_predictions: list[SystemPrediction] | None = None
    primary_cases = cases
    for baseline_name, retrieval_method, assessor in baseline_specs:
        predictions = run_predictions(
            cases,
            requirements_by_id,
            passages,
            retrieval_method,
            args.k,
            assessor,
            seed=args.seed,
        )
        metrics = compliance_metrics(cases, predictions)
        if args.version in {"v02", "v03", "v04"}:
            metrics["performance_drop_under_mutation"] = _mutation_drop(cases, predictions)
        summary_rows.append({"baseline": baseline_name, **metrics})
        all_outputs[baseline_name] = {
            "retrieval_method": retrieval_method,
            "model_or_method": predictions[0].model_or_method if predictions else "",
            "metrics": metrics,
        }
        write_jsonl(
            ROOT / f"experiments/results/compliance_predictions_{baseline_name}_k{args.k}_{args.version}.jsonl",
            [prediction.to_dict() for prediction in predictions],
        )
        write_csv(
            ROOT / f"experiments/results/compliance_predictions_{baseline_name}_k{args.k}_{args.version}.csv",
            prediction_rows(cases, predictions),
        )
        if baseline_name in {"bm25_metadata_aware", "bm25_provenance_balanced"} or (args.version not in {"v02", "v03", "v04"} and baseline_name == args.method):
            primary_predictions = predictions

    if primary_predictions is None:
        primary_predictions = run_predictions(
            cases,
            requirements_by_id,
            passages,
            args.method,
            args.k,
            RuleBasedComplianceAssessor(metadata_aware=True),
            seed=args.seed,
        )

    suffix = f"_{args.version}" if args.version in {"v02", "v03", "v04"} else ""
    output_base = ROOT / f"experiments/results/compliance_eval_{args.method}_k{args.k}{suffix}"
    primary_metrics = compliance_metrics(primary_cases, primary_predictions)
    if args.version in {"v02", "v03", "v04"}:
        primary_metrics["performance_drop_under_mutation"] = _mutation_drop(primary_cases, primary_predictions)
    write_json(
        output_base.with_suffix(".json"),
        {
            "method": args.method,
            "k": args.k,
            "version": args.version,
            "metrics": primary_metrics,
            "num_cases": len(primary_cases),
            "baselines": all_outputs,
        },
    )
    write_csv(output_base.with_name(output_base.name + "_confusion").with_suffix(".csv"), confusion_rows(primary_cases, primary_predictions))

    if args.version == "v02":
        write_json(
            ROOT / "experiments/results/summary_v02.json",
            {
                "version": "v02",
                "k": args.k,
                "num_cases": len(cases),
                "primary_baseline": "bm25_metadata_aware",
                "primary_metrics": primary_metrics,
                "baselines": all_outputs,
            },
        )
        write_csv(ROOT / "experiments/results/summary_v02.csv", summary_rows)
        write_csv(ROOT / "experiments/results/by_label_v02.csv", grouped_metrics(primary_cases, primary_predictions, "label"))
        write_csv(ROOT / "experiments/results/by_difficulty_v02.csv", grouped_metrics(primary_cases, primary_predictions, "difficulty_type"))
        write_csv(ROOT / "experiments/results/by_source_type_v02.csv", grouped_metrics(primary_cases, primary_predictions, "source_type"))
        write_csv(ROOT / "experiments/results/by_language_v02.csv", grouped_metrics(primary_cases, primary_predictions, "language"))
        write_csv(ROOT / "experiments/results/by_mutation_type_v02.csv", grouped_metrics(primary_cases, primary_predictions, "mutation_type"))
        write_csv(ROOT / "experiments/results/confusion_matrix_v02.csv", confusion_rows(primary_cases, primary_predictions))
        write_csv(ROOT / "experiments/results/ablation_v02.csv", summary_rows)
    elif args.version in {"v03", "v04"}:
        suffix_name = args.version
        write_json(
            ROOT / f"experiments/results/summary_{suffix_name}.json",
            {
                "version": suffix_name,
                "k": args.k,
                "num_cases": len(cases),
                "primary_baseline": "bm25_provenance_balanced",
                "primary_metrics": primary_metrics,
                "baselines": all_outputs,
            },
        )
        write_csv(ROOT / f"experiments/results/summary_{suffix_name}.csv", summary_rows)
        by_split_rows = grouped_metrics(primary_cases, primary_predictions, "split")
        write_csv(ROOT / f"experiments/results/by_split_{suffix_name}.csv", by_split_rows)
        write_csv(ROOT / f"experiments/results/by_method_{suffix_name}.csv", summary_rows)
        write_csv(ROOT / f"experiments/results/by_difficulty_{suffix_name}.csv", grouped_metrics(primary_cases, primary_predictions, "difficulty_type"))
        write_csv(ROOT / f"experiments/results/ablation_{suffix_name}.csv", summary_rows)
        write_csv(
            ROOT / f"experiments/results/risk_weighted_errors_{suffix_name}.csv",
            [
                {
                    "method": row["baseline"],
                    "risk_weighted_error": row["risk_weighted_error"],
                    "false_compliance_rate": row["false_compliance_rate"],
                    "abstention_rate": row["abstention_rate"],
                    "over_conservatism_rate": row["over_conservatism_rate"],
                    "false_non_compliance_rate": row["false_non_compliance_rate"],
                }
                for row in summary_rows
            ],
        )
        if args.version == "v04":
            base = next((row for row in by_split_rows if row["split"] == "heldout_template"), None)
            para = next((row for row in by_split_rows if row["split"] == "paraphrase_stress_v04"), None)
            existing = []
            para_path = ROOT / "experiments/results/paraphrase_stress_v04.csv"
            if para_path.exists():
                from kisec.utils.tabular import read_csv

                existing = read_csv(para_path)
            if base and para:
                existing.append(
                    {
                        "surface": "classification",
                        "method": "bm25_provenance_balanced",
                        "num_cases": para["num_cases"],
                        "macro_f1": para["macro_f1"],
                        "false_compliance_rate": para["false_compliance_rate"],
                        "source_attribution_error_rate": "",
                        "baseline_macro_f1": base["macro_f1"],
                        "paraphrase_macro_f1": para["macro_f1"],
                        "macro_f1_drop": base["macro_f1"] - para["macro_f1"],
                        "baseline_false_compliance": base["false_compliance_rate"],
                        "paraphrase_false_compliance": para["false_compliance_rate"],
                    }
                )
                write_csv(para_path, existing)
        confusion_dir = ROOT / f"experiments/results/confusion_matrices_{suffix_name}"
        confusion_dir.mkdir(parents=True, exist_ok=True)
        for baseline_name in all_outputs:
            pred_path = ROOT / f"experiments/results/compliance_predictions_{baseline_name}_k{args.k}_{args.version}.jsonl"
            preds = [SystemPrediction.from_dict(item) for item in read_jsonl(pred_path)]
            write_csv(confusion_dir / f"{baseline_name}.csv", confusion_rows(cases, preds))
        write_csv(ROOT / f"experiments/results/confusion_matrix_{suffix_name}.csv", confusion_rows(primary_cases, primary_predictions))
        source_guard_rows = []
        for baseline_name in all_outputs:
            pred_path = ROOT / f"experiments/results/compliance_predictions_{baseline_name}_k{args.k}_{args.version}.jsonl"
            preds = [SystemPrediction.from_dict(item) for item in read_jsonl(pred_path)]
            total_errors = sum(len(pred.source_attribution_errors_detected) for pred in preds)
            affected = sum(1 for pred in preds if pred.source_attribution_errors_detected)
            source_guard_rows.append(
                {
                    "method": baseline_name,
                    "num_cases": len(preds),
                    "cases_with_source_guard_findings": affected,
                    "source_guard_findings": total_errors,
                }
            )
        write_csv(ROOT / f"experiments/results/source_guard_{suffix_name}.csv", source_guard_rows)
    else:
        write_csv(output_base.with_name(output_base.name + "_predictions").with_suffix(".csv"), prediction_rows(primary_cases, primary_predictions))

    print(primary_metrics)


if __name__ == "__main__":
    main()
