#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.compliance.provenance_assessor import ProvenanceAwareEvidenceAssessor
from kisec.compliance.rule_based import RuleBasedComplianceAssessor
from kisec.evaluation.metrics import attack_metrics, compliance_metrics
from kisec.ingestion.requirements import load_requirements
from kisec.models import BenchmarkCase, EvidencePassage
from kisec.retrieval.factory import make_retriever
from kisec.utils.io import read_jsonl, write_json, write_jsonl
from kisec.utils.tabular import write_csv


def _predict_cases(cases, requirements_by_id, passages, method, k, assessor):
    retriever = make_retriever(method).fit(passages)
    evidence_by_id = {passage.evidence_id: passage for passage in passages}
    predictions = []
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
                config={"retrieval_method": method, "k": k, "attack_eval": True},
            )
        )
    return predictions


def _load_v03_clean_data():
    clean_passages = []
    clean_cases = []
    for split in ["development_template", "heldout_template", "stress_test"]:
        clean_passages.extend(
            EvidencePassage.from_dict(item)
            for item in read_jsonl(ROOT / f"data/synthetic_cases/evidence_passages_v03_{split}.jsonl")
        )
        clean_cases.extend(
            BenchmarkCase.from_dict(item)
            for item in read_jsonl(ROOT / f"data/benchmark/benchmark_cases_v03_{split}.jsonl")
        )
    mutation_cases_path = ROOT / "data/benchmark/mutation_cases_v03.jsonl"
    mutation_evidence_path = ROOT / "data/synthetic_cases/mutation_evidence_passages_v03.jsonl"
    if mutation_cases_path.exists() and mutation_evidence_path.exists():
        clean_cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(mutation_cases_path))
        clean_passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(mutation_evidence_path))
    return clean_cases, clean_passages


def _v04_baselines():
    return [
        ("metadata_blind", RuleBasedComplianceAssessor(metadata_aware=False)),
        ("metadata_aware", RuleBasedComplianceAssessor(metadata_aware=True)),
        ("provenance_balanced", ProvenanceAwareEvidenceAssessor(policy="balanced")),
        ("provenance_conservative", ProvenanceAwareEvidenceAssessor(policy="conservative")),
        (
            "provenance_conservative_with_source_guard",
            ProvenanceAwareEvidenceAssessor(policy="conservative", use_source_guard=True),
        ),
    ]


def _evaluate_attack_suite(
    *,
    suite_name: str,
    attack_cases: list[BenchmarkCase],
    attack_passages: list[EvidencePassage],
    clean_cases: list[BenchmarkCase],
    clean_passages: list[EvidencePassage],
    requirements_by_id,
    method: str,
    k: int,
    baselines,
) -> tuple[list[dict], list[dict], dict]:
    all_passages = clean_passages + attack_passages
    evidence_by_id = {passage.evidence_id: passage for passage in all_passages}
    method_rows = []
    by_type_rows = []
    all_metrics = {}
    for baseline_name, assessor in baselines:
        clean_predictions = _predict_cases(clean_cases, requirements_by_id, clean_passages, method, k, assessor)
        clean_by_case_id = {prediction.case_id: prediction for prediction in clean_predictions}
        attack_predictions = _predict_cases(attack_cases, requirements_by_id, all_passages, method, k, assessor)
        metrics = attack_metrics(attack_cases, attack_predictions, evidence_by_id, clean_by_case_id)
        metrics["compliance_on_attack_cases"] = compliance_metrics(attack_cases, attack_predictions)
        all_metrics[baseline_name] = metrics
        compliance_on_attack_cases = {
            f"classification_{key}": value
            for key, value in metrics["compliance_on_attack_cases"].items()
        }
        row = {
            "attack_suite": suite_name,
            "method": baseline_name,
            **metrics["overall"],
            **compliance_on_attack_cases,
        }
        method_rows.append(row)
        for by_type in metrics["by_attack_type"]:
            by_type_rows.append({"attack_suite": suite_name, "method": baseline_name, **by_type})
        write_jsonl(
            ROOT / f"experiments/results/attack_predictions_{suite_name}_{baseline_name}_{method}_k{k}_v04.jsonl",
            [prediction.to_dict() for prediction in attack_predictions],
        )
    return method_rows, by_type_rows, all_metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate attack robustness.")
    parser.add_argument("--method", choices=["bm25", "tfidf", "dense"], default="bm25")
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--version", choices=["v01", "v02", "v03", "v04"], default="v01")
    parser.add_argument("--adaptive", action="store_true", help="Evaluate the adaptive v0.4 attack suite.")
    parser.add_argument("--requirements", default="data/processed/requirements.json")
    parser.add_argument("--evidence", default="data/synthetic_cases/evidence_passages.jsonl")
    parser.add_argument("--attack-evidence", default="data/attacks/attack_evidence_passages.jsonl")
    parser.add_argument("--cases", default="data/benchmark/benchmark_cases.jsonl")
    parser.add_argument("--attack-cases", default="data/attacks/attack_cases.jsonl")
    args = parser.parse_args()
    if args.version in {"v02", "v03", "v04"}:
        if args.requirements == "data/processed/requirements.json":
            args.requirements = "data/processed/requirements_v03.json" if args.version == "v04" else f"data/processed/requirements_{args.version}.json"
    if args.version == "v02":
        if args.evidence == "data/synthetic_cases/evidence_passages.jsonl":
            args.evidence = "data/synthetic_cases/evidence_passages_v02.jsonl"
        if args.attack_evidence == "data/attacks/attack_evidence_passages.jsonl":
            args.attack_evidence = "data/attacks/attack_evidence_passages_v02.jsonl"
        if args.cases == "data/benchmark/benchmark_cases.jsonl":
            args.cases = "data/benchmark/benchmark_cases_v02.jsonl"
        if args.attack_cases == "data/attacks/attack_cases.jsonl":
            args.attack_cases = "data/attacks/attack_cases_v02.jsonl"
    elif args.version == "v03":
        if args.attack_evidence == "data/attacks/attack_evidence_passages.jsonl":
            args.attack_evidence = "data/attacks/attack_evidence_passages_v03.jsonl"
        if args.attack_cases == "data/attacks/attack_cases.jsonl":
            args.attack_cases = "data/attacks/attack_cases_v03.jsonl"
    elif args.version == "v04":
        if args.attack_evidence == "data/attacks/attack_evidence_passages.jsonl":
            args.attack_evidence = "data/attacks/adaptive_attack_evidence_passages_v04.jsonl"
        if args.attack_cases == "data/attacks/attack_cases.jsonl":
            args.attack_cases = "data/attacks/adaptive_attack_cases_v04.jsonl"

    requirements_by_id = {item.requirement_id: item for item in load_requirements(ROOT / args.requirements)}
    if args.version == "v04":
        clean_cases, clean_passages = _load_v03_clean_data()
        original_cases = [BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / "data/attacks/attack_cases_v03.jsonl")]
        original_passages = [EvidencePassage.from_dict(item) for item in read_jsonl(ROOT / "data/attacks/attack_evidence_passages_v03.jsonl")]
        adaptive_cases = [BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / args.attack_cases)]
        adaptive_passages = [EvidencePassage.from_dict(item) for item in read_jsonl(ROOT / args.attack_evidence)]
        suites = [
            ("original_attack_cases_v03", original_cases, original_passages),
            ("adaptive_attacks_v04", adaptive_cases, adaptive_passages),
            ("combined_attack_suite", original_cases + adaptive_cases, original_passages + adaptive_passages),
        ]
        all_method_rows = []
        all_by_type_rows = []
        all_outputs = {}
        for suite_name, suite_cases, suite_passages in suites:
            method_rows, by_type_rows, metrics = _evaluate_attack_suite(
                suite_name=suite_name,
                attack_cases=suite_cases,
                attack_passages=suite_passages,
                clean_cases=clean_cases,
                clean_passages=clean_passages,
                requirements_by_id=requirements_by_id,
                method=args.method,
                k=args.k,
                baselines=_v04_baselines(),
            )
            all_method_rows.extend(method_rows)
            all_by_type_rows.extend(by_type_rows)
            all_outputs[suite_name] = metrics
            if suite_name == "adaptive_attacks_v04":
                write_csv(ROOT / "experiments/results/adaptive_attack_v04.csv", method_rows)
            if suite_name == "combined_attack_suite":
                write_csv(ROOT / "experiments/results/combined_attack_v04.csv", method_rows)
        write_csv(ROOT / "experiments/results/attack_metrics_by_method_v04.csv", all_method_rows)
        write_csv(ROOT / "experiments/results/attack_metrics_by_type_v04.csv", all_by_type_rows)
        write_csv(
            ROOT / "experiments/results/residual_attack_risk_v04.csv",
            [
                {
                    "attack_suite": row["attack_suite"],
                    "method": row["method"],
                    "residual_attack_risk_score": row["residual_attack_risk_score"],
                    "full_attack_success_rate": row["full_attack_success_rate"],
                    "partial_attack_success_rate": row["partial_attack_success_rate"],
                    "unsafe_evidence_acceptance_rate": row["unsafe_evidence_acceptance_rate"],
                    "source_attribution_failure_rate": row["source_attribution_failure_rate"],
                }
                for row in all_method_rows
            ],
        )
        write_json(
            ROOT / "experiments/results/attack_eval_v04.json",
            {
                "method": args.method,
                "k": args.k,
                "version": "v04",
                "suites": all_outputs,
            },
        )
        print({"v04_attack_suites": len(suites), "rows": len(all_method_rows)})
        return
    if args.version == "v03":
        clean_cases, clean_passages = _load_v03_clean_data()
    else:
        clean_passages = [EvidencePassage.from_dict(item) for item in read_jsonl(ROOT / args.evidence)]
        clean_cases = [BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / args.cases)]
    attack_passages = [EvidencePassage.from_dict(item) for item in read_jsonl(ROOT / args.attack_evidence)]
    all_passages = clean_passages + attack_passages
    attack_cases = [BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / args.attack_cases)]
    evidence_by_id = {passage.evidence_id: passage for passage in all_passages}

    if args.version == "v03":
        baselines = [
            ("naive_metadata_blind", RuleBasedComplianceAssessor(metadata_aware=False)),
            ("metadata_aware", RuleBasedComplianceAssessor(metadata_aware=True)),
            ("provenance_balanced", ProvenanceAwareEvidenceAssessor(policy="balanced")),
            ("provenance_conservative", ProvenanceAwareEvidenceAssessor(policy="conservative")),
            (
                "provenance_conservative_with_source_guard",
                ProvenanceAwareEvidenceAssessor(policy="conservative", use_source_guard=True),
            ),
        ]
    elif args.version == "v02":
        baselines = [
        ("metadata_aware", RuleBasedComplianceAssessor(metadata_aware=True)),
        ("metadata_blind", RuleBasedComplianceAssessor(metadata_aware=False)),
        ]
    else:
        baselines = [("metadata_aware", RuleBasedComplianceAssessor(metadata_aware=True))]

    all_metrics = {}
    by_type_rows = []
    primary_metrics = None
    for baseline_name, assessor in baselines:
        clean_predictions = _predict_cases(clean_cases, requirements_by_id, clean_passages, args.method, args.k, assessor)
        clean_by_case_id = {prediction.case_id: prediction for prediction in clean_predictions}
        attack_predictions = _predict_cases(attack_cases, requirements_by_id, all_passages, args.method, args.k, assessor)
        metrics = attack_metrics(attack_cases, attack_predictions, evidence_by_id, clean_by_case_id)
        metrics["compliance_on_attack_cases"] = compliance_metrics(attack_cases, attack_predictions)
        all_metrics[baseline_name] = metrics
        for row in metrics["by_attack_type"]:
            by_type_rows.append({"baseline": baseline_name, **row})
        if baseline_name == "metadata_aware":
            primary_metrics = metrics
        write_jsonl(
            ROOT / f"experiments/results/attack_predictions_{baseline_name}_{args.method}_k{args.k}_{args.version}.jsonl",
            [prediction.to_dict() for prediction in attack_predictions],
        )

    if primary_metrics is None:
        primary_metrics = next(iter(all_metrics.values()))

    suffix = f"_{args.version}" if args.version in {"v02", "v03"} else ""
    output_base = ROOT / f"experiments/results/attack_eval_{args.method}_k{args.k}{suffix}"
    write_json(
        output_base.with_suffix(".json"),
        {
            "method": args.method,
            "k": args.k,
            "version": args.version,
            "metrics": primary_metrics,
            "baselines": all_metrics,
            "num_cases": len(attack_cases),
        },
    )
    write_csv(output_base.with_name(output_base.name + "_by_type").with_suffix(".csv"), primary_metrics["by_attack_type"])
    if args.version == "v02":
        write_csv(ROOT / "experiments/results/by_attack_type_v02.csv", by_type_rows)
    if args.version == "v03":
        write_csv(ROOT / "experiments/results/by_attack_type_v03.csv", by_type_rows)
        method_rows = []
        for baseline_name, metrics in all_metrics.items():
            method_rows.append({"method": baseline_name, **metrics["overall"], **metrics["compliance_on_attack_cases"]})
        write_csv(ROOT / "experiments/results/attack_by_method_v03.csv", method_rows)
    print(primary_metrics["overall"])


if __name__ == "__main__":
    main()
