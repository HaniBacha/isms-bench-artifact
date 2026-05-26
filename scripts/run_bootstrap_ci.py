#!/usr/bin/env python
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.evaluation.bootstrap import bootstrap_ci
from kisec.evaluation.metrics import attack_metrics, compliance_metrics
from kisec.models import BenchmarkCase, EvidencePassage, SystemPrediction, is_more_compliant
from kisec.utils.io import read_jsonl
from kisec.utils.tabular import write_csv


METHODS = [
    "bm25_metadata_aware_rules",
    "bm25_provenance_balanced",
    "bm25_provenance_conservative",
]

ATTACK_METHODS = [
    "metadata_aware",
    "provenance_balanced",
    "provenance_conservative",
]


def _load_v04_cases() -> tuple[list[BenchmarkCase], list[EvidencePassage]]:
    cases: list[BenchmarkCase] = []
    passages: list[EvidencePassage] = []
    for split in ["development_template", "heldout_template", "stress_test"]:
        cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / f"data/benchmark/benchmark_cases_v03_{split}.jsonl"))
        passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(ROOT / f"data/synthetic_cases/evidence_passages_v03_{split}.jsonl"))
    for case_path, evidence_path in [
        ("data/benchmark/mutation_cases_v03.jsonl", "data/synthetic_cases/mutation_evidence_passages_v03.jsonl"),
        ("data/benchmark/paraphrase_stress_cases_v04.jsonl", "data/synthetic_cases/paraphrase_stress_evidence_v04.jsonl"),
    ]:
        if (ROOT / case_path).exists() and (ROOT / evidence_path).exists():
            cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / case_path))
            passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(ROOT / evidence_path))
    return cases, passages


def _load_combined_attack_cases() -> tuple[list[BenchmarkCase], list[EvidencePassage]]:
    cases: list[BenchmarkCase] = []
    passages: list[EvidencePassage] = []
    for case_path, evidence_path in [
        ("data/attacks/attack_cases_v03.jsonl", "data/attacks/attack_evidence_passages_v03.jsonl"),
        ("data/attacks/adaptive_attack_cases_v04.jsonl", "data/attacks/adaptive_attack_evidence_passages_v04.jsonl"),
    ]:
        cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / case_path))
        passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(ROOT / evidence_path))
    return cases, passages


def _subset_predictions(predictions: list[SystemPrediction], case_ids: set[str]) -> list[SystemPrediction]:
    return [pred for pred in predictions if pred.case_id in case_ids]


def _normal_approx_mcnemar(b: int, c: int) -> float:
    total = b + c
    if total == 0:
        return 1.0
    stat = (abs(b - c) - 1) ** 2 / total
    return math.erfc(math.sqrt(stat / 2))


def _macro_f1_from_pairs(sample) -> float:
    labels = ["fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"]
    scores = []
    for label in labels:
        tp = sum(1 for case, pred in sample if case.ground_truth_status == label and pred.predicted_status == label)
        fp = sum(1 for case, pred in sample if case.ground_truth_status != label and pred.predicted_status == label)
        fn = sum(1 for case, pred in sample if case.ground_truth_status == label and pred.predicted_status != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        scores.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    return sum(scores) / len(scores)


def _risk_from_pairs(sample) -> float:
    from kisec.evaluation.metrics import risk_weighted_error

    return risk_weighted_error([case for case, _ in sample], [pred for _, pred in sample])


def _attack_metric_fast(sample, evidence_by_id, metric_name: str) -> float:
    result = attack_metrics([case for case, _ in sample], [pred for _, pred in sample], evidence_by_id)["overall"]
    return result[metric_name]


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap confidence intervals for v0.4 metrics.")
    parser.add_argument("--version", choices=["v04"], default="v04")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--resamples", type=int, default=120)
    args = parser.parse_args()

    cases, clean_passages = _load_v04_cases()
    case_by_id = {case.case_id: case for case in cases}
    rows = []
    prediction_cache: dict[str, list[SystemPrediction]] = {}
    for method in METHODS:
        path = ROOT / f"experiments/results/compliance_predictions_{method}_k5_v04.jsonl"
        if not path.exists():
            continue
        predictions = [SystemPrediction.from_dict(item) for item in read_jsonl(path)]
        prediction_cache[method] = predictions
        items = [(case_by_id[pred.case_id], pred) for pred in predictions]

        metric_fns = {
            "macro_f1": _macro_f1_from_pairs,
            "false_compliance_rate": lambda sample: sum(
                is_more_compliant(pred.predicted_status, case.ground_truth_status) for case, pred in sample
            )
            / len(sample)
            if sample
            else 0.0,
            "abstention_rate": lambda sample: sum(1 for _, pred in sample if pred.predicted_status == "unclear") / len(sample) if sample else 0.0,
            "risk_weighted_error": _risk_from_pairs,
        }
        for metric_name, metric_fn in metric_fns.items():
            ci = bootstrap_ci(items, metric_fn, seed=args.seed, n_resamples=args.resamples)
            rows.append({"surface": "compliance", "method": method, "metric": metric_name, **ci})

    attack_cases, attack_passages = _load_combined_attack_cases()
    all_passages = clean_passages + attack_passages
    evidence_by_id = {passage.evidence_id: passage for passage in all_passages}
    attack_case_by_id = {case.case_id: case for case in attack_cases}
    for method in ATTACK_METHODS:
        path = ROOT / f"experiments/results/attack_predictions_combined_attack_suite_{method}_bm25_k5_v04.jsonl"
        if not path.exists():
            continue
        predictions = [SystemPrediction.from_dict(item) for item in read_jsonl(path)]
        items = [(attack_case_by_id[pred.case_id], pred) for pred in predictions]

        for metric_name in ["attack_success_rate", "full_attack_success_rate", "partial_attack_success_rate", "abstention_rate", "residual_attack_risk_score"]:
            if metric_name == "abstention_rate":
                ci = bootstrap_ci(
                    items,
                    lambda sample: sum(1 for _, pred in sample if pred.predicted_status == "unclear") / len(sample) if sample else 0.0,
                    seed=args.seed,
                    n_resamples=args.resamples,
                )
            else:
                ci = bootstrap_ci(items, lambda sample, name=metric_name: _attack_metric_fast(sample, evidence_by_id, name), seed=args.seed, n_resamples=args.resamples)
            rows.append({"surface": "attack", "method": method, "metric": metric_name, **ci})

    write_csv(ROOT / "experiments/results/bootstrap_ci_v04.csv", rows)

    comparison_rows = []
    if "bm25_metadata_aware_rules" in prediction_cache and "bm25_provenance_balanced" in prediction_cache:
        a = {pred.case_id: pred for pred in prediction_cache["bm25_metadata_aware_rules"]}
        b = {pred.case_id: pred for pred in prediction_cache["bm25_provenance_balanced"]}
        shared = sorted(set(a) & set(b))
        b_only_correct = c_only_correct = 0
        for case_id in shared:
            truth = case_by_id[case_id].ground_truth_status
            a_correct = a[case_id].predicted_status == truth
            b_correct = b[case_id].predicted_status == truth
            if b_correct and not a_correct:
                b_only_correct += 1
            if a_correct and not b_correct:
                c_only_correct += 1
        comparison_rows.append(
            {
                "comparison": "provenance_balanced_vs_metadata_aware",
                "test": "mcnemar_normal_approx",
                "b_only_correct": b_only_correct,
                "c_only_correct": c_only_correct,
                "p_value_approx": _normal_approx_mcnemar(b_only_correct, c_only_correct),
                "notes": "Approximate McNemar test on paired classification correctness.",
            }
        )
        pair_items = [(case_by_id[case_id], a[case_id], b[case_id]) for case_id in shared]
        ci = bootstrap_ci(
            pair_items,
            lambda sample: (
                sum(is_more_compliant(old.predicted_status, case.ground_truth_status) for case, old, _ in sample)
                - sum(is_more_compliant(new.predicted_status, case.ground_truth_status) for case, _, new in sample)
            )
            / len(sample),
            seed=args.seed,
            n_resamples=args.resamples,
        )
        comparison_rows.append(
            {
                "comparison": "false_compliance_reduction_provenance_vs_metadata",
                "test": "paired_bootstrap_difference",
                "b_only_correct": "",
                "c_only_correct": "",
                "p_value_approx": "",
                "estimate": ci["estimate"],
                "ci_low": ci["ci_low"],
                "ci_high": ci["ci_high"],
                "notes": "Positive value means provenance-balanced reduces false compliance.",
            }
        )
    write_csv(ROOT / "experiments/results/method_comparison_tests_v04.csv", comparison_rows)
    print({"bootstrap_rows": len(rows), "comparison_rows": len(comparison_rows)})


if __name__ == "__main__":
    main()
