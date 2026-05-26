#!/usr/bin/env python
from __future__ import annotations

import argparse
import random
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.models import BenchmarkCase
from kisec.utils.io import read_jsonl, write_jsonl
from kisec.utils.tabular import write_csv


NON_ATTACK_SUITES = [
    ("development", "data/benchmark/benchmark_cases_v03_development_template.jsonl", 50),
    ("heldout", "data/benchmark/benchmark_cases_v03_heldout_template.jsonl", 50),
    ("stress", "data/benchmark/benchmark_cases_v03_stress_test.jsonl", 50),
    ("mutation", "data/benchmark/mutation_cases_v03.jsonl", 50),
    ("paraphrase_multilingual", "data/benchmark/paraphrase_stress_cases_v04.jsonl", 50),
    ("manual_challenge", "data/benchmark/manual_challenge_cases_v09.jsonl", 50),
]

ATTACK_SUITES = [
    ("adaptive_attack", "data/attacks/adaptive_attack_cases_v04.jsonl", 100),
    ("original_attack", "data/attacks/attack_cases_v03.jsonl", 50),
]


def _load(path: str) -> list[BenchmarkCase]:
    return [BenchmarkCase.from_dict(row) for row in read_jsonl(ROOT / path)]


def _balanced_sample(cases: list[BenchmarkCase], n: int, rng: random.Random) -> list[BenchmarkCase]:
    by_label: dict[str, list[BenchmarkCase]] = {}
    for case in cases:
        by_label.setdefault(case.ground_truth_status, []).append(case)
    for values in by_label.values():
        rng.shuffle(values)
    labels = ["fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"]
    selected: list[BenchmarkCase] = []
    while len(selected) < min(n, len(cases)):
        progressed = False
        for label in labels:
            bucket = by_label.get(label, [])
            if bucket and len(selected) < n:
                selected.append(bucket.pop())
                progressed = True
        if not progressed:
            break
    if len(selected) < n:
        remaining = [case for bucket in by_label.values() for case in bucket]
        rng.shuffle(remaining)
        selected.extend(remaining[: n - len(selected)])
    return selected[:n]


def _tag(cases: list[BenchmarkCase], suite: str) -> list[BenchmarkCase]:
    tagged: list[BenchmarkCase] = []
    for case in cases:
        metadata = dict(case.metadata)
        metadata["llm_eval_suite"] = suite
        tagged.append(replace(case, metadata=metadata))
    return tagged


def main() -> None:
    parser = argparse.ArgumentParser(description="Create stratified LLM evaluation subsets for v1.3.")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    rng = random.Random(args.seed)

    non_attack: list[BenchmarkCase] = []
    attack: list[BenchmarkCase] = []
    summary_rows: list[dict] = []
    for suite, path, n in NON_ATTACK_SUITES:
        selected = _balanced_sample(_load(path), n, rng)
        non_attack.extend(_tag(selected, suite))
        summary_rows.append({"subset": "non_attack", "suite": suite, "requested": n, "selected": len(selected)})
    for suite, path, n in ATTACK_SUITES:
        selected = _balanced_sample(_load(path), n, rng)
        attack.extend(_tag(selected, suite))
        summary_rows.append({"subset": "attack", "suite": suite, "requested": n, "selected": len(selected)})

    write_jsonl(ROOT / "data/benchmark/llm_eval_subset_v13.jsonl", [case.to_dict() for case in non_attack])
    write_jsonl(ROOT / "data/attacks/llm_attack_subset_v13.jsonl", [case.to_dict() for case in attack])
    write_csv(ROOT / "data/benchmark/llm_eval_subset_v13_summary.csv", summary_rows)
    print({"non_attack_cases": len(non_attack), "attack_cases": len(attack), "seed": args.seed})


if __name__ == "__main__":
    main()
