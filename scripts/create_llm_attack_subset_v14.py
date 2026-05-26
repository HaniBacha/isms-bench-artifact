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


SOURCES = [
    ("adaptive_attack", "data/attacks/adaptive_attack_cases_v04.jsonl", 75),
    ("original_attack", "data/attacks/attack_cases_v03.jsonl", 75),
]


def _load(path: str) -> list[BenchmarkCase]:
    return [BenchmarkCase.from_dict(row) for row in read_jsonl(ROOT / path)]


def _balanced_sample(cases: list[BenchmarkCase], n: int, rng: random.Random) -> list[BenchmarkCase]:
    by_type: dict[str, list[BenchmarkCase]] = {}
    for case in cases:
        by_type.setdefault(case.attack_type or "unknown", []).append(case)
    for bucket in by_type.values():
        rng.shuffle(bucket)
    selected: list[BenchmarkCase] = []
    attack_types = sorted(by_type)
    while len(selected) < min(n, len(cases)):
        progressed = False
        for attack_type in attack_types:
            bucket = by_type.get(attack_type, [])
            if bucket and len(selected) < n:
                selected.append(bucket.pop())
                progressed = True
        if not progressed:
            break
    if len(selected) < n:
        remaining = [case for bucket in by_type.values() for case in bucket]
        rng.shuffle(remaining)
        selected.extend(remaining[: n - len(selected)])
    return selected[:n]


def _tag(cases: list[BenchmarkCase], suite: str) -> list[BenchmarkCase]:
    tagged: list[BenchmarkCase] = []
    for case in cases:
        metadata = dict(case.metadata)
        metadata["llm_attack_suite"] = suite
        metadata["llm_eval_suite"] = suite
        tagged.append(replace(case, metadata=metadata))
    return tagged


def main() -> None:
    parser = argparse.ArgumentParser(description="Create attack-only LLM evaluation subset for v1.4.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--adaptive", type=int, default=75)
    parser.add_argument("--original", type=int, default=75)
    args = parser.parse_args()
    requested = {"adaptive_attack": args.adaptive, "original_attack": args.original}
    rng = random.Random(args.seed)

    selected_all: list[BenchmarkCase] = []
    rows: list[dict] = []
    for suite, path, default_n in SOURCES:
        n = requested.get(suite, default_n)
        available = _load(path)
        selected = _balanced_sample(available, n, rng)
        tagged = _tag(selected, suite)
        selected_all.extend(tagged)
        rows.append(
            {
                "suite": suite,
                "source_path": path,
                "available": len(available),
                "requested": n,
                "selected": len(selected),
                "attack_types": "|".join(sorted({case.attack_type or "unknown" for case in selected})),
            }
        )

    jsonl_path = ROOT / "data/attacks/llm_attack_subset_v14.jsonl"
    csv_path = ROOT / "data/attacks/llm_attack_subset_v14.csv"
    write_jsonl(jsonl_path, [case.to_dict() for case in selected_all])
    write_csv(
        csv_path,
        [
            {
                "case_id": case.case_id,
                "requirement_id": case.requirement_id,
                "ground_truth_status": case.ground_truth_status,
                "attack_type": case.attack_type or "",
                "llm_attack_suite": case.metadata.get("llm_attack_suite", ""),
                "num_company_documents": len(case.company_document_ids),
            }
            for case in selected_all
        ],
    )
    write_csv(ROOT / "data/attacks/llm_attack_subset_v14_summary.csv", rows)
    print({"attack_cases": len(selected_all), "seed": args.seed, "composition": rows})


if __name__ == "__main__":
    main()
