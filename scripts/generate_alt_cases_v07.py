#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.benchmark.alt_generator_v07 import (
    generate_alt_cases_v07,
    generate_independent_challenge_v07,
    generate_public_template_distractors_v07,
)
from kisec.ingestion.requirements import load_requirements, write_default_requirements_v02
from kisec.utils.io import write_json, write_jsonl
from kisec.utils.tabular import write_csv


def _requirements():
    path = ROOT / "data/processed/requirements_v03.json"
    if path.exists():
        return load_requirements(path)
    return write_default_requirements_v02(path)


def _counts(cases):
    return dict(Counter(case.ground_truth_status for case in cases))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate v0.7 independent and alternative benchmark surfaces.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--independent-n", type=int, default=80)
    parser.add_argument("--alt-n", type=int, default=400)
    parser.add_argument("--distractor-n", type=int, default=36)
    args = parser.parse_args()

    requirements = _requirements()
    independent = generate_independent_challenge_v07(requirements, n=args.independent_n, seed=args.seed)
    alt = generate_alt_cases_v07(requirements, n=args.alt_n, seed=args.seed)
    distractors = generate_public_template_distractors_v07(n=args.distractor_n, seed=args.seed)

    write_jsonl(ROOT / "data/benchmark/independent_challenge_cases_v07.jsonl", [case.to_dict() for case in independent.cases])
    write_csv(ROOT / "data/benchmark/independent_challenge_cases_v07.csv", [case.to_dict() for case in independent.cases])
    write_jsonl(ROOT / "data/synthetic_cases/independent_challenge_evidence_v07.jsonl", [p.to_dict() for p in independent.passages])
    write_csv(ROOT / "data/synthetic_cases/independent_challenge_evidence_v07.csv", [p.to_dict() for p in independent.passages])

    write_jsonl(ROOT / "data/benchmark/alt_generator_cases_v07.jsonl", [case.to_dict() for case in alt.cases])
    write_csv(ROOT / "data/benchmark/alt_generator_cases_v07.csv", [case.to_dict() for case in alt.cases])
    write_jsonl(ROOT / "data/synthetic_cases/alt_generator_evidence_v07.jsonl", [p.to_dict() for p in alt.passages])
    write_csv(ROOT / "data/synthetic_cases/alt_generator_evidence_v07.csv", [p.to_dict() for p in alt.passages])

    write_jsonl(ROOT / "data/benchmark/public_template_distractors_v07.jsonl", [p.to_dict() for p in distractors])
    write_csv(ROOT / "data/benchmark/public_template_distractors_v07.csv", [p.to_dict() for p in distractors])

    write_json(
        ROOT / "data/benchmark/summary_v07.json",
        {
            "seed": args.seed,
            "independent_challenge_cases": len(independent.cases),
            "independent_challenge_label_counts": _counts(independent.cases),
            "independent_challenge_evidence_passages": len(independent.passages),
            "alt_generator_cases": len(alt.cases),
            "alt_generator_label_counts": _counts(alt.cases),
            "alt_generator_evidence_passages": len(alt.passages),
            "public_template_distractors": len(distractors),
        },
    )
    print(
        {
            "independent_challenge_cases": len(independent.cases),
            "alt_generator_cases": len(alt.cases),
            "public_template_distractors": len(distractors),
        }
    )


if __name__ == "__main__":
    main()
