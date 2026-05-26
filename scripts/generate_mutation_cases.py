#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.benchmark.mutations import generate_mutation_cases
from kisec.models import BenchmarkCase, EvidencePassage
from kisec.utils.io import read_jsonl, write_json, write_jsonl
from kisec.utils.tabular import write_csv


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate mutation-based ISMS-Bench cases.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--version", choices=["v02", "v03"], default="v02")
    parser.add_argument("--max-base-cases", type=int, default=None)
    parser.add_argument("--cases", default="data/benchmark/benchmark_cases_v02.jsonl")
    parser.add_argument("--evidence", default="data/synthetic_cases/evidence_passages_v02.jsonl")
    parser.add_argument("--cases-out", default="data/benchmark/mutation_cases_v02.jsonl")
    parser.add_argument("--evidence-out", default="data/synthetic_cases/mutation_evidence_passages_v02.jsonl")
    args = parser.parse_args()

    if args.version == "v03":
        if args.cases == "data/benchmark/benchmark_cases_v02.jsonl":
            args.cases = "data/benchmark/benchmark_cases_v03_development_template.jsonl"
        if args.evidence == "data/synthetic_cases/evidence_passages_v02.jsonl":
            args.evidence = "data/synthetic_cases/evidence_passages_v03_development_template.jsonl"
        if args.cases_out == "data/benchmark/mutation_cases_v02.jsonl":
            args.cases_out = "data/benchmark/mutation_cases_v03.jsonl"
        if args.evidence_out == "data/synthetic_cases/mutation_evidence_passages_v02.jsonl":
            args.evidence_out = "data/synthetic_cases/mutation_evidence_passages_v03.jsonl"
    max_base_cases = args.max_base_cases
    if max_base_cases is None:
        max_base_cases = 20 if args.version == "v03" else 15

    cases = [BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / args.cases)]
    passages = [EvidencePassage.from_dict(item) for item in read_jsonl(ROOT / args.evidence)]
    by_document_id: dict[str, list[EvidencePassage]] = defaultdict(list)
    for passage in passages:
        by_document_id[passage.document_id].append(passage)

    fulfilled_cases = [case for case in cases if case.ground_truth_status == "fulfilled"]
    mutation_cases, mutation_passages = generate_mutation_cases(
        fulfilled_cases,
        by_document_id,
        max_base_cases=max_base_cases,
    )

    write_jsonl(ROOT / args.cases_out, [case.to_dict() for case in mutation_cases])
    write_jsonl(ROOT / args.evidence_out, [passage.to_dict() for passage in mutation_passages])
    suffix = args.version
    write_csv(ROOT / f"data/benchmark/mutation_cases_{suffix}.csv", [case.to_dict() for case in mutation_cases])
    write_csv(
        ROOT / f"data/synthetic_cases/mutation_evidence_passages_{suffix}.csv",
        [passage.to_dict() for passage in mutation_passages],
    )
    write_json(
        ROOT / f"data/benchmark/mutation_summary_{suffix}.json",
        {
            "seed": args.seed,
            "version": args.version,
            "num_mutation_cases": len(mutation_cases),
            "num_mutation_evidence_passages": len(mutation_passages),
            "max_base_cases": max_base_cases,
        },
    )
    print(f"Wrote {len(mutation_cases)} mutation cases.")


if __name__ == "__main__":
    main()
