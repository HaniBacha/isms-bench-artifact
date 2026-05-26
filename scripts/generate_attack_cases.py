#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.attacks.generator import generate_adaptive_attack_dataset, generate_attack_dataset
from kisec.models import BenchmarkCase
from kisec.utils.io import read_jsonl, write_json, write_jsonl
from kisec.utils.tabular import write_csv


def _load_v03_cases() -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    for split in ["development_template", "heldout_template", "stress_test"]:
        path = ROOT / f"data/benchmark/benchmark_cases_v03_{split}.jsonl"
        if path.exists():
            cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(path))
    mutation_path = ROOT / "data/benchmark/mutation_cases_v03.jsonl"
    if mutation_path.exists():
        cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(mutation_path))
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate attack cases for ISMS-Bench.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--version", choices=["v02", "v03", "v04"], default="v03")
    parser.add_argument("--adaptive", action="store_true", help="Generate the adaptive v0.4 attack suite.")
    parser.add_argument("--max-base-cases", type=int, default=None)
    parser.add_argument("--cases", default="")
    parser.add_argument("--cases-out", default="")
    parser.add_argument("--evidence-out", default="")
    args = parser.parse_args()

    if args.version in {"v03", "v04"}:
        cases = _load_v03_cases()
        max_base_cases = args.max_base_cases or 200
        if args.version == "v04" or args.adaptive:
            cases_out = args.cases_out or "data/attacks/adaptive_attack_cases_v04.jsonl"
            evidence_out = args.evidence_out or "data/attacks/adaptive_attack_evidence_passages_v04.jsonl"
            csv_cases = "data/attacks/adaptive_attack_cases_v04.csv"
            csv_evidence = "data/attacks/adaptive_attack_evidence_passages_v04.csv"
            summary_out = "data/attacks/adaptive_attack_summary_v04.json"
        else:
            cases_out = args.cases_out or "data/attacks/attack_cases_v03.jsonl"
            evidence_out = args.evidence_out or "data/attacks/attack_evidence_passages_v03.jsonl"
            csv_cases = "data/attacks/attack_cases_v03.csv"
            csv_evidence = "data/attacks/attack_evidence_passages_v03.csv"
            summary_out = "data/attacks/attack_summary_v03.json"
    else:
        cases_path = args.cases or "data/benchmark/benchmark_cases_v02.jsonl"
        cases = [BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / cases_path)]
        max_base_cases = args.max_base_cases or 180
        cases_out = args.cases_out or "data/attacks/attack_cases_v02.jsonl"
        evidence_out = args.evidence_out or "data/attacks/attack_evidence_passages_v02.jsonl"
        csv_cases = "data/attacks/attack_cases_v02.csv"
        csv_evidence = "data/attacks/attack_evidence_passages_v02.csv"
        summary_out = "data/attacks/attack_summary_v02.json"

    if args.version == "v04" or args.adaptive:
        attack_cases, attack_passages = generate_adaptive_attack_dataset(cases, max_base_cases=max_base_cases)
    else:
        attack_cases, attack_passages = generate_attack_dataset(cases, max_base_cases=max_base_cases)
    write_jsonl(ROOT / cases_out, [case.to_dict() for case in attack_cases])
    write_jsonl(ROOT / evidence_out, [passage.to_dict() for passage in attack_passages])
    write_csv(ROOT / csv_cases, [case.to_dict() for case in attack_cases])
    write_csv(ROOT / csv_evidence, [passage.to_dict() for passage in attack_passages])
    write_json(
        ROOT / summary_out,
        {
            "seed": args.seed,
            "version": args.version,
            "adaptive": bool(args.adaptive or args.version == "v04"),
            "num_source_cases": len(cases),
            "num_attack_cases": len(attack_cases),
            "num_attack_evidence_passages": len(attack_passages),
            "max_base_cases": max_base_cases,
        },
    )
    print(f"Wrote {len(attack_cases)} attack cases for {args.version}.")


if __name__ == "__main__":
    main()
