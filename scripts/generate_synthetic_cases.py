#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.corpus.synthetic import generate_incident_response_dataset
from kisec.evaluation.metrics import label_counts
from kisec.ingestion.requirements import load_requirements, write_default_requirements, write_default_requirements_v02
from kisec.utils.io import write_json, write_jsonl
from kisec.utils.tabular import write_csv


def _load_or_create_requirements(path: Path):
    if path.exists():
        return load_requirements(path)
    return write_default_requirements(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deterministic Incident Response cases.")
    parser.add_argument("--n", type=int, default=None)
    parser.add_argument("--num-cases", type=int, default=120)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--version", choices=["v02", "v03"], default="v02")
    parser.add_argument(
        "--split",
        choices=["development_template", "heldout_template", "stress_test"],
        default="development_template",
        help="v0.3 benchmark split to generate.",
    )
    parser.add_argument("--requirements", default="data/processed/requirements.json")
    parser.add_argument("--evidence-out", default="data/synthetic_cases/evidence_passages.jsonl")
    parser.add_argument("--cases-out", default="data/benchmark/benchmark_cases.jsonl")
    parser.add_argument("--attacks-out", default="data/attacks/attack_cases.jsonl")
    parser.add_argument("--attack-evidence-out", default="data/attacks/attack_evidence_passages.jsonl")
    args = parser.parse_args()
    num_cases = args.n if args.n is not None else args.num_cases

    if args.version == "v02":
        args.num_cases = num_cases if args.n is not None else max(num_cases, 500)
        if args.requirements == "data/processed/requirements.json":
            args.requirements = "data/processed/requirements_v02.json"
        if args.evidence_out == "data/synthetic_cases/evidence_passages.jsonl":
            args.evidence_out = "data/synthetic_cases/evidence_passages_v02.jsonl"
        if args.cases_out == "data/benchmark/benchmark_cases.jsonl":
            args.cases_out = "data/benchmark/benchmark_cases_v02.jsonl"
        if args.attacks_out == "data/attacks/attack_cases.jsonl":
            args.attacks_out = "data/attacks/attack_cases_v02.jsonl"
        if args.attack_evidence_out == "data/attacks/attack_evidence_passages.jsonl":
            args.attack_evidence_out = "data/attacks/attack_evidence_passages_v02.jsonl"
    elif args.version == "v03":
        minimum = 300 if args.split == "stress_test" else 500
        args.num_cases = num_cases if args.n is not None else max(num_cases, minimum)
        if args.requirements == "data/processed/requirements.json":
            args.requirements = "data/processed/requirements_v03.json"
        if args.evidence_out == "data/synthetic_cases/evidence_passages.jsonl":
            args.evidence_out = f"data/synthetic_cases/evidence_passages_v03_{args.split}.jsonl"
        if args.cases_out == "data/benchmark/benchmark_cases.jsonl":
            args.cases_out = f"data/benchmark/benchmark_cases_v03_{args.split}.jsonl"

    req_path = ROOT / args.requirements
    if not req_path.exists():
        if args.version in {"v02", "v03"}:
            requirements = write_default_requirements_v02(req_path)
        else:
            raw_path = ROOT / "data/raw/incident_response_requirements.json"
            requirements = _load_or_create_requirements(raw_path)
        write_json(req_path, [requirement.to_dict() for requirement in requirements])
    else:
        requirements = load_requirements(req_path)

    dataset = generate_incident_response_dataset(
        requirements=requirements,
        num_cases=args.num_cases,
        seed=args.seed,
        version=args.version,
        split=args.split,
    )
    write_jsonl(ROOT / args.evidence_out, [item.to_dict() for item in dataset.evidence_passages])
    write_jsonl(ROOT / args.cases_out, [item.to_dict() for item in dataset.benchmark_cases])

    attack_cases = []
    attack_passages = []
    if args.version == "v02":
        from kisec.attacks.generator import generate_attack_dataset

        attack_cases, attack_passages = generate_attack_dataset(dataset.benchmark_cases, max_base_cases=180)
        write_jsonl(ROOT / args.attacks_out, [item.to_dict() for item in attack_cases])
        write_jsonl(ROOT / args.attack_evidence_out, [item.to_dict() for item in attack_passages])

    case_summary = {
        "num_cases": len(dataset.benchmark_cases),
        "num_evidence_passages": len(dataset.evidence_passages),
        "num_attack_cases": len(attack_cases),
        "num_attack_evidence_passages": len(attack_passages),
        "seed": args.seed,
        "version": args.version,
        "split": args.split if args.version == "v03" else "",
        "label_counts": label_counts(dataset.benchmark_cases),
    }
    if args.version == "v02":
        summary_path = "data/benchmark/summary_v02.json"
        csv_path = "data/benchmark/benchmark_cases_v02.csv"
        evidence_csv_path = "data/synthetic_cases/evidence_passages_v02.csv"
    elif args.version == "v03":
        summary_path = f"data/benchmark/summary_v03_{args.split}.json"
        csv_path = f"data/benchmark/benchmark_cases_v03_{args.split}.csv"
        evidence_csv_path = f"data/synthetic_cases/evidence_passages_v03_{args.split}.csv"
    else:
        summary_path = "data/benchmark/summary.json"
        csv_path = "data/benchmark/benchmark_cases.csv"
        evidence_csv_path = "data/synthetic_cases/evidence_passages.csv"
    write_json(ROOT / summary_path, case_summary)
    write_csv(ROOT / csv_path, [case.to_dict() for case in dataset.benchmark_cases])
    write_csv(
        ROOT / evidence_csv_path,
        [passage.to_dict() for passage in dataset.evidence_passages],
    )
    print(f"Wrote {case_summary['num_cases']} benchmark cases for {args.version} {case_summary['split']}.")


if __name__ == "__main__":
    main()
