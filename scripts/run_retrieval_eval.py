#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.evaluation.metrics import aggregate_retrieval_metrics, retrieval_row
from kisec.ingestion.requirements import load_requirements
from kisec.models import BenchmarkCase, EvidencePassage
from kisec.retrieval.factory import make_retriever
from kisec.utils.io import read_jsonl, write_json
from kisec.utils.tabular import write_csv


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate evidence retrieval.")
    parser.add_argument("--method", choices=["bm25", "tfidf", "dense"], default="bm25")
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--version", choices=["v01", "v02", "v03", "v04"], default="v01")
    parser.add_argument("--requirements", default="data/processed/requirements.json")
    parser.add_argument("--evidence", default="data/synthetic_cases/evidence_passages.jsonl")
    parser.add_argument("--cases", default="data/benchmark/benchmark_cases.jsonl")
    args = parser.parse_args()
    if args.version in {"v02", "v03", "v04"}:
        if args.requirements == "data/processed/requirements.json":
            args.requirements = "data/processed/requirements_v03.json" if args.version == "v04" else f"data/processed/requirements_{args.version}.json"
    if args.version == "v02":
        if args.evidence == "data/synthetic_cases/evidence_passages.jsonl":
            args.evidence = "data/synthetic_cases/evidence_passages_v02.jsonl"
        if args.cases == "data/benchmark/benchmark_cases.jsonl":
            args.cases = "data/benchmark/benchmark_cases_v02.jsonl"

    requirements = {item.requirement_id: item for item in load_requirements(ROOT / args.requirements)}
    passages: list[EvidencePassage] = []
    cases: list[BenchmarkCase] = []
    if args.version not in {"v03", "v04"}:
        passages = [EvidencePassage.from_dict(item) for item in read_jsonl(ROOT / args.evidence)]
        cases = [BenchmarkCase.from_dict(item) for item in read_jsonl(ROOT / args.cases)]
    if args.version == "v02":
        mutation_cases_path = ROOT / "data/benchmark/mutation_cases_v02.jsonl"
        mutation_evidence_path = ROOT / "data/synthetic_cases/mutation_evidence_passages_v02.jsonl"
        if mutation_cases_path.exists() and mutation_evidence_path.exists():
            cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(mutation_cases_path))
            passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(mutation_evidence_path))
    if args.version in {"v03", "v04"}:
        for split in ["development_template", "heldout_template", "stress_test"]:
            case_path = ROOT / f"data/benchmark/benchmark_cases_v03_{split}.jsonl"
            evidence_path = ROOT / f"data/synthetic_cases/evidence_passages_v03_{split}.jsonl"
            if case_path.exists() and evidence_path.exists():
                cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(case_path))
                passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(evidence_path))
        mutation_cases_path = ROOT / "data/benchmark/mutation_cases_v03.jsonl"
        mutation_evidence_path = ROOT / "data/synthetic_cases/mutation_evidence_passages_v03.jsonl"
        if mutation_cases_path.exists() and mutation_evidence_path.exists():
            cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(mutation_cases_path))
            passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(mutation_evidence_path))
        if args.version == "v04":
            para_cases_path = ROOT / "data/benchmark/paraphrase_stress_cases_v04.jsonl"
            para_evidence_path = ROOT / "data/synthetic_cases/paraphrase_stress_evidence_v04.jsonl"
            if para_cases_path.exists() and para_evidence_path.exists():
                cases.extend(BenchmarkCase.from_dict(item) for item in read_jsonl(para_cases_path))
                passages.extend(EvidencePassage.from_dict(item) for item in read_jsonl(para_evidence_path))

    retriever = make_retriever(args.method).fit(passages)
    rows = []
    for case in cases:
        requirement = requirements[case.requirement_id]
        query = f"{requirement.title}. {requirement.text}"
        results = retriever.retrieve(query, k=args.k, candidate_document_ids=case.company_document_ids)
        retrieved_ids = [result.evidence_id for result in results]
        rows.append(retrieval_row(case, retrieved_ids, args.k))

    aggregate = aggregate_retrieval_metrics(rows, args.k)
    suffix = f"_{args.version}" if args.version in {"v02", "v03", "v04"} else ""
    output_base = ROOT / f"experiments/results/retrieval_eval_{args.method}_k{args.k}{suffix}"
    write_csv(output_base.with_suffix(".csv"), rows)
    write_json(
        output_base.with_suffix(".json"),
        {
            "method": args.method,
            "k": args.k,
            "version": args.version,
            "metrics": aggregate,
            "num_cases": len(cases),
        },
    )
    if args.version == "v04":
        base_rows = [row for row in rows if row.get("split") != "paraphrase_stress_v04"]
        para_rows = [row for row in rows if row.get("split") == "paraphrase_stress_v04"]
        base_metrics = aggregate_retrieval_metrics(base_rows, args.k)
        para_metrics = aggregate_retrieval_metrics(para_rows, args.k)
        write_csv(
            ROOT / "experiments/results/paraphrase_stress_v04.csv",
            [
                {
                    "surface": "retrieval",
                    "method": args.method,
                    "num_cases": len(para_rows),
                    "macro_f1": "",
                    "false_compliance_rate": "",
                    "source_attribution_error_rate": "",
                    "baseline_recall_at_5": base_metrics.get(f"recall_at_{args.k}", 0.0),
                    "paraphrase_recall_at_5": para_metrics.get(f"recall_at_{args.k}", 0.0),
                    "recall_drop": base_metrics.get(f"recall_at_{args.k}", 0.0) - para_metrics.get(f"recall_at_{args.k}", 0.0),
                    **para_metrics,
                }
            ],
        )
    print(aggregate)


if __name__ == "__main__":
    main()
