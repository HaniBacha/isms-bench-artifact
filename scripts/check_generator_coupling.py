#!/usr/bin/env python
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.models import BenchmarkCase, PredictionCase
from kisec.utils.io import read_jsonl, write_json

PREDICTION_DIRS = [
    ROOT / "src/kisec/compliance",
    ROOT / "src/kisec/retrieval",
    ROOT / "src/kisec/rag",
]

FORBIDDEN_RUNTIME_FIELDS = {
    "ground_truth_status",
    "ground_truth_evidence_ids",
    "criteria_truth",
    "difficulty_type",
    "mutation_type",
    "attack_type",
    "planted",
}

FORBIDDEN_IMPORTS = [
    "kisec.corpus.synthetic",
    "kisec.benchmark.mutations",
    "kisec.attacks.generator",
]

FORBIDDEN_BRANCH_TOKENS = [
    "difficulty_type",
    "mutation_type",
    "attack_type",
    "template_family",
    "criteria_truth",
    "ground_truth_status",
    "ground_truth_evidence_ids",
]

RATIONALE_PHRASES = [
    "v03 split=",
    "satisfied=",
    "Expected status changed",
    "Attack variant of",
]


def _node_text(source: str, node: ast.AST) -> str:
    return ast.get_source_segment(source, node) or ""


def scan_prediction_code() -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for directory in PREDICTION_DIRS:
        for path in directory.rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            rel = str(path.relative_to(ROOT))
            for phrase in RATIONALE_PHRASES:
                if phrase in source:
                    findings.append({"path": rel, "finding": "rationale_phrase_used", "detail": phrase})
            for forbidden_import in FORBIDDEN_IMPORTS:
                if forbidden_import in source:
                    findings.append({"path": rel, "finding": "forbidden_generator_import", "detail": forbidden_import})
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.If, ast.Match)):
                    text = _node_text(source, node)
                    for token in FORBIDDEN_BRANCH_TOKENS:
                        if token in text:
                            findings.append({"path": rel, "finding": "branch_on_generator_field", "detail": token})
                if isinstance(node, ast.Compare):
                    text = _node_text(source, node)
                    if "case_id" in text:
                        findings.append({"path": rel, "finding": "branch_on_case_id", "detail": text.strip()})
    return findings


def validate_runtime_prediction_schema() -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    sample_paths = [
        ROOT / "data/benchmark/benchmark_cases_v03_development_template.jsonl",
        ROOT / "data/benchmark/benchmark_cases_v03_heldout_template.jsonl",
        ROOT / "data/benchmark/benchmark_cases_v03_stress_test.jsonl",
    ]
    for path in sample_paths:
        if not path.exists():
            continue
        first = next(iter(read_jsonl(path)), None)
        if not first:
            continue
        case = BenchmarkCase.from_dict(first)
        sanitized = case.to_prediction_input().to_dict()
        forbidden_present = sorted(FORBIDDEN_RUNTIME_FIELDS & set(sanitized))
        if forbidden_present:
            findings.append(
                {
                    "path": str(path.relative_to(ROOT)),
                    "finding": "runtime_schema_contains_forbidden_fields",
                    "detail": ",".join(forbidden_present),
                }
            )
        try:
            PredictionCase.from_dict({**sanitized, "difficulty_type": case.difficulty_type})
        except ValueError:
            pass
        else:
            findings.append(
                {
                    "path": str(path.relative_to(ROOT)),
                    "finding": "runtime_schema_accepts_difficulty_type",
                    "detail": case.case_id,
                }
            )
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Check obvious generator-baseline coupling for v0.3.")
    parser.add_argument("--out", default="experiments/results/coupling_check_v03.json")
    args = parser.parse_args()

    findings = scan_prediction_code() + validate_runtime_prediction_schema()
    result = {
        "passed": not findings,
        "check": "heuristic_static_and_runtime_generator_coupling",
        "findings": findings,
        "forbidden_runtime_fields": sorted(FORBIDDEN_RUNTIME_FIELDS),
    }
    write_json(ROOT / args.out, result)
    if findings:
        print(result)
        raise SystemExit(1)
    print(result)


if __name__ == "__main__":
    main()
