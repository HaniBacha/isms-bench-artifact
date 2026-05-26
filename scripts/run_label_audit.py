#!/usr/bin/env python
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALID_LABELS = {"fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"}

CASE_FILES = [
    "data/benchmark/benchmark_cases_v03_development_template.jsonl",
    "data/benchmark/benchmark_cases_v03_heldout_template.jsonl",
    "data/benchmark/benchmark_cases_v03_stress_test.jsonl",
    "data/benchmark/mutation_cases_v03.jsonl",
    "data/benchmark/paraphrase_stress_cases_v04.jsonl",
    "data/benchmark/manual_challenge_cases_v09.jsonl",
    "data/benchmark/public_external_validation_cases_v18c.jsonl",
    "data/attacks/attack_cases_v03.jsonl",
    "data/attacks/adaptive_attack_cases_v04.jsonl",
]

EVIDENCE_FILES = [
    "data/synthetic_cases/evidence_passages_v03_development_template.jsonl",
    "data/synthetic_cases/evidence_passages_v03_heldout_template.jsonl",
    "data/synthetic_cases/evidence_passages_v03_stress_test.jsonl",
    "data/synthetic_cases/mutation_evidence_passages_v03.jsonl",
    "data/synthetic_cases/paraphrase_stress_evidence_v04.jsonl",
    "data/attacks/attack_evidence_passages_v03.jsonl",
    "data/attacks/adaptive_attack_evidence_passages_v04.jsonl",
    "data/external_public/public_ir_evidence_corpus_v18b.jsonl",
]


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> None:
    evidence_ids: set[str] = set()
    for rel in EVIDENCE_FILES:
        for row in _jsonl(ROOT / rel):
            evidence_ids.add(str(row["evidence_id"]))

    findings: list[dict[str, str]] = []
    counts: dict[str, int] = {label: 0 for label in sorted(VALID_LABELS)}
    audited_cases = 0

    for rel in CASE_FILES:
        for case in _jsonl(ROOT / rel):
            audited_cases += 1
            case_id = str(case.get("case_id", ""))
            status = case.get("ground_truth_status") or case.get("expected_status")
            if status not in VALID_LABELS:
                findings.append({"case_id": case_id, "file": rel, "finding": f"invalid label {status}"})
                continue
            counts[str(status)] += 1

            if "expected_status" in case and case.get("ground_truth_status") != case.get("expected_status"):
                findings.append({"case_id": case_id, "file": rel, "finding": "expected_status differs from ground_truth_status"})

            gold_ids = set(case.get("ground_truth_evidence_ids", []))
            accepted_ids = set(case.get("accepted_evidence_ids", []))
            sufficient_ids = set(case.get("sufficient_evidence_ids", []))
            inline_ids = {row.get("evidence_id") for row in case.get("evidence_bundle", []) if isinstance(row, dict)}
            known_ids = evidence_ids | {str(eid) for eid in inline_ids if eid}
            missing_ids = sorted((gold_ids | accepted_ids | sufficient_ids) - known_ids)
            if missing_ids:
                findings.append({"case_id": case_id, "file": rel, "finding": f"unknown evidence ids: {missing_ids[:5]}"})

            if status == "fulfilled" and case.get("missing_evidence"):
                findings.append({"case_id": case_id, "file": rel, "finding": "fulfilled case has non-empty missing_evidence"})

            if case.get("metadata", {}).get("public_document_derived") and case.get("external_review_status") != "pending":
                findings.append({"case_id": case_id, "file": rel, "finding": "public-document case external_review_status is not pending"})

    report = {
        "passed": not findings,
        "audited_cases": audited_cases,
        "known_evidence_ids": len(evidence_ids),
        "label_counts": counts,
        "findings": findings,
        "note": "This audit checks structural label/evidence consistency. It is not expert adjudication.",
    }
    out = ROOT / "experiments/results/label_audit_v30.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(report)
    if findings:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
