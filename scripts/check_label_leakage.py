#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.compliance.rule_based import RuleBasedComplianceAssessor
from kisec.ingestion.requirements import DEFAULT_INCIDENT_REQUIREMENTS_V02
from kisec.models import EvidencePassage, PredictionCase
from kisec.utils.io import write_json

FORBIDDEN_TOKENS = [
    "ground_truth_status",
    "ground_truth_evidence_ids",
    "criteria_truth",
    "difficulty_type",
    "mutation_type",
    "attack_type",
    "planted",
]

SCAN_DIRS = [
    ROOT / "src/kisec/compliance",
    ROOT / "src/kisec/retrieval",
    ROOT / "src/kisec/rag",
]


def scan_prediction_code() -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for directory in SCAN_DIRS:
        for path in directory.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in FORBIDDEN_TOKENS:
                if token in text:
                    findings.append(
                        {
                            "path": str(path.relative_to(ROOT)),
                            "forbidden_token": token,
                        }
                    )
    return findings


def validate_runtime_schema() -> None:
    try:
        PredictionCase.from_dict(
            {
                "case_id": "LEAK",
                "requirement_id": "IR-V02-001",
                "company_document_ids": [],
                "ground_truth_status": "fulfilled",
            }
        )
    except ValueError:
        pass
    else:
        raise AssertionError("PredictionCase accepted ground_truth_status.")

    case = PredictionCase(
        case_id="SAFE",
        requirement_id="IR-V02-001",
        company_document_ids=["DOC-1"],
    )
    evidence = EvidencePassage(
        evidence_id="EV-1",
        document_id="DOC-1",
        title="Safe policy",
        section_title="Safe section",
        text="The approved incident response policy defines service desk reporting and escalation to the ISMS manager.",
        source_type="company_policy",
        planted=True,
        approval_status="approved",
        valid_from="2026-01-01",
        valid_until="2027-01-01",
        created_at="2026-01-02",
        language="en",
        source_trust_level="high",
    )
    RuleBasedComplianceAssessor().predict(
        case,
        DEFAULT_INCIDENT_REQUIREMENTS_V02[0],
        {evidence.evidence_id: evidence},
        [evidence.evidence_id],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Check prediction code for ground-truth leakage.")
    parser.add_argument("--out", default="experiments/results/label_leakage_check_v02.json")
    args = parser.parse_args()
    findings = scan_prediction_code()
    validate_runtime_schema()
    result = {
        "passed": not findings,
        "forbidden_tokens": FORBIDDEN_TOKENS,
        "findings": findings,
        "runtime_prediction_schema": "passed",
    }
    write_json(ROOT / args.out, result)
    if findings:
        print(result)
        raise SystemExit(1)
    print(result)


if __name__ == "__main__":
    main()
