#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.ingestion.requirements import load_requirements, write_default_requirements, write_default_requirements_v02
from kisec.schemas import (
    BENCHMARK_CASE_SCHEMA,
    EVIDENCE_PASSAGE_SCHEMA,
    REQUIREMENT_SCHEMA,
    SYSTEM_PREDICTION_SCHEMA,
)
from kisec.utils.io import write_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Build normalized seed corpus artifacts.")
    parser.add_argument("--raw-requirements", default="data/raw/incident_response_requirements.json")
    parser.add_argument("--out-requirements", default="data/processed/requirements.json")
    args = parser.parse_args()

    raw_path = ROOT / args.raw_requirements
    out_path = ROOT / args.out_requirements
    if raw_path.exists():
        requirements = load_requirements(raw_path)
        write_json(out_path, [requirement.to_dict() for requirement in requirements])
    else:
        requirements = write_default_requirements(raw_path)
        write_json(out_path, [requirement.to_dict() for requirement in requirements])
    v02_requirements = write_default_requirements_v02(ROOT / "data/processed/requirements_v02.json")

    write_json(
        ROOT / "data/processed/json_schemas.json",
        {
            "Requirement": REQUIREMENT_SCHEMA,
            "EvidencePassage": EVIDENCE_PASSAGE_SCHEMA,
            "BenchmarkCase": BENCHMARK_CASE_SCHEMA,
            "SystemPrediction": SYSTEM_PREDICTION_SCHEMA,
        },
    )
    write_json(
        ROOT / "data/processed/corpus_metadata.json",
        {
            "domain": "Incident Management",
            "num_requirements": len(requirements),
            "num_requirements_v02": len(v02_requirements),
            "source": "synthetic_ir_control_set_v1",
            "source_v02": "synthetic_ir_control_set_v02",
            "scope_note": "Pre-assessment research benchmark; not certification.",
        },
    )
    print(f"Wrote {len(requirements)} requirements to {out_path}")


if __name__ == "__main__":
    main()
