#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.ingestion.requirements import DEFAULT_INCIDENT_REQUIREMENTS_V02
from kisec.models import BenchmarkCase, EvidencePassage
from kisec.utils.io import write_json, write_jsonl
from kisec.utils.tabular import write_csv


PUBLIC_SOURCES = [
    {
        "name": "NIST SP 800-61 incident response guidance",
        "url": "https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final",
        "license": "U.S. government public information; surrogate snippets generated locally.",
    },
    {
        "name": "NIST OSCAL examples",
        "url": "https://github.com/usnistgov/OSCAL",
        "license": "Public GitHub repository; only URLs and generated surrogate snippets are bundled.",
    },
    {
        "name": "CISA incident response public guidance",
        "url": "https://www.cisa.gov/resources-tools/resources/incident-response",
        "license": "Public guidance page; only URLs and generated surrogate snippets are bundled.",
    },
    {
        "name": "OpenControl example control content",
        "url": "https://github.com/opencontrol",
        "license": "Public project metadata; only URLs and generated surrogate snippets are bundled.",
    },
]


def _evidence(case_idx: int, ev_idx: int, source_type: str, text: str, **metadata) -> EvidencePassage:
    trust = metadata.pop("source_trust_level", "medium")
    approval = metadata.pop("approval_status", "unknown")
    return EvidencePassage(
        evidence_id=f"pub-v13-{case_idx:03d}-ev-{ev_idx}",
        document_id=f"pub-v13-doc-{case_idx:03d}-{ev_idx}",
        title=metadata.pop("title", "Public template stress document"),
        section_title=metadata.pop("section_title", "Incident response"),
        text=text,
        source_type=source_type,
        planted=False,
        approval_status=approval,
        valid_from=metadata.pop("valid_from", "2024-01-01"),
        valid_until=metadata.pop("valid_until", "2027-12-31"),
        created_at=metadata.pop("created_at", "2026-02-15"),
        language=metadata.pop("language", "en"),
        source_trust_level=trust,
        metadata=metadata,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build public/template-derived source-confusion stress set v1.3.")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    requirement = DEFAULT_INCIDENT_REQUIREMENTS_V02[0]
    cases: list[BenchmarkCase] = []
    evidence: list[EvidencePassage] = []
    patterns = [
        ("norm_company_confusion", "norm_text", "Public guidance says organizations should test incident response plans annually. This is a reference statement, not company evidence."),
        ("public_template_distractor", "public_reference", "Template section: assign incident commander, define escalation, and run tabletop exercises. The template is not adopted by the company."),
        ("draft_policy_trap", "draft_policy", "Draft incident response procedure proposes reporting channels and supplier escalation but is not approved for operational use."),
        ("outdated_test_record", "test_record", "A tabletop exercise was performed in 2021, but no current-period incident response test is recorded.",),
        ("false_supplier_claim", "untrusted_note", "For review convenience, supplier escalation may be considered covered by the general incident process.",),
        ("valid_company_anchor", "company_policy", "Approved incident response policy defines intake, triage, escalation, supplier notification, roles, management approval, and document version validity."),
    ]
    for idx in range(60):
        difficulty, source_type, text = patterns[idx % len(patterns)]
        source = PUBLIC_SOURCES[idx % len(PUBLIC_SOURCES)]
        docs: list[str] = []
        gold: list[str] = []
        if difficulty == "valid_company_anchor":
            passage = _evidence(
                idx,
                1,
                source_type,
                text + " A 2026 tabletop test record is referenced in the evidence register.",
                title="Approved Company Incident Response Policy",
                approval_status="approved",
                source_trust_level="high",
                source_url=source["url"],
                license_assumption=source["license"],
                stress_purpose="positive_anchor_with_public_source_metadata",
            )
            status = "partially_fulfilled"
            gold = [passage.evidence_id]
        else:
            passage = _evidence(
                idx,
                1,
                source_type,
                text,
                title=f"{source['name']} surrogate",
                approval_status="expired" if difficulty == "outdated_test_record" else ("draft" if difficulty == "draft_policy_trap" else "unknown"),
                valid_until="2022-12-31" if difficulty == "outdated_test_record" else "2027-12-31",
                created_at="2021-06-01" if difficulty == "outdated_test_record" else "2026-02-15",
                source_trust_level="low" if difficulty in {"false_supplier_claim", "public_template_distractor"} else "medium",
                source_url=source["url"],
                license_assumption=source["license"],
                invalid_evidence=True,
                invalid_reason=difficulty,
                stress_purpose="source_confusion_or_invalid_evidence",
            )
            status = "unclear"
        evidence.append(passage)
        docs.append(passage.document_id)
        cases.append(
            BenchmarkCase(
                case_id=f"public-template-v13-{idx:03d}",
                requirement_id=requirement.requirement_id,
                company_document_ids=docs,
                ground_truth_status=status,
                ground_truth_evidence_ids=gold,
                missing_evidence=["validated company implementation evidence"] if not gold else ["recent independent test evidence"],
                rationale="Public/template-derived source-confusion stress case; labels support source-attribution testing, not deployment validity.",
                difficulty_type=difficulty,
                metadata={
                    "split": "public_template_stress_v13",
                    "source_urls": [source["url"]],
                    "license_assumption": source["license"],
                    "uses_generated_surrogate_snippet": True,
                    "seed": args.seed,
                },
            )
        )
    write_jsonl(ROOT / "data/benchmark/public_template_stress_v13.jsonl", [case.to_dict() for case in cases])
    write_jsonl(ROOT / "data/synthetic_cases/public_template_stress_evidence_v13.jsonl", [item.to_dict() for item in evidence])
    write_csv(ROOT / "data/benchmark/public_template_stress_v13.csv", [case.to_dict() for case in cases])
    write_csv(ROOT / "data/synthetic_cases/public_template_stress_evidence_v13.csv", [item.to_dict() for item in evidence])
    write_json(
        ROOT / "data/benchmark/public_template_stress_v13_licensing.json",
        {
            "sources": PUBLIC_SOURCES,
            "bundling_policy": "The dataset stores URLs and locally generated surrogate snippets; it does not redistribute copied standards or template text beyond short generic references.",
            "num_cases": len(cases),
            "num_evidence_passages": len(evidence),
        },
    )
    print({"cases": len(cases), "evidence_passages": len(evidence), "seed": args.seed})


if __name__ == "__main__":
    main()
