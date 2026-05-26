#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.corpus.synthetic import CRITERIA
from kisec.ingestion.requirements import load_requirements, write_default_requirements_v02
from kisec.models import BenchmarkCase, EvidencePassage
from kisec.utils.io import write_json, write_jsonl
from kisec.utils.tabular import write_csv


LABELS = ["fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"]


def _truth(label: str) -> dict[str, bool]:
    if label == "fulfilled":
        return {criterion: True for criterion in CRITERIA}
    if label == "partially_fulfilled":
        return {
            criterion: criterion
            not in {"periodic_testing_or_exercises", "evidence_of_recent_test_or_exercise"}
            for criterion in CRITERIA
        }
    if label == "not_fulfilled":
        return {criterion: False for criterion in CRITERIA}
    return {criterion: False for criterion in CRITERIA}


def _missing(truth: dict[str, bool]) -> list[str]:
    return [criterion for criterion, value in truth.items() if not value]


def _passage(case_id: str, suffix: str, text: str, source_type: str, title: str, section: str, language: str = "en", approval: str = "approved", trust: str = "high") -> EvidencePassage:
    return EvidencePassage(
        evidence_id=f"{case_id}-EV-{suffix}",
        document_id=f"{case_id}-DOC-{suffix}",
        title=title,
        section_title=section,
        text=text,
        source_type=source_type,
        planted=True,
        approval_status=approval,
        valid_from="2026-01-01",
        valid_until="2027-01-01",
        created_at="2026-03-20",
        language=language,
        source_trust_level=trust,
        metadata={"benchmark_version": "v04", "split": "paraphrase_stress_v04"},
    )


def _case_passages(case_id: str, label: str, variant: int) -> tuple[list[EvidencePassage], list[str], dict[str, bool]]:
    truth = _truth(label)
    if label == "fulfilled":
        if variant % 3 == 0:
            passages = [
                _passage(case_id, "POL", "Cyber event handling describes intake, severity sorting, containment coordination, ticket reporting, escalation to security governance, leadership sign-off, and controlled revision status.", "company_policy", "Cyber Event Handling Standard", "Operating model"),
                _passage(case_id, "ROLE", "Named accountability is assigned for event lead, technical coordinator, communications, procurement liaison, legal review, and executive authorization.", "role_matrix", "Response Accountability Register", "Accountability"),
                _passage(case_id, "TEST", "A 2026 ransomware rehearsal recorded participants, decisions, corrective actions, owners, completion evidence, and lessons learned.", "test_record", "Scenario Rehearsal Minutes", "Current exercise"),
                _passage(case_id, "SUP", "Provider agreements require security-event notification within one business day and escalation to the event lead and procurement liaison.", "supplier_contract", "Provider Notification Clause", "Third-party escalation"),
            ]
        elif variant % 3 == 1:
            passages = [
                _passage(case_id, "DE-POL", "Der Ablauf fuer Cyber-Sicherheitsereignisse regelt Annahme, Bewertung, Eindammung, Meldung ueber Tickets, Eskalation an die ISMS-Koordination, Freigabe durch die Leitung und gueltigen Dokumentenstand.", "company_policy", "Leitfaden Sicherheitsereignisse", "Ablauf und Freigabe", "de"),
                _passage(case_id, "DE-ROLE", "Die Zustandsliste benennt Ereignisleitung, technische Koordination, Kommunikation, Einkauf, Rechtskontakt und Freigabeinhaber.", "role_matrix", "Zustaendigkeitsliste Cyber-Ereignisse", "Rollen", "de"),
                _passage(case_id, "DE-TEST", "Im Jahr 2026 wurde eine Ransomware-Uebung mit Teilnehmern, Entscheidungen, Verbesserungen, Verantwortlichen und Abschlussnachweisen protokolliert.", "test_record", "Protokoll Cyber-Uebung", "Aktuelle Uebung", "de"),
                _passage(case_id, "DE-SUP", "Dienstleister muessen Sicherheitsereignisse innerhalb eines Arbeitstages melden und an Ereignisleitung sowie Einkauf eskalieren.", "supplier_contract", "Dienstleister-Meldeklausel", "Eskalation", "de"),
            ]
        else:
            passages = [
                _passage(case_id, "MIX-POL", "The Vorfall workflow defines intake, triage, Eindammung, service ticket reporting, escalation to ISMS Leitung, management sign-off, and current revision validity.", "company_policy", "Incident/Vorfall Playbook", "Hybrid procedure", "en"),
                _passage(case_id, "MIX-ROLE", "Incident commander, technische Leitung, communications owner, procurement liaison, legal reviewer, and executive approver are assigned.", "role_matrix", "Hybrid Role Matrix", "Named owners", "en"),
                _passage(case_id, "MIX-TEST", "Die 2026 tabletop Uebung documents scenario, decisions, lessons learned, Massnahmen, owners, and closure evidence.", "test_record", "Hybrid Exercise Record", "Exercise evidence", "de"),
                _passage(case_id, "MIX-SUP", "Supplier and Dienstleister incident escalation is required to procurement and the event lead within one business day.", "supplier_contract", "Hybrid Supplier Annex", "Provider escalation", "en"),
            ]
        return passages, [p.evidence_id for p in passages], truth
    if label == "partially_fulfilled":
        passages = [
            _passage(case_id, "POL", "Cyber incident handling defines intake, containment coordination, reporting, escalation, management sign-off, and document validity.", "company_policy", "Cyber Response Guide", "Core process"),
            _passage(case_id, "ROLE", "The accountability roster names operational incident response owners.", "role_matrix", "Response Roster", "Duties"),
            _passage(case_id, "SUP", "Provider notification and escalation duties are included in supplier clauses.", "supplier_contract", "Provider Escalation Clause", "Suppliers"),
            _passage(case_id, "GAP", "No current-period exercise minutes, tabletop record, or lessons-learned closure evidence was available.", "audit_report", "Assurance Note", "Testing gap"),
        ]
        return passages, [p.evidence_id for p in passages], truth
    if label == "not_fulfilled":
        passages = [
            _passage(case_id, "NONE", "The review found cyber-event terminology in awareness slides, but no approved incident response process, no assigned response roles, and no current exercise record.", "audit_report", "Document Review Note", "No implementation evidence"),
            _passage(case_id, "DIST", "Risk scenarios mention cyber incident impact and recovery priorities without defining response operations.", "irrelevant_document", "Risk Register Extract", "Scenario text", trust="medium"),
        ]
        return passages, [passages[0].evidence_id], truth
    passages = [
        _passage(case_id, "AMBIG", "Teams handle security events as needed. A formal workflow, supplier escalation path, assigned roles, and recent exercise evidence are expected to be clarified later.", "company_policy", "Working Note Security Events", "Informal practice", approval="unknown", trust="medium"),
        _passage(case_id, "PLAN", "A tabletop exercise is planned for the next cycle; current evidence is not yet attached.", "audit_report", "Planning Note", "Future evidence", approval="approved", trust="high"),
    ]
    return passages, [p.evidence_id for p in passages], truth


def generate_paraphrase_stress_v04(n: int = 200, seed: int = 42) -> tuple[list[BenchmarkCase], list[EvidencePassage]]:
    if n < 200:
        raise ValueError("v0.4 paraphrase stress requires at least 200 cases.")
    req_path = ROOT / "data/processed/requirements_v03.json"
    requirements = load_requirements(req_path) if req_path.exists() else write_default_requirements_v02(req_path)
    cases: list[BenchmarkCase] = []
    passages: list[EvidencePassage] = []
    for index in range(n):
        case_id = f"IRV04PARA-{index + 1:04d}"
        label = LABELS[(index + seed) % len(LABELS)]
        requirement = requirements[index % len(requirements)]
        case_passages, gold_ids, truth = _case_passages(case_id, label, index)
        passages.extend(case_passages)
        cases.append(
            BenchmarkCase(
                case_id=case_id,
                requirement_id=requirement.requirement_id,
                company_document_ids=sorted({p.document_id for p in case_passages}),
                ground_truth_status=label,  # type: ignore[arg-type]
                ground_truth_evidence_ids=gold_ids,
                missing_evidence=_missing(truth),
                rationale=f"v0.4 paraphrase stress case; label={label}; variant={index % 3}.",
                difficulty_type="paraphrase_stress_v04",
                expected_criteria=list(CRITERIA),
                criteria_truth=truth,
                metadata={
                    "benchmark_version": "v04",
                    "split": "paraphrase_stress_v04",
                    "difficulty_tags": ["paraphrase_stress_v04"],
                    "source_types": sorted({p.source_type for p in case_passages}),
                    "languages": sorted({p.language for p in case_passages}),
                },
            )
        )
    return cases, passages


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate v0.4 paraphrase and multilingual stress cases.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n", type=int, default=200)
    args = parser.parse_args()
    try:
        cases, passages = generate_paraphrase_stress_v04(n=args.n, seed=args.seed)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    write_jsonl(ROOT / "data/benchmark/paraphrase_stress_cases_v04.jsonl", [case.to_dict() for case in cases])
    write_jsonl(ROOT / "data/synthetic_cases/paraphrase_stress_evidence_v04.jsonl", [p.to_dict() for p in passages])
    write_csv(ROOT / "data/benchmark/paraphrase_stress_cases_v04.csv", [case.to_dict() for case in cases])
    write_csv(ROOT / "data/synthetic_cases/paraphrase_stress_evidence_v04.csv", [p.to_dict() for p in passages])
    write_json(
        ROOT / "data/benchmark/paraphrase_stress_summary_v04.json",
        {
            "seed": args.seed,
            "num_cases": len(cases),
            "num_evidence_passages": len(passages),
            "label_counts": {label: sum(1 for case in cases if case.ground_truth_status == label) for label in LABELS},
        },
    )
    print(f"Wrote {len(cases)} paraphrase stress cases.")


if __name__ == "__main__":
    main()
