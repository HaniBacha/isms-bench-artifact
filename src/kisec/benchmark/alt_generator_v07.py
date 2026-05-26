from __future__ import annotations

import random
from dataclasses import dataclass

from kisec.ingestion.requirements import INCIDENT_RESPONSE_CRITERIA_V02, Requirement
from kisec.models import BenchmarkCase, EvidencePassage


LABELS = ["fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"]

INDEPENDENT_DIFFICULTIES = [
    "realistic_policy_bundle",
    "ambiguous_management_statement",
    "outdated_test_record",
    "draft_only_process",
    "supplier_gap",
    "contradiction_between_policy_and_audit",
    "implicit_but_insufficient_evidence",
    "strong_evidence_scattered_across_documents",
    "German_policy_with_English_audit_note",
    "norm_text_confused_with_company_policy",
    "realistic_false_positive_trap",
    "realistic_false_negative_trap",
]

ALT_DIFFICULTIES = [
    "paragraph_bundle_positive",
    "indirect_evidence_positive",
    "operations_note_without_test",
    "supplier_chain_gap",
    "audit_denial",
    "business_document_keyword_trap",
    "soft_management_claim",
    "draft_minutes_only",
    "competing_current_records",
    "mixed_language_bundle",
]

ASSESSMENT_DATE = "2026-04-24"
CURRENT_FROM = "2026-01-01"
CURRENT_UNTIL = "2027-01-01"


@dataclass(frozen=True)
class V07Dataset:
    cases: list[BenchmarkCase]
    passages: list[EvidencePassage]


def _truth(label: str, missing: set[str] | None = None) -> dict[str, bool]:
    missing = missing or set()
    if label == "fulfilled":
        return {criterion: True for criterion in INCIDENT_RESPONSE_CRITERIA_V02}
    if label == "not_fulfilled":
        return {criterion: False for criterion in INCIDENT_RESPONSE_CRITERIA_V02}
    if label == "unclear":
        return {criterion: False for criterion in INCIDENT_RESPONSE_CRITERIA_V02}
    return {criterion: criterion not in missing for criterion in INCIDENT_RESPONSE_CRITERIA_V02}


def _missing(truth: dict[str, bool]) -> list[str]:
    return [criterion for criterion, value in truth.items() if not value]


def _passage(
    *,
    case_id: str,
    suffix: str,
    doc_suffix: str,
    title: str,
    section_title: str,
    text: str,
    source_type: str,
    planted: bool = True,
    approval_status: str = "approved",
    valid_from: str | None = CURRENT_FROM,
    valid_until: str | None = CURRENT_UNTIL,
    created_at: str | None = "2026-03-12",
    language: str = "en",
    source_trust_level: str = "high",
    metadata: dict | None = None,
) -> EvidencePassage:
    return EvidencePassage(
        evidence_id=f"{case_id}-E-{suffix}",
        document_id=f"{case_id}-D-{doc_suffix}",
        title=title,
        section_title=section_title,
        text=text,
        source_type=source_type,
        planted=planted,
        approval_status=approval_status,
        valid_from=valid_from,
        valid_until=valid_until,
        created_at=created_at,
        language=language,
        source_trust_level=source_trust_level,
        metadata=metadata or {},
    )


def _case(
    *,
    case_id: str,
    requirement: Requirement,
    label: str,
    difficulty: str,
    passages: list[EvidencePassage],
    gold: list[str],
    truth: dict[str, bool],
    rationale: str,
    split: str,
) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        requirement_id=requirement.requirement_id,
        company_document_ids=sorted({passage.document_id for passage in passages}),
        ground_truth_status=label,  # type: ignore[arg-type]
        ground_truth_evidence_ids=gold,
        missing_evidence=_missing(truth),
        rationale=rationale,
        difficulty_type=difficulty,
        expected_criteria=list(INCIDENT_RESPONSE_CRITERIA_V02),
        criteria_truth=truth,
        metadata={
            "benchmark_version": "v07",
            "split": split,
            "difficulty_tags": [difficulty],
            "assessment_date": ASSESSMENT_DATE,
            "source_types": sorted({passage.source_type for passage in passages}),
            "languages": sorted({passage.language for passage in passages}),
            "authorship": "fixed_independent_challenge" if split == "independent_challenge_v07" else "alternative_generator_v07",
        },
    )


def _independent_bundle(
    case_id: str,
    label: str,
    difficulty: str,
    requirement: Requirement,
    variant: int,
) -> tuple[BenchmarkCase, list[EvidencePassage]]:
    if label == "fulfilled":
        language_de = difficulty == "German_policy_with_English_audit_note" or variant % 4 == 1
        policy_text = (
            "Die freigegebene Verfahrensanweisung fuer Sicherheitsvorfaelle regelt Meldung ueber das Helpdesk-Portal, Bewertung, Eindammung, Wiederanlauf, Eskalation an ISMS-Leitung und Geschaeftsfuehrung sowie die gueltige Dokumentversion 2026.2."
            if language_de
            else "The approved security incident procedure records intake through the helpdesk portal, severity review, containment coordination, recovery handover, escalation to the ISMS lead and executive sponsor, and active document revision 2026.2."
        )
        passages = [
            _passage(
                case_id=case_id,
                suffix="PROC",
                doc_suffix="PROC",
                title="Security Incident Operating Procedure" if not language_de else "Verfahrensanweisung Sicherheitsvorfaelle",
                section_title="Operating workflow",
                text=policy_text,
                source_type="company_policy",
                language="de" if language_de else "en",
            ),
            _passage(
                case_id=case_id,
                suffix="DUTY",
                doc_suffix="DUTY",
                title="Incident Duty Register",
                section_title="Named response owners",
                text="The register names the incident lead, technical coordinator, communications owner, supplier liaison, legal reviewer, and executive approver.",
                source_type="role_matrix",
            ),
            _passage(
                case_id=case_id,
                suffix="DRILL",
                doc_suffix="DRILL",
                title="March 2026 Security Incident Exercise Minutes",
                section_title="Exercise outcome and corrective actions",
                text="The 2026 exercise record lists scenario decisions, participants, gaps, owners, lessons learned, closure evidence, and management review.",
                source_type="test_record",
                created_at="2026-03-08",
            ),
            _passage(
                case_id=case_id,
                suffix="SUP",
                doc_suffix="SUP",
                title="Managed Service Incident Notification Clause",
                section_title="Supplier notification",
                text="Managed service providers must notify suspected security incidents within one business day and escalate material supplier events to the incident lead and procurement owner.",
                source_type="supplier_contract",
            ),
        ]
        truth = _truth("fulfilled")
        return (
            _case(
                case_id=case_id,
                requirement=requirement,
                label=label,
                difficulty=difficulty,
                passages=passages,
                gold=[p.evidence_id for p in passages],
                truth=truth,
                rationale="Independent fulfilled case authored as a natural document bundle with current approved evidence across policy, roles, testing, and supplier escalation.",
                split="independent_challenge_v07",
            ),
            passages,
        )

    if label == "partially_fulfilled":
        missing = {
            "periodic_testing_or_exercises",
            "evidence_of_recent_test_or_exercise",
        }
        if difficulty == "supplier_gap":
            missing = {"supplier_or_third_party_incident_escalation"}
        passages = [
            _passage(
                case_id=case_id,
                suffix="RUNBOOK",
                doc_suffix="RUN",
                title="Security Event Runbook",
                section_title="Response coordination",
                text="The runbook defines reporting to the security mailbox, triage by the duty lead, escalation to management, recovery handover, document owner approval, and valid revision 2026-Q1.",
                source_type="company_policy",
            ),
            _passage(
                case_id=case_id,
                suffix="ROSTER",
                doc_suffix="ROS",
                title="On-Call Security Roster",
                section_title="Response assignment",
                text="Named staff are assigned for incident command, technical investigation, communications, legal review, and management sign-off.",
                source_type="role_matrix",
            ),
        ]
        if difficulty == "supplier_gap":
            passages.append(
                _passage(
                    case_id=case_id,
                    suffix="TEST",
                    doc_suffix="TEST",
                    title="Current Incident Walkthrough Record",
                    section_title="Walkthrough and improvements",
                    text="A current-year security incident walkthrough captured attendees, scenario notes, lessons learned, remediation owners, and completion evidence.",
                    source_type="test_record",
                    created_at="2026-02-14",
                )
            )
            passages.append(
                _passage(
                    case_id=case_id,
                    suffix="SUPGAP",
                    doc_suffix="AUD",
                    title="Supplier Control Review",
                    section_title="Supplier incident escalation gap",
                    text="The review did not identify a clause requiring service providers to escalate security incidents to the company.",
                    source_type="audit_report",
                )
            )
        else:
            passages.append(
                _passage(
                    case_id=case_id,
                    suffix="TESTGAP",
                    doc_suffix="AUD",
                    title="Evidence Completeness Review",
                    section_title="Exercise evidence gap",
                    text="The procedure is current, but no exercise minutes, tabletop record, or post-exercise lessons learned evidence was provided for the current period.",
                    source_type="audit_report",
                )
            )
            passages.append(
                _passage(
                    case_id=case_id,
                    suffix="SUP",
                    doc_suffix="SUP",
                    title="Service Provider Security Addendum",
                    section_title="Provider reporting",
                    text="Providers must notify security incidents to procurement and the incident lead within one business day.",
                    source_type="supplier_contract",
                )
            )
        truth = _truth("partially_fulfilled", missing)
        return (
            _case(
                case_id=case_id,
                requirement=requirement,
                label=label,
                difficulty=difficulty,
                passages=passages,
                gold=[p.evidence_id for p in passages],
                truth=truth,
                rationale="Independent partial case where the process exists but a required evidence area is missing or explicitly called out by an audit note.",
                split="independent_challenge_v07",
            ),
            passages,
        )

    if label == "not_fulfilled":
        passages = [
            _passage(
                case_id=case_id,
                suffix="NONE",
                doc_suffix="AUD",
                title="ISMS Document Sampling Note",
                section_title="Incident response sample",
                text="The sample found references to cyber risk and outage handling, but no approved incident response procedure, no named response roles, and no current exercise evidence.",
                source_type="audit_report",
            ),
            _passage(
                case_id=case_id,
                suffix="DIST",
                doc_suffix="BCP",
                title="Business Continuity Recovery Checklist",
                section_title="Service outage priorities",
                text="The checklist lists recovery priorities and stakeholder calls for office outages; it does not define security incident reporting, response roles, or supplier security escalation.",
                source_type="irrelevant_document",
                source_trust_level="medium",
                planted=False,
            ),
        ]
        truth = _truth("not_fulfilled")
        return (
            _case(
                case_id=case_id,
                requirement=requirement,
                label=label,
                difficulty=difficulty,
                passages=passages,
                gold=[passages[0].evidence_id],
                truth=truth,
                rationale="Independent negative case with realistic business-continuity overlap but no security incident response implementation evidence.",
                split="independent_challenge_v07",
            ),
            passages,
        )

    # unclear
    if difficulty == "outdated_test_record":
        passages = [
            _passage(
                case_id=case_id,
                suffix="POL",
                doc_suffix="POL",
                title="Cyber Incident Procedure",
                section_title="Handling procedure",
                text="The approved procedure defines reporting, escalation, roles, management approval, supplier escalation, and controlled revision status.",
                source_type="company_policy",
            ),
            _passage(
                case_id=case_id,
                suffix="OLDTEST",
                doc_suffix="OLD",
                title="Security Incident Exercise Record 2023",
                section_title="Archived exercise",
                text="The archived exercise record from 2023 lists participants and lessons learned, but no current exercise record is available.",
                source_type="test_record",
                approval_status="expired",
                valid_from="2023-01-01",
                valid_until="2024-01-01",
                created_at="2023-06-01",
            ),
        ]
    elif difficulty == "draft_only_process":
        passages = [
            _passage(
                case_id=case_id,
                suffix="DRAFT",
                doc_suffix="DRAFT",
                title="Draft Security Incident Process",
                section_title="Draft response workflow",
                text="Draft for review: reporting, escalation, roles, supplier notification, tabletop exercises, management approval, and document control will be formalized after approval.",
                source_type="draft_policy",
                approval_status="draft",
                source_trust_level="medium",
            )
        ]
    elif difficulty == "contradiction_between_policy_and_audit":
        passages = [
            _passage(
                case_id=case_id,
                suffix="POL",
                doc_suffix="POL",
                title="Approved Incident Handling Procedure",
                section_title="Testing requirement",
                text="The procedure states that incident response tests are performed annually and lessons learned are recorded.",
                source_type="company_policy",
            ),
            _passage(
                case_id=case_id,
                suffix="CONTRA",
                doc_suffix="AUD",
                title="Current Internal Audit Note",
                section_title="Testing contradiction",
                text="The current approved audit note states that no incident response testing has occurred in the current or prior year.",
                source_type="audit_report",
            ),
        ]
    elif difficulty == "norm_text_confused_with_company_policy":
        passages = [
            _passage(
                case_id=case_id,
                suffix="NORM",
                doc_suffix="NORM",
                title="Incident Response Requirement Extract",
                section_title="Control expectation",
                text="Organizations should document incident handling, assign roles, define escalation, test the process, review lessons learned, and keep approved versions current.",
                source_type="norm_text",
                approval_status="unknown",
                source_trust_level="low",
            ),
            _passage(
                case_id=case_id,
                suffix="AUD",
                doc_suffix="AUD",
                title="Company Evidence Note",
                section_title="Evidence status",
                text="The requirement text was available, but the company implementation evidence was not provided in the sampled documents.",
                source_type="audit_report",
            ),
        ]
    else:
        passages = [
            _passage(
                case_id=case_id,
                suffix="MGT",
                doc_suffix="MGT",
                title="Management Security Statement",
                section_title="General assurance statement",
                text="Management considers incident handling to be covered by existing operational routines; details for reporting channels, supplier escalation, exercises, and owners are not attached.",
                source_type="company_policy",
                approval_status="unknown",
                source_trust_level="medium",
            )
        ]
    truth = _truth("unclear")
    return (
        _case(
            case_id=case_id,
            requirement=requirement,
            label=label,
            difficulty=difficulty,
            passages=passages,
            gold=[p.evidence_id for p in passages],
            truth=truth,
            rationale="Independent unclear case where evidence is ambiguous, outdated, draft-only, normative, or contradictory.",
            split="independent_challenge_v07",
        ),
        passages,
    )


def generate_independent_challenge_v07(
    requirements: list[Requirement],
    n: int = 80,
    seed: int = 42,
) -> V07Dataset:
    if n < 80:
        raise ValueError("v0.7 independent challenge set requires at least 80 cases.")
    rng = random.Random(seed)
    cases: list[BenchmarkCase] = []
    passages: list[EvidencePassage] = []
    for index in range(n):
        label = LABELS[index % len(LABELS)]
        difficulty = INDEPENDENT_DIFFICULTIES[(index + rng.randint(0, 11)) % len(INDEPENDENT_DIFFICULTIES)]
        requirement = requirements[index % len(requirements)]
        case_id = f"CHAL7-{rng.randrange(0x1000, 0xFFFF):04X}-{index + 1:03d}"
        case, case_passages = _independent_bundle(case_id, label, difficulty, requirement, index)
        cases.append(case)
        passages.extend(case_passages)
    return V07Dataset(cases=cases, passages=passages)


def _alt_positive(case_id: str, variant: int) -> list[EvidencePassage]:
    title_prefix = ["Incident Desk", "Security Event", "Cyber Response"][variant % 3]
    return [
        _passage(
            case_id=case_id,
            suffix="P1",
            doc_suffix="OPS",
            title=f"{title_prefix} Operating Notes",
            section_title="How events move through the team",
            text="Incoming security events are logged in the service channel, ranked by impact, contained by the duty lead, escalated to senior security governance, and closed under the current controlled revision.",
            source_type="company_policy",
        ),
        _passage(
            case_id=case_id,
            suffix="P2",
            doc_suffix="OWN",
            title="Accountability Snapshot",
            section_title="Who is accountable",
            text="The snapshot assigns the shift lead, responder, communications coordinator, procurement contact, legal reviewer, and executive approver for security-event handling.",
            source_type="role_matrix",
        ),
        _passage(
            case_id=case_id,
            suffix="P3",
            doc_suffix="SIM",
            title="Exercise Debrief Record",
            section_title="Current-year debrief",
            text="A 2026 simulation debrief lists scenario choices, observers, improvement actions, owners, closure evidence, and lessons carried into the next playbook update.",
            source_type="test_record",
            created_at="2026-02-21",
        ),
        _passage(
            case_id=case_id,
            suffix="P4",
            doc_suffix="MSA",
            title="Managed Service Security Appendix",
            section_title="Event notices from providers",
            text="Providers notify suspected security incidents to procurement and the response lead within one business day, with urgent escalation for customer-impacting events.",
            source_type="supplier_contract",
        ),
    ]


def _alt_partial(case_id: str, variant: int) -> tuple[list[EvidencePassage], set[str]]:
    supplier_gap = variant % 2 == 0
    passages = [
        _passage(
            case_id=case_id,
            suffix="A1",
            doc_suffix="PLAN",
            title="Security Event Handling Plan",
            section_title="Working procedure",
            text="The plan describes intake, impact sorting, containment coordination, internal reporting, escalation to the security governance lead, executive approval, and live revision control.",
            source_type="company_policy",
        ),
        _passage(
            case_id=case_id,
            suffix="A2",
            doc_suffix="OWNER",
            title="Duty Allocation List",
            section_title="Event responsibilities",
            text="Duty allocation names command, technical response, communications, legal review, and approval roles.",
            source_type="role_matrix",
        ),
    ]
    if supplier_gap:
        passages.append(
            _passage(
                case_id=case_id,
                suffix="A3",
                doc_suffix="SIM",
                title="Scenario Review Note",
                section_title="Current walkthrough",
                text="A current-year walkthrough documented scenario results, action owners, closure notes, and lessons learned.",
                source_type="test_record",
                created_at="2026-03-02",
            )
        )
        passages.append(
            _passage(
                case_id=case_id,
                suffix="A4",
                doc_suffix="SUPAUD",
                title="Contract Sampling Result",
                section_title="Provider escalation missing",
                text="Supplier files did not contain a security incident escalation clause or provider notification deadline.",
                source_type="audit_report",
            )
        )
        missing = {"supplier_or_third_party_incident_escalation"}
    else:
        passages.append(
            _passage(
                case_id=case_id,
                suffix="A3",
                doc_suffix="SUP",
                title="Provider Notice Appendix",
                section_title="Supplier event notification",
                text="The provider appendix requires security incident notification to procurement and the response lead within one business day.",
                source_type="supplier_contract",
            )
        )
        passages.append(
            _passage(
                case_id=case_id,
                suffix="A4",
                doc_suffix="GAP",
                title="Evidence Gap Memo",
                section_title="No exercise record",
                text="No 2026 simulation, tabletop, or exercise debrief was located for the incident response process.",
                source_type="audit_report",
            )
        )
        missing = {"periodic_testing_or_exercises", "evidence_of_recent_test_or_exercise"}
    return passages, missing


def _alt_negative(case_id: str, variant: int) -> list[EvidencePassage]:
    return [
        _passage(
            case_id=case_id,
            suffix="N1",
            doc_suffix="ASSURE",
            title="Operational Assurance Memo",
            section_title="Security event document sample",
            text="The sample contains operational outage notes and generic cyber risk wording, but no approved security incident process, no response owners, and no current exercise or supplier escalation evidence.",
            source_type="audit_report",
        ),
        _passage(
            case_id=case_id,
            suffix="N2",
            doc_suffix="DIST",
            title="Quarterly Risk Register",
            section_title="Cyber incident scenario",
            text="Cyber incidents are listed as a business risk with possible customer impact; the register does not define response handling or evidence of tests.",
            source_type="irrelevant_document",
            planted=False,
            source_trust_level="medium",
        ),
    ]


def _alt_unclear(case_id: str, variant: int) -> list[EvidencePassage]:
    kind = variant % 4
    if kind == 0:
        return [
            _passage(
                case_id=case_id,
                suffix="U1",
                doc_suffix="DRAFT",
                title="Draft Cyber Event Procedure",
                section_title="Unapproved operating model",
                text="Draft text says reporting, roles, supplier notices, annual exercises, lessons learned, and management approval will be introduced after approval.",
                source_type="draft_policy",
                approval_status="draft",
                source_trust_level="medium",
            )
        ]
    if kind == 1:
        return [
            _passage(
                case_id=case_id,
                suffix="U1",
                doc_suffix="POL",
                title="Security Event Procedure",
                section_title="Exercise expectation",
                text="The approved procedure expects annual exercises and role reviews.",
                source_type="company_policy",
            ),
            _passage(
                case_id=case_id,
                suffix="U2",
                doc_suffix="AUD",
                title="Current Audit Note",
                section_title="Exercise contradiction",
                text="The approved audit note states that no incident response test or exercise has occurred since 2023.",
                source_type="audit_report",
            ),
        ]
    if kind == 2:
        return [
            _passage(
                case_id=case_id,
                suffix="U1",
                doc_suffix="ALTDE",
                title="Sicherheitsereignis Kurznotiz",
                section_title="Unklare Praxis",
                text="Sicherheitsereignisse werden situativ durch geeignete Personen behandelt; feste Rollen, Lieferanteneskalation und Uebungsnachweise sind nicht beschrieben.",
                source_type="company_policy",
                approval_status="unknown",
                language="de",
                source_trust_level="medium",
            )
        ]
    return [
        _passage(
            case_id=case_id,
            suffix="U1",
            doc_suffix="OLD",
            title="Archived Security Event Exercise",
            section_title="Old test record",
            text="The last documented response exercise occurred in 2023 and was retained as an archive record; no current-year exercise was provided.",
            source_type="test_record",
            approval_status="expired",
            valid_from="2023-01-01",
            valid_until="2024-01-01",
            created_at="2023-05-18",
        )
    ]


def _business_distractor(case_id: str, variant: int) -> EvidencePassage:
    texts = [
        "The customer escalation matrix lists account owners and outage notifications for service incidents, without defining security incident evidence.",
        "The facilities continuity plan discusses fire, power loss, recovery rooms, and management calls.",
        "The procurement checklist asks providers whether they maintain security contacts but does not define company supplier incident escalation.",
        "The privacy FAQ mentions breach wording and data-subject communication, but no ISMS incident response roles or tests.",
    ]
    return _passage(
        case_id=case_id,
        suffix=f"D{variant}",
        doc_suffix=f"DIST{variant}",
        title="Plausible Business Distractor",
        section_title="Operational reference",
        text=texts[variant % len(texts)],
        source_type="irrelevant_document",
        planted=False,
        source_trust_level="medium",
    )


def generate_alt_cases_v07(
    requirements: list[Requirement],
    n: int = 400,
    seed: int = 42,
) -> V07Dataset:
    if n < 400:
        raise ValueError("v0.7 alternative generator requires at least 400 cases.")
    rng = random.Random(seed)
    cases: list[BenchmarkCase] = []
    passages: list[EvidencePassage] = []
    for index in range(n):
        label = LABELS[index % len(LABELS)]
        requirement = requirements[index % len(requirements)]
        case_id = f"ALT7-{index + 1:04d}-{rng.randrange(100, 999)}"
        difficulty = ALT_DIFFICULTIES[(index * 3 + rng.randint(0, 9)) % len(ALT_DIFFICULTIES)]
        if label == "fulfilled":
            case_passages = _alt_positive(case_id, index)
            truth = _truth(label)
        elif label == "partially_fulfilled":
            case_passages, missing = _alt_partial(case_id, index)
            truth = _truth(label, missing)
        elif label == "not_fulfilled":
            case_passages = _alt_negative(case_id, index)
            truth = _truth(label)
        else:
            case_passages = _alt_unclear(case_id, index)
            truth = _truth(label)
        if index % 5 == 0:
            case_passages.append(_business_distractor(case_id, index))
        passages.extend(case_passages)
        cases.append(
            _case(
                case_id=case_id,
                requirement=requirement,
                label=label,
                difficulty=difficulty,
                passages=case_passages,
                gold=[p.evidence_id for p in case_passages if p.planted],
                truth=truth,
                rationale="Alternative v0.7 paragraph-level case assembled without the original template generator.",
                split="alt_generator_v07",
            )
        )
    return V07Dataset(cases=cases, passages=passages)


def generate_public_template_distractors_v07(n: int = 36, seed: int = 42) -> list[EvidencePassage]:
    rng = random.Random(seed)
    topics = [
        ("NIST incident response profile note", "public_reference", "Preparation, detection, response, and recovery are described as general incident-response concerns, not as company implementation evidence."),
        ("OSCAL-style incident response control", "norm_text", "A control statement may ask an organization to establish reporting, response, testing, and lessons-learned practices."),
        ("Public policy template excerpt", "norm_text", "The template instructs organizations to assign an incident coordinator, create communication paths, and perform periodic exercises."),
        ("Example supplier notification clause", "public_reference", "Example wording says suppliers should notify incidents promptly, but it is not an executed company agreement."),
        ("Security awareness handout", "irrelevant_document", "Employees should report suspicious messages; the handout does not document incident response ownership or test evidence."),
        ("General business continuity template", "irrelevant_document", "Continuity plans may include crisis calls and recovery priorities without documenting security incident response criteria."),
    ]
    passages: list[EvidencePassage] = []
    for index in range(n):
        title, source_type, text = topics[index % len(topics)]
        case_id = f"PUBLIC7-{index + 1:03d}-{rng.randrange(10, 99)}"
        passages.append(
            _passage(
                case_id=case_id,
                suffix="REF",
                doc_suffix="REF",
                title=title,
                section_title="Public template-like distractor",
                text=text,
                source_type=source_type,
                planted=False,
                approval_status="unknown",
                valid_from=None,
                valid_until=None,
                created_at="2026-04-01",
                language="en",
                source_trust_level="low" if source_type == "norm_text" else "medium",
                metadata={
                    "benchmark_version": "v07",
                    "split": "public_template_distractors_v07",
                    "purpose": "distractor_only",
                    "source_note": "Synthetic public-policy-style wording informed by public NIST incident-response and OSCAL concepts; not copied standard text.",
                    "reference_urls": [
                        "https://csrc.nist.gov/projects/incident-response",
                        "https://pages.nist.gov/OSCAL/",
                    ],
                },
            )
        )
    return passages
