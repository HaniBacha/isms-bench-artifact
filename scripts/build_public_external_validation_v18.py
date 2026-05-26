#!/usr/bin/env python
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ACCESS_DATE = "2026-04-26"

ALL_CRITERIA = [
    "documented_incident_response_process",
    "assigned_roles_and_responsibilities",
    "incident_reporting_channel",
    "escalation_procedure",
    "supplier_or_third_party_incident_escalation",
    "periodic_testing_or_exercises",
    "post_incident_review_or_lessons_learned",
    "evidence_preservation",
    "management_approval",
    "document_version_and_validity",
]

SOURCES: list[dict[str, str]] = [
    {
        "source_id": "PUBIR-S01-MSU",
        "title": "Cybersecurity Incident Response Plan",
        "organization": "Mississippi State University",
        "url": "https://www.infosecurity.msstate.edu/isp/irplan",
        "source_type": "public_university_incident_response_plan",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public university web page; PDF redistribution not assumed.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Public page identifies reporting, investigation, communication, forensic analysis, and post mortem elements.",
        "notes": "Use page and PDF URL as public source pointers; do not store full PDF text.",
    },
    {
        "source_id": "PUBIR-S02-EPA",
        "title": "Water and Wastewater Systems Cybersecurity Incident Response Plan Template Instructions",
        "organization": "U.S. Environmental Protection Agency",
        "url": "https://www.epa.gov/cyberwater/cybersecurity-planning",
        "source_type": "government_incident_response_template",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "U.S. government public web material; local split still stores short paraphrases only.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Template instructions mention CIRP planning, external contractors, document maintenance, training, and tabletop exercises.",
        "notes": "Template material is useful for source-confusion and template-only evidence cases.",
    },
    {
        "source_id": "PUBIR-S03-UMGC",
        "title": "Information Security Incident Response Policy",
        "organization": "University of Maryland Global Campus",
        "url": "https://www.umgc.edu/administration/policies-and-reporting/policies/info-governance-security-technology/information-security-incident-response",
        "source_type": "public_university_incident_response_policy",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public university policy page; redistribution terms not independently verified.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Policy describes CIRT, plan contents, severity classifications, annual review, reporting channel, and documentation.",
        "notes": "Strong public-policy source for process, roles, reporting, review validity, and documentation criteria.",
    },
    {
        "source_id": "PUBIR-S04-UA",
        "title": "Information Security Incident Response Plan",
        "organization": "University of Alabama Office of Information Technology",
        "url": "https://oit.ua.edu/services/cybersecurity/information-security-incident-response-procedures/",
        "source_type": "public_university_incident_response_plan",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public university page; redistribution terms not independently verified.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Plan includes reporting, investigation, oversight, management, remediation, recovery, documentation, authority roles, and NIST process phases.",
        "notes": "Useful for process, reporting, authority, escalation, and evidence-review cases.",
    },
    {
        "source_id": "PUBIR-S05-USC",
        "title": "Cybersecurity Incident Response Policy",
        "organization": "University of Southern California",
        "url": "https://policy.usc.edu/security-incident-response/",
        "source_type": "public_university_incident_response_policy",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public university policy page; redistribution terms not independently verified.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Policy defines cybersecurity incidents, includes third-party services in scope, and sets minimum response expectations.",
        "notes": "Useful for third-party/source-scope and current reviewed policy evidence.",
    },
    {
        "source_id": "PUBIR-S06-UCONN",
        "title": "Incident Response Plan",
        "organization": "University of Connecticut",
        "url": "https://security.uconn.edu/incident-response-plan/",
        "source_type": "public_university_incident_response_plan",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public university page; redistribution terms not independently verified.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Plan covers roles, responsibilities, reporting, evidence preservation, training/tabletop exercises, phases, and lessons learned.",
        "notes": "Strong source for process, roles, reporting, evidence preservation, training, and after-action criteria.",
    },
    {
        "source_id": "PUBIR-S07-BUFFALO",
        "title": "Information Security Incident Response Plan",
        "organization": "University at Buffalo",
        "url": "https://www.buffalo.edu/ubit/policies/policies-standards-guidelines/ubit-standards/incident-response-plan.html",
        "source_type": "public_university_incident_response_plan",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public university page; redistribution terms not independently verified.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Plan identifies roles, responsibilities, procedures, annual review, reporting contacts, practice, preservation, and after-action analysis.",
        "notes": "Useful for annual review and broad IR lifecycle evidence.",
    },
    {
        "source_id": "PUBIR-S08-SCU",
        "title": "Incident Response Procedure",
        "organization": "Santa Clara University",
        "url": "https://www.scu.edu/is/technology-policies-procedures-and-standards/incident-response-procedure/",
        "source_type": "public_university_incident_response_procedure",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public university procedure page; redistribution terms not independently verified.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Procedure covers reporting, incident handler designation, incident logs, system isolation, and evidence preservation.",
        "notes": "Narrow but useful for reporting and evidence-preservation cases.",
    },
    {
        "source_id": "PUBIR-S09-ASU",
        "title": "ITS Incident Response",
        "organization": "Albany State University",
        "url": "https://www.asurams.edu/technology/forms-policies/its-incident-response.php",
        "source_type": "public_university_incident_response_policy",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public university policy page; redistribution terms not independently verified.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Policy describes reporting, investigation, escalation to governance/law enforcement, affected owner notification, and incident tracking.",
        "notes": "Useful for reporting and escalation evidence.",
    },
    {
        "source_id": "PUBIR-S10-USNH",
        "title": "Incident Response Standard for Cybersecurity",
        "organization": "University System of New Hampshire",
        "url": "https://www.usnh.edu/it/departments/cybersecurity/cybersecurity-policies-standards/incident-response-standard-cybersecurity",
        "source_type": "public_university_incident_response_standard",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public web page states copyright; store paraphrases only.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Standard describes an incident response team, assessment, containment, communication, documentation, legal notification, lessons learned, approval, and revision history.",
        "notes": "Strong source, but use paraphrases because copyright notice is visible.",
    },
    {
        "source_id": "PUBIR-S11-WWU",
        "title": "Cybersecurity Incident Response Guidelines",
        "organization": "Western Washington University",
        "url": "https://its.wwu.edu/gdl-300007i-cybersecurity-incident-response-guidelines",
        "source_type": "public_university_incident_response_guideline",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public university guideline page; redistribution terms not independently verified.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Guideline covers IRP creation, annual updates, CIO approval, IRP elements, documentation, communication, testing, and lessons learned.",
        "notes": "Strong source for management approval, version/review validity, and testing.",
    },
    {
        "source_id": "PUBIR-S12-MCNEESE",
        "title": "Information Technology Incident Response Plan",
        "organization": "McNeese State University",
        "url": "https://www.mcneese.edu/policy/information-technology-incident-response-plan/",
        "source_type": "public_university_incident_response_plan",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public university policy page; redistribution terms not independently verified.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Plan describes risk classification, IRT assembly, vendor/procurement involvement, remediation plan, incident reports, and archival responsibility.",
        "notes": "Useful for supplier/procurement involvement and incident documentation.",
    },
    {
        "source_id": "PUBIR-S13-NIST61R3",
        "title": "SP 800-61 Rev. 3 Incident Response Recommendations and Considerations",
        "organization": "National Institute of Standards and Technology",
        "url": "https://www.nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations",
        "source_type": "public_incident_response_guidance",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "U.S. government public guidance page; local split stores paraphrases only.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Normative/guidance source for incident-response recommendations; not company implementation evidence.",
        "notes": "Used for source-confusion cases, not as implementation evidence.",
    },
    {
        "source_id": "PUBIR-S14-NIST84",
        "title": "SP 800-84 Guide to Test, Training, and Exercise Programs for IT Plans and Capabilities",
        "organization": "National Institute of Standards and Technology",
        "url": "https://csrc.nist.gov/pubs/sp/800/84/final",
        "source_type": "public_testing_exercise_guidance",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "U.S. government public guidance page; local split stores paraphrases only.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Guidance source for tests, training, and exercises; not company implementation evidence.",
        "notes": "Used for testing source-confusion and template-only cases.",
    },
    {
        "source_id": "PUBIR-S15-OSCAL",
        "title": "OSCAL Assessment Plan Model",
        "organization": "National Institute of Standards and Technology",
        "url": "https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-plan/",
        "source_type": "public_machine_readable_assessment_model",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "NIST public documentation; local split stores paraphrases only.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Structured assessment/provenance framing, not incident-response implementation evidence.",
        "notes": "Used to create norm/provenance source-confusion distractors.",
    },
    {
        "source_id": "PUBIR-S16-FEDRAMP",
        "title": "FedRAMP Annual Assessment Guidance and OSCAL Templates",
        "organization": "FedRAMP / GSA",
        "url": "https://help.fedramp.gov/hc/en-us/articles/28895414289947-FedRAMP-Annual-Assessment-Guidance-Version-3-0",
        "source_type": "public_assessment_template_reference",
        "access_date": ACCESS_DATE,
        "license_or_terms_note": "Public government help page; local split stores paraphrases only.",
        "redistribution_decision": "store_url_and_short_paraphrases_only",
        "relevance_to_ir_criteria": "Assessment-template and OSCAL provenance framing, not company IR implementation evidence.",
        "notes": "Used as public assessment-template distractor and provenance reference.",
    },
]


def evidence(
    eid: str,
    source_id: str,
    section: str,
    summary: str,
    criteria: list[str],
    source_type: str = "company_policy",
    approval: str = "approved",
    valid_until: str | None = "2028-12-31",
    trust: str = "high",
    invalid: bool = False,
    note: str | None = None,
) -> dict[str, Any]:
    source = next(item for item in SOURCES if item["source_id"] == source_id)
    return {
        "evidence_id": eid,
        "source_id": source_id,
        "document_id": source_id,
        "source_url": source["url"],
        "page_or_section_reference": section,
        "short_excerpt_or_paraphrase": summary,
        "criterion_tags": criteria,
        "source_type": source_type,
        "approval_status_if_inferable": approval,
        "validity_or_review_date_if_inferable": valid_until or "unknown",
        "language": "en",
        "trust_level": trust,
        "redistribution_note": note or source["redistribution_decision"],
        "section_title": section,
        "text": summary,
        "title": source["title"],
        "planted": False,
        "approval_status": approval,
        "valid_from": "2024-01-01",
        "valid_until": valid_until,
        "created_at": "2026-04-26",
        "source_trust_level": trust,
        "metadata": {
            "public_external_v18": True,
            "source_id": source_id,
            "source_url": source["url"],
            "criterion_tags": criteria,
            "redistribution_note": note or source["redistribution_decision"],
            "invalid_evidence": invalid,
            "invalid_reason": "not_company_implementation_evidence" if invalid else "",
        },
    }


EVIDENCE: list[dict[str, Any]] = [
    evidence("PUBIR-E001", "PUBIR-S01-MSU", "Overview", "Paraphrase: the MSU plan page describes procedures for timely response to information security breaches.", ["documented_incident_response_process"]),
    evidence("PUBIR-E002", "PUBIR-S01-MSU", "Key elements", "Paraphrase: listed elements include incident reporting, investigation, communication, forensic analysis, and post mortem.", ["incident_reporting_channel", "evidence_preservation", "post_incident_review_or_lessons_learned"]),
    evidence("PUBIR-E003", "PUBIR-S01-MSU", "Full plan pointer", "Paraphrase: the page links to the full cybersecurity incident response plan PDF.", ["documented_incident_response_process", "document_version_and_validity"]),
    evidence("PUBIR-E004", "PUBIR-S03-UMGC", "Security Incident Response", "Paraphrase: the policy requires an Information Security Incident response plan with organized response, roles, management notification, reportable incidents, and severity classifications.", ["documented_incident_response_process", "assigned_roles_and_responsibilities", "escalation_procedure"]),
    evidence("PUBIR-E005", "PUBIR-S03-UMGC", "CIRT", "Paraphrase: a CIRT is established under the senior information-security director and contains technical, administrative, and communication skills.", ["assigned_roles_and_responsibilities", "management_approval"]),
    evidence("PUBIR-E006", "PUBIR-S03-UMGC", "Incident Reporting", "Paraphrase: suspected information security incidents can be reported to the technical support service desk or Information Security.", ["incident_reporting_channel"]),
    evidence("PUBIR-E007", "PUBIR-S03-UMGC", "Annual review", "Paraphrase: the plan and procedures are reviewed at least annually to address changes, problems, execution, or testing.", ["document_version_and_validity", "periodic_testing_or_exercises"]),
    evidence("PUBIR-E008", "PUBIR-S03-UMGC", "Documentation", "Paraphrase: incident handling is documented in the response plan and remediation processes are documented separately.", ["documented_incident_response_process", "evidence_preservation"]),
    evidence("PUBIR-E009", "PUBIR-S04-UA", "Purpose", "Paraphrase: the UA plan provides oversight, management, remediation, recovery, and documentation for all security incidents.", ["documented_incident_response_process", "post_incident_review_or_lessons_learned"]),
    evidence("PUBIR-E010", "PUBIR-S04-UA", "Reporting", "Paraphrase: incidents are reported through the OIT service desk email or phone channel.", ["incident_reporting_channel"]),
    evidence("PUBIR-E011", "PUBIR-S04-UA", "Authority", "Paraphrase: the CIO, deputy CIO, CISO, and emergency management leadership have oversight and management responsibilities.", ["assigned_roles_and_responsibilities", "management_approval"]),
    evidence("PUBIR-E012", "PUBIR-S04-UA", "Incident management", "Paraphrase: the response team uses NIST SP 800-61 concepts and phases including preparation, detection, containment, eradication, and recovery.", ["documented_incident_response_process", "escalation_procedure"]),
    evidence("PUBIR-E013", "PUBIR-S04-UA", "Investigation approval", "Paraphrase: sensitive investigations require approval from appropriate authority groups such as HR, legal, law enforcement, dean, or vice president.", ["management_approval", "escalation_procedure"]),
    evidence("PUBIR-E014", "PUBIR-S05-USC", "Scope", "Paraphrase: the policy applies to employees, students, consultants, vendors, affiliates, contractors, guests, retirees, and other users of USC technology resources.", ["supplier_or_third_party_incident_escalation"]),
    evidence("PUBIR-E015", "PUBIR-S05-USC", "Purpose", "Paraphrase: the policy describes expectations for managing cybersecurity incidents and minimum security requirements.", ["documented_incident_response_process"]),
    evidence("PUBIR-E016", "PUBIR-S05-USC", "Third-party information assets", "Paraphrase: the definition of cybersecurity incident includes university information assets handled, stored, or accessed by third-party services or products.", ["supplier_or_third_party_incident_escalation", "incident_reporting_channel"]),
    evidence("PUBIR-E017", "PUBIR-S06-UCONN", "Purpose", "Paraphrase: the UConn plan defines roles, responsibilities, response characterization, policy relationships, and reporting requirements.", ["documented_incident_response_process", "assigned_roles_and_responsibilities", "incident_reporting_channel"]),
    evidence("PUBIR-E018", "PUBIR-S06-UCONN", "Reporting contacts", "Paraphrase: suspected exposure can be reported to the Technology Support Center, Information Security Office, or Privacy Program.", ["incident_reporting_channel"]),
    evidence("PUBIR-E019", "PUBIR-S06-UCONN", "Roles and responsibilities", "Paraphrase: CISO, Privacy Officer, Executive Response Team, coordinator, and handlers have defined incident-response responsibilities.", ["assigned_roles_and_responsibilities", "management_approval"]),
    evidence("PUBIR-E020", "PUBIR-S06-UCONN", "Evidence preservation", "Paraphrase: evidence collection can delay restoration, and documentation supports chain of custody for gathered data.", ["evidence_preservation"]),
    evidence("PUBIR-E021", "PUBIR-S06-UCONN", "Training", "Paraphrase: incident-handling processes are periodically reviewed, exercised, and evaluated; training may include tabletop exercises.", ["periodic_testing_or_exercises"]),
    evidence("PUBIR-E022", "PUBIR-S06-UCONN", "Recovery", "Paraphrase: recovery includes lessons learned from handling incidents and their incorporation into future exercises or training.", ["post_incident_review_or_lessons_learned"]),
    evidence("PUBIR-E023", "PUBIR-S06-UCONN", "External vendor", "Paraphrase: the executive response appendix mentions procurement engaging a designated vendor for notification and monitoring services when applicable.", ["supplier_or_third_party_incident_escalation"]),
    evidence("PUBIR-E024", "PUBIR-S07-BUFFALO", "Abstract", "Paraphrase: the plan identifies incident-handling roles, responsibilities, and procedures.", ["documented_incident_response_process", "assigned_roles_and_responsibilities"]),
    evidence("PUBIR-E025", "PUBIR-S07-BUFFALO", "Reporting contacts", "Paraphrase: suspected or confirmed information security incidents can be reported to the UBIT Help Center or police for illegal/life-threatening situations.", ["incident_reporting_channel", "escalation_procedure"]),
    evidence("PUBIR-E026", "PUBIR-S07-BUFFALO", "Stewardship", "Paraphrase: the Information Security Office owns the plan and reviews it annually or after a major-risk incident.", ["management_approval", "document_version_and_validity"]),
    evidence("PUBIR-E027", "PUBIR-S07-BUFFALO", "Lifecycle", "Paraphrase: plan stages include preparation, detection, activation/response, containment, notification, remediation, resolution, and after-action analysis.", ["documented_incident_response_process", "post_incident_review_or_lessons_learned"]),
    evidence("PUBIR-E028", "PUBIR-S07-BUFFALO", "Preparation", "Paraphrase: preparation includes communication protocols, training, tool acquisition, and practice.", ["periodic_testing_or_exercises"]),
    evidence("PUBIR-E029", "PUBIR-S07-BUFFALO", "Containment", "Paraphrase: containment includes preserving evidence while minimizing and stopping damage.", ["evidence_preservation"]),
    evidence("PUBIR-E030", "PUBIR-S08-SCU", "Immediate steps", "Paraphrase: suspected security breaches should be isolated without shutdown or alteration and reported to Information Security.", ["incident_reporting_channel", "evidence_preservation"]),
    evidence("PUBIR-E031", "PUBIR-S08-SCU", "ISO actions", "Paraphrase: Information Security designates an incident handler, creates an incident log, identifies affected systems, and preserves electronic evidence.", ["assigned_roles_and_responsibilities", "evidence_preservation"]),
    evidence("PUBIR-E032", "PUBIR-S09-ASU", "Policy", "Paraphrase: the policy defines methods for identifying, tracking, and responding to network and computer-based IT security incidents.", ["documented_incident_response_process"]),
    evidence("PUBIR-E033", "PUBIR-S09-ASU", "CISO role", "Paraphrase: the CISO ensures prompt reporting, investigation, and escalation to governance or law enforcement where applicable.", ["assigned_roles_and_responsibilities", "escalation_procedure", "management_approval"]),
    evidence("PUBIR-E034", "PUBIR-S09-ASU", "User reporting", "Paraphrase: IT users report suspected incidents through the Help Desk; affected owners and executives are notified on discovery.", ["incident_reporting_channel", "escalation_procedure"]),
    evidence("PUBIR-E035", "PUBIR-S10-USNH", "IR team", "Paraphrase: the university maintains a dedicated incident response team that coordinates and executes the incident response plan.", ["assigned_roles_and_responsibilities", "documented_incident_response_process"]),
    evidence("PUBIR-E036", "PUBIR-S10-USNH", "Process phases", "Paraphrase: the standard covers assessment, containment, eradication, recovery, communication, documentation, legal compliance, notification, and lessons learned.", ["documented_incident_response_process", "escalation_procedure", "post_incident_review_or_lessons_learned"]),
    evidence("PUBIR-E037", "PUBIR-S10-USNH", "Documentation", "Paraphrase: detailed incident records include actions taken, evidence collected, and communications.", ["evidence_preservation"]),
    evidence("PUBIR-E038", "PUBIR-S10-USNH", "Approval history", "Paraphrase: the document history identifies CISO approval, GRC review, and a 2024 revision.", ["management_approval", "document_version_and_validity"]),
    evidence("PUBIR-E039", "PUBIR-S11-WWU", "Creation and maintenance", "Paraphrase: the Information Security Office creates and annually updates the IRP, which is reviewed by a standards committee and approved by the CIO.", ["management_approval", "document_version_and_validity"]),
    evidence("PUBIR-E040", "PUBIR-S11-WWU", "IRP elements", "Paraphrase: required IRP elements include core IRT contacts, risk classification, reporting, handling, investigation, remediation, documentation, communication, testing, and playbooks.", ["documented_incident_response_process", "assigned_roles_and_responsibilities", "incident_reporting_channel", "evidence_preservation"]),
    evidence("PUBIR-E041", "PUBIR-S11-WWU", "Testing", "Paraphrase: IRPs should be tested annually using tabletop or functional exercises, and lessons learned should update the plan.", ["periodic_testing_or_exercises", "post_incident_review_or_lessons_learned"]),
    evidence("PUBIR-E042", "PUBIR-S12-MCNEESE", "Risk classification", "Paraphrase: the incident coordinator and OIT review known details and classify incident risk.", ["documented_incident_response_process", "escalation_procedure"]),
    evidence("PUBIR-E043", "PUBIR-S12-MCNEESE", "IRT assembly", "Paraphrase: the coordinator assembles an IRT under CIO guidance and may consult legal, police, leadership, communications, and other departments.", ["assigned_roles_and_responsibilities", "escalation_procedure", "management_approval"]),
    evidence("PUBIR-E044", "PUBIR-S12-MCNEESE", "Supplier/procurement", "Paraphrase: procurement advises on incidents involving contracted vendors.", ["supplier_or_third_party_incident_escalation"]),
    evidence("PUBIR-E045", "PUBIR-S12-MCNEESE", "Incident documentation", "Paraphrase: critical and major incidents require incident reports, remediation documentation, tracking tickets, and archive responsibility.", ["evidence_preservation", "post_incident_review_or_lessons_learned"]),
    evidence("PUBIR-E046", "PUBIR-S02-EPA", "Template purpose", "Paraphrase: EPA provides a customizable cybersecurity incident response plan template for water and wastewater utilities.", ["documented_incident_response_process"], "draft_policy", "unknown", None, "medium", True),
    evidence("PUBIR-E047", "PUBIR-S02-EPA", "External contractors", "Paraphrase: template instructions tell utilities to coordinate with vendors, third-party suppliers, and integrators during CIRP development.", ["supplier_or_third_party_incident_escalation"], "draft_policy", "unknown", None, "medium", True),
    evidence("PUBIR-E048", "PUBIR-S02-EPA", "Maintenance and training", "Paraphrase: instructions describe the CIRP as a living document and recommend training, response-partner familiarization, and tabletop exercises.", ["periodic_testing_or_exercises", "document_version_and_validity"], "draft_policy", "unknown", None, "medium", True),
    evidence("PUBIR-E049", "PUBIR-S13-NIST61R3", "NIST guidance", "Paraphrase: NIST SP 800-61 Rev. 3 frames incident response as part of cybersecurity risk management and response/recovery activities.", ["documented_incident_response_process"], "norm_text", "approved", None, "high", True),
    evidence("PUBIR-E050", "PUBIR-S14-NIST84", "TT&E guidance", "Paraphrase: NIST SP 800-84 describes designing, conducting, and evaluating test, training, and exercise events for IT plans.", ["periodic_testing_or_exercises"], "norm_text", "approved", None, "high", True),
    evidence("PUBIR-E051", "PUBIR-S15-OSCAL", "Assessment plan model", "Paraphrase: OSCAL assessment plans express scope, schedule, activities, rules of engagement, continuous monitoring, and responsible roles.", ["evidence_preservation", "management_approval"], "norm_text", "approved", None, "high", True),
    evidence("PUBIR-E052", "PUBIR-S16-FEDRAMP", "Assessment templates", "Paraphrase: FedRAMP guidance points to OSCAL versions of SSP, SAP, SAR, and POA&M templates for assessment artifacts.", ["evidence_preservation"], "norm_text", "approved", None, "high", True),
]


def make_case(
    idx: int,
    status: str,
    required: list[str],
    evidence_ids: list[str],
    accepted: list[str],
    missing: list[str],
    rationale: str,
    difficulty: str,
    rejected: list[str] | None = None,
) -> dict[str, Any]:
    evidence_by_id = {row["evidence_id"]: row for row in EVIDENCE}
    bundle = [evidence_by_id[eid] for eid in evidence_ids]
    source_ids = sorted({row["source_id"] for row in bundle})
    requirement = (
        "Assess whether the public-document evidence supports Incident Response pre-assessment criteria: "
        + ", ".join(required)
        + "."
    )
    return {
        "case_id": f"PUBEXT18-{idx:03d}",
        "requirement_id": f"PUBEXT18-REQ-{idx:03d}",
        "requirement_text": requirement,
        "requirement": {
            "requirement_id": f"PUBEXT18-REQ-{idx:03d}",
            "source": "project_public_external_v18",
            "title": "Public-document Incident Response evidence pre-assessment",
            "text": requirement,
            "domain": "Incident Management",
            "expected_evidence_types": required,
        },
        "company_document_ids": source_ids,
        "ground_truth_status": status,
        "expected_status": status,
        "ground_truth_evidence_ids": accepted,
        "accepted_evidence_ids": accepted,
        "rejected_evidence_ids": rejected or [eid for eid in evidence_ids if eid not in accepted],
        "missing_evidence": missing,
        "missing_criteria": missing,
        "rationale": rationale,
        "source_document_ids": source_ids,
        "source_ids": source_ids,
        "source_urls": [evidence_by_id[eid]["source_url"] for eid in evidence_ids],
        "label_author": "project_initial",
        "external_review_status": "pending",
        "redistribution_note": "Case stores URLs and short paraphrases only; no full public document text or PDFs are redistributed.",
        "difficulty_type": difficulty,
        "attack_type": None,
        "mutation_type": None,
        "expected_criteria": required,
        "criteria_truth": {},
        "metadata": {
            "split": "public_external_validation_v18",
            "benchmark_version": "v18",
            "label_author": "project_initial",
            "external_review_status": "pending",
            "source_ids": source_ids,
            "source_urls": [evidence_by_id[eid]["source_url"] for eid in evidence_ids],
            "source_types": sorted({evidence_by_id[eid]["source_type"] for eid in evidence_ids}),
            "languages": ["en"],
            "public_document_derived": True,
        },
        "evidence_bundle": [
            {
                "evidence_id": row["evidence_id"],
                "source_id": row["source_id"],
                "source_url": row["source_url"],
                "page_or_section_reference": row["page_or_section_reference"],
                "short_excerpt_or_paraphrase": row["short_excerpt_or_paraphrase"],
                "redistribution_note": row["redistribution_note"],
            }
            for row in bundle
        ],
    }


CASE_SPECS = [
    ("fulfilled", ["documented_incident_response_process", "incident_reporting_channel", "assigned_roles_and_responsibilities"], ["PUBIR-E004", "PUBIR-E005", "PUBIR-E006"], ["PUBIR-E004", "PUBIR-E005", "PUBIR-E006"], [], "UMGC policy supports plan contents, CIRT roles, and reporting channel.", "public_policy_bundle"),
    ("fulfilled", ["documented_incident_response_process", "escalation_procedure", "management_approval"], ["PUBIR-E009", "PUBIR-E011", "PUBIR-E013"], ["PUBIR-E009", "PUBIR-E011", "PUBIR-E013"], [], "UA evidence supports process, authority, and escalation/approval paths.", "public_policy_bundle"),
    ("fulfilled", ["documented_incident_response_process", "assigned_roles_and_responsibilities", "incident_reporting_channel", "evidence_preservation"], ["PUBIR-E017", "PUBIR-E018", "PUBIR-E019", "PUBIR-E020"], ["PUBIR-E017", "PUBIR-E018", "PUBIR-E019", "PUBIR-E020"], [], "UConn evidence supports process, roles, reporting contacts, and evidence preservation.", "public_policy_bundle"),
    ("fulfilled", ["documented_incident_response_process", "document_version_and_validity", "periodic_testing_or_exercises"], ["PUBIR-E039", "PUBIR-E040", "PUBIR-E041"], ["PUBIR-E039", "PUBIR-E040", "PUBIR-E041"], [], "WWU guideline supports approved/reviewed IRP elements and annual exercise testing.", "public_policy_bundle"),
    ("fulfilled", ["documented_incident_response_process", "escalation_procedure", "evidence_preservation", "post_incident_review_or_lessons_learned"], ["PUBIR-E035", "PUBIR-E036", "PUBIR-E037"], ["PUBIR-E035", "PUBIR-E036", "PUBIR-E037"], [], "USNH standard supports process phases, documentation/evidence, and lessons learned.", "public_policy_bundle"),
    ("fulfilled", ["documented_incident_response_process", "assigned_roles_and_responsibilities", "supplier_or_third_party_incident_escalation"], ["PUBIR-E042", "PUBIR-E043", "PUBIR-E044"], ["PUBIR-E042", "PUBIR-E043", "PUBIR-E044"], [], "McNeese plan supports risk classification, IRT roles, and procurement involvement for vendor incidents.", "supplier_evidence_public"),
    ("fulfilled", ["documented_incident_response_process", "incident_reporting_channel", "evidence_preservation"], ["PUBIR-E030", "PUBIR-E031"], ["PUBIR-E030", "PUBIR-E031"], [], "SCU procedure supports immediate reporting, incident handler assignment, logs, and evidence preservation.", "narrow_procedure_evidence"),
    ("fulfilled", ["documented_incident_response_process", "incident_reporting_channel", "escalation_procedure"], ["PUBIR-E032", "PUBIR-E033", "PUBIR-E034"], ["PUBIR-E032", "PUBIR-E033", "PUBIR-E034"], [], "Albany State policy supports process, help-desk reporting, and escalation responsibilities.", "public_policy_bundle"),
    ("fulfilled", ["documented_incident_response_process", "incident_reporting_channel", "post_incident_review_or_lessons_learned", "evidence_preservation"], ["PUBIR-E001", "PUBIR-E002", "PUBIR-E003"], ["PUBIR-E001", "PUBIR-E002", "PUBIR-E003"], [], "MSU public page supports plan existence, reporting, forensic analysis, and post mortem elements.", "public_summary_page"),
    ("fulfilled", ["documented_incident_response_process", "assigned_roles_and_responsibilities", "periodic_testing_or_exercises", "post_incident_review_or_lessons_learned"], ["PUBIR-E024", "PUBIR-E027", "PUBIR-E028"], ["PUBIR-E024", "PUBIR-E027", "PUBIR-E028"], [], "Buffalo plan supports roles/procedures, lifecycle, practice, and after-action analysis.", "public_policy_bundle"),
    ("fulfilled", ["supplier_or_third_party_incident_escalation", "incident_reporting_channel"], ["PUBIR-E014", "PUBIR-E016"], ["PUBIR-E014", "PUBIR-E016"], [], "USC policy scope includes third-party services/products and incident-response expectations.", "third_party_scope"),
    ("fulfilled", ["documented_incident_response_process", "periodic_testing_or_exercises", "document_version_and_validity"], ["PUBIR-E007", "PUBIR-E008"], ["PUBIR-E007", "PUBIR-E008"], [], "UMGC evidence supports documented handling plus annual review linked to execution/testing.", "review_validity"),
    ("partially_fulfilled", ["documented_incident_response_process", "periodic_testing_or_exercises", "supplier_or_third_party_incident_escalation"], ["PUBIR-E004", "PUBIR-E007"], ["PUBIR-E004", "PUBIR-E007"], ["supplier_or_third_party_incident_escalation"], "UMGC evidence supports process and annual review/testing reference, but no supplier escalation in the selected bundle.", "missing_supplier"),
    ("partially_fulfilled", ["documented_incident_response_process", "assigned_roles_and_responsibilities", "periodic_testing_or_exercises"], ["PUBIR-E009", "PUBIR-E011", "PUBIR-E012"], ["PUBIR-E009", "PUBIR-E011", "PUBIR-E012"], ["periodic_testing_or_exercises"], "UA evidence supports plan and roles but not exercise/testing evidence in this bundle.", "missing_testing"),
    ("partially_fulfilled", ["documented_incident_response_process", "evidence_preservation", "post_incident_review_or_lessons_learned", "supplier_or_third_party_incident_escalation"], ["PUBIR-E017", "PUBIR-E020", "PUBIR-E022"], ["PUBIR-E017", "PUBIR-E020", "PUBIR-E022"], ["supplier_or_third_party_incident_escalation"], "UConn evidence supports process, evidence preservation, and lessons learned, but no third-party escalation in the selected bundle.", "missing_supplier"),
    ("partially_fulfilled", ["documented_incident_response_process", "assigned_roles_and_responsibilities", "incident_reporting_channel", "periodic_testing_or_exercises"], ["PUBIR-E024", "PUBIR-E025", "PUBIR-E026"], ["PUBIR-E024", "PUBIR-E025", "PUBIR-E026"], ["periodic_testing_or_exercises"], "Buffalo evidence supports plan, roles, reporting, and review ownership, but not testing in the selected bundle.", "missing_testing"),
    ("partially_fulfilled", ["documented_incident_response_process", "supplier_or_third_party_incident_escalation", "periodic_testing_or_exercises"], ["PUBIR-E014", "PUBIR-E015", "PUBIR-E016"], ["PUBIR-E014", "PUBIR-E015", "PUBIR-E016"], ["periodic_testing_or_exercises"], "USC policy supports scope and third-party relevance but lacks exercise evidence in the selected bundle.", "missing_testing"),
    ("partially_fulfilled", ["documented_incident_response_process", "incident_reporting_channel", "post_incident_review_or_lessons_learned"], ["PUBIR-E030", "PUBIR-E031"], ["PUBIR-E030", "PUBIR-E031"], ["post_incident_review_or_lessons_learned"], "SCU procedure supports reporting and evidence handling but not after-action review in this bundle.", "missing_lessons"),
    ("partially_fulfilled", ["documented_incident_response_process", "incident_reporting_channel", "document_version_and_validity"], ["PUBIR-E032", "PUBIR-E034"], ["PUBIR-E032", "PUBIR-E034"], ["document_version_and_validity"], "Albany State evidence supports process and reporting/escalation, but no review or validity date in selected evidence.", "missing_validity"),
    ("partially_fulfilled", ["documented_incident_response_process", "assigned_roles_and_responsibilities", "evidence_preservation", "periodic_testing_or_exercises"], ["PUBIR-E035", "PUBIR-E037", "PUBIR-E038"], ["PUBIR-E035", "PUBIR-E037", "PUBIR-E038"], ["periodic_testing_or_exercises"], "USNH evidence supports team, records, and approval history, but not testing in selected evidence.", "missing_testing"),
    ("partially_fulfilled", ["documented_incident_response_process", "supplier_or_third_party_incident_escalation", "evidence_preservation"], ["PUBIR-E042", "PUBIR-E044"], ["PUBIR-E042", "PUBIR-E044"], ["evidence_preservation"], "McNeese evidence supports process and vendor/procurement involvement, but not evidence preservation in selected evidence.", "missing_evidence_preservation"),
    ("partially_fulfilled", ["documented_incident_response_process", "incident_reporting_channel", "evidence_preservation", "periodic_testing_or_exercises"], ["PUBIR-E001", "PUBIR-E002"], ["PUBIR-E001", "PUBIR-E002"], ["periodic_testing_or_exercises"], "MSU summary supports plan, reporting, forensics, and post mortem, but no testing evidence.", "missing_testing"),
    ("partially_fulfilled", ["documented_incident_response_process", "management_approval", "periodic_testing_or_exercises", "supplier_or_third_party_incident_escalation"], ["PUBIR-E039", "PUBIR-E041"], ["PUBIR-E039", "PUBIR-E041"], ["supplier_or_third_party_incident_escalation"], "WWU evidence supports ownership, review/approval, and annual testing but not supplier escalation.", "missing_supplier"),
    ("partially_fulfilled", ["documented_incident_response_process", "post_incident_review_or_lessons_learned", "supplier_or_third_party_incident_escalation"], ["PUBIR-E036", "PUBIR-E037"], ["PUBIR-E036", "PUBIR-E037"], ["supplier_or_third_party_incident_escalation"], "USNH evidence supports process and lessons learned, but no supplier escalation.", "missing_supplier"),
    ("not_fulfilled", ["documented_incident_response_process"], ["PUBIR-E049"], [], ["documented_incident_response_process"], "NIST guidance is a public norm source, not implementation evidence for an organization.", "norm_text_confusion"),
    ("not_fulfilled", ["periodic_testing_or_exercises"], ["PUBIR-E050"], [], ["periodic_testing_or_exercises"], "NIST SP 800-84 guidance supports what exercises are, but it is not evidence that an organization performed one.", "norm_text_confusion"),
    ("not_fulfilled", ["evidence_preservation"], ["PUBIR-E051"], [], ["evidence_preservation"], "OSCAL assessment-plan documentation is structured assessment guidance, not organization-specific evidence preservation.", "assessment_template_confusion"),
    ("not_fulfilled", ["documented_incident_response_process", "supplier_or_third_party_incident_escalation"], ["PUBIR-E046", "PUBIR-E047"], [], ["documented_incident_response_process", "supplier_or_third_party_incident_escalation"], "EPA template instructions are not an adopted incident-response plan or supplier escalation record.", "template_only"),
    ("not_fulfilled", ["documented_incident_response_process"], ["PUBIR-E052"], [], ["documented_incident_response_process"], "FedRAMP/OSCAL assessment-template references are not implementation evidence for incident response.", "assessment_template_confusion"),
    ("not_fulfilled", ["incident_reporting_channel"], ["PUBIR-E049", "PUBIR-E051"], [], ["incident_reporting_channel"], "Normative guidance and OSCAL model references do not provide a public organization's reporting channel.", "norm_text_confusion"),
    ("not_fulfilled", ["supplier_or_third_party_incident_escalation"], ["PUBIR-E050", "PUBIR-E052"], [], ["supplier_or_third_party_incident_escalation"], "Testing guidance and assessment templates do not prove supplier incident escalation.", "norm_text_confusion"),
    ("not_fulfilled", ["periodic_testing_or_exercises", "post_incident_review_or_lessons_learned"], ["PUBIR-E046"], [], ["periodic_testing_or_exercises", "post_incident_review_or_lessons_learned"], "A blank/customizable template is not a completed exercise record or lessons-learned record.", "template_only"),
    ("not_fulfilled", ["documented_incident_response_process", "assigned_roles_and_responsibilities"], ["PUBIR-E048"], [], ["documented_incident_response_process", "assigned_roles_and_responsibilities"], "Training advice in template instructions is not an adopted plan with assigned roles.", "template_only"),
    ("not_fulfilled", ["evidence_preservation", "management_approval"], ["PUBIR-E052", "PUBIR-E051"], [], ["evidence_preservation", "management_approval"], "Assessment model and template references cannot substitute for organization-specific evidence custody and owner approval.", "assessment_template_confusion"),
    ("not_fulfilled", ["documented_incident_response_process", "document_version_and_validity"], ["PUBIR-E049", "PUBIR-E050"], [], ["documented_incident_response_process", "document_version_and_validity"], "NIST publications are guidance, not a versioned organization plan.", "norm_text_confusion"),
    ("unclear", ["documented_incident_response_process", "document_version_and_validity"], ["PUBIR-E003"], ["PUBIR-E003"], ["document_version_and_validity"], "MSU page links a full plan but the selected short public summary does not expose enough review/validity metadata.", "insufficient_public_metadata"),
    ("unclear", ["documented_incident_response_process", "supplier_or_third_party_incident_escalation"], ["PUBIR-E014", "PUBIR-E016"], ["PUBIR-E014", "PUBIR-E016"], ["documented_incident_response_process"], "USC third-party scope is relevant, but this selected evidence alone is insufficient for a full documented process.", "scope_without_process"),
    ("unclear", ["periodic_testing_or_exercises", "evidence_preservation"], ["PUBIR-E021", "PUBIR-E020"], ["PUBIR-E021", "PUBIR-E020"], ["periodic_testing_or_exercises"], "UConn mentions exercises and evidence preservation, but selected evidence does not show a recent completed exercise.", "testing_not_recent"),
    ("unclear", ["periodic_testing_or_exercises"], ["PUBIR-E028"], ["PUBIR-E028"], ["periodic_testing_or_exercises"], "Buffalo preparation mentions practice, but the evidence does not show a completed tabletop or test record.", "practice_not_test_record"),
    ("unclear", ["documented_incident_response_process", "management_approval"], ["PUBIR-E035", "PUBIR-E038"], ["PUBIR-E035", "PUBIR-E038"], ["documented_incident_response_process"], "USNH approval history and team evidence are strong, but the selected evidence is not enough for a full process-only conclusion.", "selected_evidence_insufficient"),
    ("unclear", ["supplier_or_third_party_incident_escalation"], ["PUBIR-E023"], ["PUBIR-E023"], ["supplier_or_third_party_incident_escalation"], "UConn vendor engagement evidence is for notification/monitoring services after breach analysis, not a clear supplier incident escalation procedure.", "indirect_supplier_evidence"),
    ("unclear", ["document_version_and_validity", "periodic_testing_or_exercises"], ["PUBIR-E048"], [], ["document_version_and_validity", "periodic_testing_or_exercises"], "EPA template instructions recommend maintenance and training but do not prove an implemented and current organization plan.", "template_only_unclear"),
    ("unclear", ["evidence_preservation", "incident_reporting_channel"], ["PUBIR-E030"], ["PUBIR-E030"], ["evidence_preservation"], "SCU immediate steps are relevant, but a single short procedure excerpt does not fully establish evidence-preservation governance.", "narrow_excerpt"),
    ("unclear", ["documented_incident_response_process", "post_incident_review_or_lessons_learned"], ["PUBIR-E045"], ["PUBIR-E045"], ["documented_incident_response_process"], "McNeese documentation evidence supports reports/debriefs but not the full incident-response process alone.", "documentation_without_process"),
    ("unclear", ["supplier_or_third_party_incident_escalation", "management_approval"], ["PUBIR-E044", "PUBIR-E043"], ["PUBIR-E044", "PUBIR-E043"], ["supplier_or_third_party_incident_escalation"], "Procurement advice for vendor incidents is relevant but not a clear supplier escalation SLA or notification obligation.", "indirect_supplier_evidence"),
    ("unclear", ["documented_incident_response_process", "periodic_testing_or_exercises"], ["PUBIR-E046", "PUBIR-E048"], [], ["documented_incident_response_process", "periodic_testing_or_exercises"], "Template instructions are useful but do not establish adoption or completed testing.", "template_only_unclear"),
]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def flatten_for_csv(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, (list, dict)):
            out[key] = json.dumps(value, sort_keys=True)
        else:
            out[key] = value
    return out


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flat_rows = [flatten_for_csv(row) for row in rows]
    if fieldnames is None:
        fieldnames = list(flat_rows[0]) if flat_rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flat_rows)


def render_source_inventory_md() -> str:
    lines = [
        "# Public External Source Inventory v18",
        "",
        "Access date: 2026-04-26.",
        "",
        "This inventory records public Incident Response and assessment/provenance sources used to create a public-document-derived stress split. Full PDFs and full web pages are not redistributed; the dataset stores URLs plus short paraphrases or short excerpts only.",
        "",
        "| source_id | title | organization | source type | redistribution decision | relevance |",
        "|---|---|---|---|---|---|",
    ]
    for src in SOURCES:
        lines.append(
            f"| {src['source_id']} | {src['title']} | {src['organization']} | {src['source_type']} | "
            f"{src['redistribution_decision']} | {src['relevance_to_ir_criteria']} |"
        )
    lines.extend(
        [
            "",
            "## Reviewer Note",
            "",
            "The labels for the public external validation cases are project-initial labels. They should not be described as independent or auditor-validated until an external reviewer has completed the review sheet.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_reviewer_packet(cases: list[dict[str, Any]]) -> str:
    counts = Counter(case["expected_status"] for case in cases)
    lines = [
        "# Public External Reviewer Packet v18",
        "",
        "This packet supports external review of project-initial labels for public-document-derived Incident Response evidence cases.",
        "",
        "## What To Review",
        "",
        "- `data/benchmark/public_external_review_sheet_v18.csv` is the editable review sheet.",
        "- Each row includes a case ID, requirement, expected status, evidence IDs, short paraphrases, URLs, and project rationale.",
        "- The reviewer should agree/disagree with the expected status, provide a corrected status where needed, mark evidence IDs accepted/rejected, and flag copyright/confidentiality concerns.",
        "",
        "## Label Status",
        "",
        "All labels are `project_initial` and `external_review_status=pending`. This dataset reduces document-generation dependence because the evidence comes from public documents, but it does not remove label-author dependence.",
        "",
        "## Composition",
        "",
    ]
    for label in ["fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"]:
        lines.append(f"- {label}: {counts[label]}")
    lines.extend(
        [
            f"- total cases: {len(cases)}",
            "",
            "## Review Guidance",
            "",
            "Use the public URL and section reference to inspect the surrounding source if needed. The local dataset intentionally avoids redistributing full public documents. If a case relies on template or norm text rather than organization-specific implementation evidence, treat that as insufficient unless the requirement explicitly asks only for guidance-level evidence.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_pending_note(num_sources: int, num_evidence: int, num_cases: int) -> str:
    return (
        "# Public External Validation Pending v18\n\n"
        f"Created a public-document-derived Incident Response validation split with {num_sources} public sources, "
        f"{num_evidence} evidence passages, and {num_cases} project-initial cases.\n\n"
        "The evidence corpus stores public URLs, section references, and short paraphrases only. It does not redistribute full PDFs or full policy pages unless a future licensing review explicitly permits that.\n\n"
        "The labels are project-initial (`label_author=project_initial`) and remain `external_review_status=pending`. This reduces document-generation dependence because the evidence is derived from real public Incident Response plans, policies, templates, and assessment/provenance artifacts. It does not remove label-author dependence and must not be described as independently validated or auditor-reviewed.\n\n"
        "Final paper integration should wait until an external reviewer completes `data/benchmark/public_external_review_sheet_v18.csv`, or the paper should explicitly call it a public-document-derived stress check with project-initial labels.\n"
    )


def main() -> None:
    cases = [
        make_case(index + 1, status, required, evidence_ids, accepted, missing, rationale, difficulty)
        for index, (status, required, evidence_ids, accepted, missing, rationale, difficulty) in enumerate(CASE_SPECS)
    ]
    evidence_rows = EVIDENCE

    source_fields = [
        "source_id",
        "title",
        "organization",
        "url",
        "source_type",
        "access_date",
        "license_or_terms_note",
        "redistribution_decision",
        "relevance_to_ir_criteria",
        "notes",
    ]
    evidence_fields = [
        "evidence_id",
        "source_id",
        "source_url",
        "page_or_section_reference",
        "short_excerpt_or_paraphrase",
        "criterion_tags",
        "source_type",
        "approval_status_if_inferable",
        "validity_or_review_date_if_inferable",
        "language",
        "trust_level",
        "redistribution_note",
    ]
    case_fields = [
        "case_id",
        "requirement_text",
        "evidence_bundle",
        "expected_status",
        "accepted_evidence_ids",
        "rejected_evidence_ids",
        "missing_criteria",
        "rationale",
        "source_document_ids",
        "source_ids",
        "source_urls",
        "label_author",
        "external_review_status",
        "redistribution_note",
    ]
    review_fields = [
        "case_id",
        "requirement_text",
        "evidence_ids",
        "evidence_summaries_and_urls",
        "expected_status",
        "reviewer_agrees",
        "corrected_status",
        "reviewer_accepted_evidence_ids",
        "reviewer_rejected_evidence_ids",
        "reviewer_rationale",
        "flag_unclear",
        "flag_confidential",
        "flag_copyright",
        "reviewer_notes",
    ]

    write_csv(ROOT / "data/external_public/source_inventory_v18.csv", SOURCES, source_fields)
    write_csv(ROOT / "data/external_public/public_ir_evidence_corpus_v18.csv", evidence_rows, evidence_fields)
    write_jsonl(ROOT / "data/external_public/public_ir_evidence_corpus_v18.jsonl", evidence_rows)
    write_csv(ROOT / "data/benchmark/public_external_validation_cases_v18.csv", cases, case_fields)
    write_jsonl(ROOT / "data/benchmark/public_external_validation_cases_v18.jsonl", cases)

    review_rows = []
    for case in cases:
        review_rows.append(
            {
                "case_id": case["case_id"],
                "requirement_text": case["requirement_text"],
                "evidence_ids": [item["evidence_id"] for item in case["evidence_bundle"]],
                "evidence_summaries_and_urls": case["evidence_bundle"],
                "expected_status": case["expected_status"],
                "reviewer_agrees": "",
                "corrected_status": "",
                "reviewer_accepted_evidence_ids": "",
                "reviewer_rejected_evidence_ids": "",
                "reviewer_rationale": "",
                "flag_unclear": "",
                "flag_confidential": "",
                "flag_copyright": "",
                "reviewer_notes": "",
            }
        )
    write_csv(ROOT / "data/benchmark/public_external_review_sheet_v18.csv", review_rows, review_fields)

    print(
        {
            "sources": len(SOURCES),
            "evidence_passages": len(evidence_rows),
            "cases": len(cases),
            "labels": dict(Counter(case["expected_status"] for case in cases)),
        }
    )


if __name__ == "__main__":
    main()
