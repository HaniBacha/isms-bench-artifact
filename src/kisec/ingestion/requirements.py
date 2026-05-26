from __future__ import annotations

from pathlib import Path

from kisec.models import Requirement
from kisec.utils.io import read_json, write_json


DEFAULT_INCIDENT_REQUIREMENTS = [
    Requirement(
        requirement_id="IR-001",
        source="synthetic_ir_control_set_v1",
        title="Documented incident response process",
        text=(
            "The organization shall maintain a documented information security "
            "incident response process covering detection, triage, containment, "
            "eradication, recovery, communication, and post-incident review."
        ),
        domain="Incident Management",
        expected_evidence_types=["process", "roles", "post_incident_review"],
    ),
    Requirement(
        requirement_id="IR-002",
        source="synthetic_ir_control_set_v1",
        title="Incident response roles and responsibilities",
        text=(
            "The organization shall assign incident response roles and "
            "responsibilities, including escalation ownership and decision authority "
            "for incident handling."
        ),
        domain="Incident Management",
        expected_evidence_types=["roles", "escalation"],
    ),
    Requirement(
        requirement_id="IR-003",
        source="synthetic_ir_control_set_v1",
        title="Testing of incident response capability",
        text=(
            "The organization shall test the incident response process through "
            "tabletop exercises, simulations, or equivalent drills and track "
            "lessons learned."
        ),
        domain="Incident Management",
        expected_evidence_types=["testing", "lessons_learned"],
    ),
    Requirement(
        requirement_id="IR-004",
        source="synthetic_ir_control_set_v1",
        title="Incident reporting and escalation",
        text=(
            "The organization shall define reporting and escalation channels for "
            "suspected or confirmed information security incidents, including "
            "time-bound notification criteria."
        ),
        domain="Incident Management",
        expected_evidence_types=["reporting", "escalation"],
    ),
]

INCIDENT_RESPONSE_CRITERIA_V02 = [
    "documented_incident_response_process",
    "assigned_roles_and_responsibilities",
    "incident_reporting_channel",
    "escalation_procedure",
    "periodic_testing_or_exercises",
    "post_incident_review_or_lessons_learned",
    "supplier_or_third_party_incident_escalation",
    "evidence_of_recent_test_or_exercise",
    "management_approval",
    "document_version_and_validity",
]

DEFAULT_INCIDENT_REQUIREMENTS_V02 = [
    Requirement(
        requirement_id="IR-V02-001",
        source="synthetic_ir_control_set_v02",
        title="Evidence-grounded incident response management",
        text=(
            "The organization shall maintain current and approved incident response "
            "documentation, assign roles and reporting channels, define escalation "
            "including supplier or third-party incidents, test the process periodically, "
            "retain recent exercise evidence, perform post-incident review or lessons "
            "learned activities, and maintain document version validity."
        ),
        domain="Incident Management",
        expected_evidence_types=INCIDENT_RESPONSE_CRITERIA_V02,
    )
]


def write_default_requirements(path: str | Path) -> list[Requirement]:
    requirements = DEFAULT_INCIDENT_REQUIREMENTS
    write_json(path, [requirement.to_dict() for requirement in requirements])
    return requirements


def write_default_requirements_v02(path: str | Path) -> list[Requirement]:
    requirements = DEFAULT_INCIDENT_REQUIREMENTS_V02
    write_json(path, [requirement.to_dict() for requirement in requirements])
    return requirements


def load_requirements(path: str | Path) -> list[Requirement]:
    return [Requirement.from_dict(item) for item in read_json(path)]
