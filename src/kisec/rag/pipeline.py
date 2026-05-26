from __future__ import annotations

from kisec.compliance.rule_based import RuleBasedComplianceAssessor


class EvidenceGroundedAssessmentPipeline:
    """Minimal non-LLM pipeline used by the first reproducible baseline."""

    def __init__(self) -> None:
        self.assessor = RuleBasedComplianceAssessor()
