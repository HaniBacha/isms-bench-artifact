# Residual Attack Risk Sensitivity Check

This script recomputes residual attack risk from existing combined attack-suite component metrics. It does not add new predictions or change the paper's main result tables.

Weight settings:
- `primary`: full=1.0, unsafe=0.55, source=0.45, partial=0.25
- `full_success_heavy`: full=1.5, unsafe=0.5, source=0.4, partial=0.2
- `unsafe_evidence_heavy`: full=1.0, unsafe=1.2, source=0.45, partial=0.2
- `source_error_heavy`: full=1.0, unsafe=0.55, source=1.2, partial=0.2
- `equalized_components`: full=1.0, unsafe=1.0, source=1.0, partial=1.0

Lowest-risk method by setting:
- `primary`: `provenance_conservative` with residual attack risk 0.403
- `full_success_heavy`: `provenance_conservative` with residual attack risk 0.355
- `unsafe_evidence_heavy`: `provenance_conservative` with residual attack risk 0.609
- `source_error_heavy`: `provenance_conservative` with residual attack risk 0.602
- `equalized_components`: `provenance_balanced` with residual attack risk 0.973

Interpretation: this is a diagnostic robustness check for the aggregate metric, not a validated organizational loss function. Component metrics remain the primary evidence.
