# Public External Error Analysis v18b

- Evaluable cases: 46
- Misclassified cases by at least one method: 42
- Misclassified method-case pairs: 119

## Primary Error Categories

- method_overabstains: 11
- requirement_too_composite: 8
- template_guidance_confusion: 8
- method_overtrusts_policy: 6
- public_guidance_used_as_org_evidence: 5
- paraphrase_too_short: 2
- genuine_generalization_failure: 2

## v18 vs v18b Primary Error Category Comparison

| category | v18 | v18b |
|---|---:|---:|
| genuine_generalization_failure | 0 | 2 |
| method_overabstains | 0 | 11 |
| method_overtrusts_policy | 0 | 6 |
| paraphrase_too_short | 0 | 2 |
| public_guidance_used_as_org_evidence | 5 | 5 |
| requirement_too_composite | 0 | 8 |
| source_type_mapping_error | 29 | 0 |
| template_guidance_confusion | 8 | 8 |

## Misclassified Cases

### PUBEXT18B-001 (fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains
- Canonical source types: public_org_policy

### PUBEXT18B-002 (fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains
- Canonical source types: public_org_plan

### PUBEXT18B-003 (fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: revised
- Primary error type: requirement_too_composite
- Categories: requirement_too_composite|label_too_strict|method_overabstains
- Canonical source types: public_org_plan

### PUBEXT18B-004 (fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains
- Canonical source types: public_org_standard

### PUBEXT18B-005 (fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: revised
- Primary error type: requirement_too_composite
- Categories: requirement_too_composite|paraphrase_too_short|label_too_strict|method_overabstains
- Canonical source types: public_org_standard

### PUBEXT18B-006 (fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=partially_fulfilled, provenance-conservative=partially_fulfilled, guarded=partially_fulfilled
- Cleanup status: retained_clean
- Primary error type: paraphrase_too_short
- Categories: paraphrase_too_short
- Canonical source types: public_org_plan

### PUBEXT18B-007 (fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=partially_fulfilled, provenance-conservative=partially_fulfilled, guarded=partially_fulfilled
- Cleanup status: retained_clean
- Primary error type: genuine_generalization_failure
- Categories: genuine_generalization_failure
- Canonical source types: public_org_procedure

### PUBEXT18B-008 (fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains
- Canonical source types: public_org_policy

### PUBEXT18B-009 (fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=partially_fulfilled, provenance-conservative=partially_fulfilled, guarded=partially_fulfilled
- Cleanup status: revised
- Primary error type: requirement_too_composite
- Categories: requirement_too_composite|label_too_strict
- Canonical source types: public_org_plan

### PUBEXT18B-010 (fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=partially_fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: revised
- Primary error type: requirement_too_composite
- Categories: requirement_too_composite|paraphrase_too_short|label_too_strict|method_overabstains
- Canonical source types: public_org_plan

### PUBEXT18B-011 (fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains
- Canonical source types: public_org_policy

### PUBEXT18B-012 (fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains
- Canonical source types: public_org_policy

### PUBEXT18B-013 (partially_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=partially_fulfilled, provenance-conservative=partially_fulfilled, guarded=partially_fulfilled
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains
- Canonical source types: public_org_policy

### PUBEXT18B-014 (partially_fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=partially_fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains
- Canonical source types: public_org_plan

### PUBEXT18B-015 (partially_fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: revised
- Primary error type: requirement_too_composite
- Categories: requirement_too_composite|label_too_strict|method_overabstains|genuine_generalization_failure
- Canonical source types: public_org_plan

### PUBEXT18B-016 (partially_fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=partially_fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: revised
- Primary error type: requirement_too_composite
- Categories: requirement_too_composite|paraphrase_too_short|label_too_strict|method_overabstains
- Canonical source types: public_org_plan

### PUBEXT18B-017 (partially_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=partially_fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains
- Canonical source types: public_org_policy

### PUBEXT18B-018 (partially_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=partially_fulfilled, provenance-conservative=partially_fulfilled, guarded=partially_fulfilled
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains
- Canonical source types: public_org_procedure

### PUBEXT18B-019 (partially_fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overabstains
- Categories: method_overabstains|genuine_generalization_failure
- Canonical source types: public_org_policy

### PUBEXT18B-020 (partially_fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=partially_fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: revised
- Primary error type: requirement_too_composite
- Categories: requirement_too_composite|paraphrase_too_short|label_too_strict|method_overabstains
- Canonical source types: public_org_standard

### PUBEXT18B-022 (partially_fulfilled)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=partially_fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: revised
- Primary error type: requirement_too_composite
- Categories: requirement_too_composite|label_too_strict|method_overabstains
- Canonical source types: public_org_plan

### PUBEXT18B-025 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=unclear, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: public_guidance_used_as_org_evidence
- Categories: public_guidance_used_as_org_evidence|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: public_guidance

### PUBEXT18B-026 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=unclear, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: public_guidance_used_as_org_evidence
- Categories: public_guidance_used_as_org_evidence|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: public_guidance

### PUBEXT18B-027 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=unclear, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: public_guidance_used_as_org_evidence
- Categories: public_guidance_used_as_org_evidence|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: oscal_control

### PUBEXT18B-028 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=partially_fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: template_guidance_confusion
- Categories: template_guidance_confusion|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: public_template

### PUBEXT18B-029 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=unclear, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: template_guidance_confusion
- Categories: template_guidance_confusion|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: assessment_template

### PUBEXT18B-030 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=unclear, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: public_guidance_used_as_org_evidence
- Categories: public_guidance_used_as_org_evidence|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: oscal_control|public_guidance

### PUBEXT18B-031 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=unclear, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: template_guidance_confusion
- Categories: template_guidance_confusion|public_guidance_used_as_org_evidence|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: assessment_template|public_guidance

### PUBEXT18B-032 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=partially_fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: template_guidance_confusion
- Categories: template_guidance_confusion|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: public_template

### PUBEXT18B-033 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=partially_fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: template_guidance_confusion
- Categories: template_guidance_confusion|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: public_template

### PUBEXT18B-034 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=unclear, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: template_guidance_confusion
- Categories: template_guidance_confusion|public_guidance_used_as_org_evidence|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: assessment_template|oscal_control

### PUBEXT18B-035 (not_fulfilled)
- Predictions: metadata-aware=unclear, provenance-balanced=unclear, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: public_guidance_used_as_org_evidence
- Categories: public_guidance_used_as_org_evidence|policy_vs_implementation_confusion|missing_metadata|method_overabstains
- Canonical source types: public_guidance

### PUBEXT18B-036 (unclear)
- Predictions: metadata-aware=unclear, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overtrusts_policy
- Categories: method_overtrusts_policy|genuine_generalization_failure
- Canonical source types: public_org_plan

### PUBEXT18B-037 (unclear)
- Predictions: metadata-aware=unclear, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overtrusts_policy
- Categories: method_overtrusts_policy|genuine_generalization_failure
- Canonical source types: public_org_policy

### PUBEXT18B-038 (unclear)
- Predictions: metadata-aware=fulfilled, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overtrusts_policy
- Categories: method_overtrusts_policy|genuine_generalization_failure
- Canonical source types: public_org_plan

### PUBEXT18B-040 (unclear)
- Predictions: metadata-aware=unclear, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overtrusts_policy
- Categories: method_overtrusts_policy|genuine_generalization_failure
- Canonical source types: public_org_standard

### PUBEXT18B-041 (unclear)
- Predictions: metadata-aware=unclear, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overtrusts_policy
- Categories: method_overtrusts_policy|genuine_generalization_failure
- Canonical source types: public_org_plan

### PUBEXT18B-042 (unclear)
- Predictions: metadata-aware=unclear, provenance-balanced=partially_fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: template_guidance_confusion
- Categories: template_guidance_confusion|policy_vs_implementation_confusion|missing_metadata
- Canonical source types: public_template

### PUBEXT18B-043 (unclear)
- Predictions: metadata-aware=partially_fulfilled, provenance-balanced=partially_fulfilled, provenance-conservative=partially_fulfilled, guarded=partially_fulfilled
- Cleanup status: retained_clean
- Primary error type: genuine_generalization_failure
- Categories: genuine_generalization_failure
- Canonical source types: public_org_procedure

### PUBEXT18B-044 (unclear)
- Predictions: metadata-aware=unclear, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: method_overtrusts_policy
- Categories: method_overtrusts_policy|genuine_generalization_failure
- Canonical source types: public_org_plan

### PUBEXT18B-045 (unclear)
- Predictions: metadata-aware=unclear, provenance-balanced=partially_fulfilled, provenance-conservative=partially_fulfilled, guarded=partially_fulfilled
- Cleanup status: retained_clean
- Primary error type: paraphrase_too_short
- Categories: paraphrase_too_short
- Canonical source types: public_org_plan

### PUBEXT18B-046 (unclear)
- Predictions: metadata-aware=unclear, provenance-balanced=fulfilled, provenance-conservative=unclear, guarded=unclear
- Cleanup status: retained_clean
- Primary error type: template_guidance_confusion
- Categories: template_guidance_confusion|policy_vs_implementation_confusion|missing_metadata|method_overtrusts_policy|genuine_generalization_failure
- Canonical source types: public_template
