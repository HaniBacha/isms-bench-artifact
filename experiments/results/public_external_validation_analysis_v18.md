# Public External Validation Analysis v18

- Cases: 46
- Evidence passages: 52
- Label status: project-initial; external review pending.
- LLM status: LLM methods were not run; deterministic v18 evaluator makes no provider calls by default.

## Results

- metadata_aware: Macro-F1=0.267, false compliance=0.283, abstention=0.565, unsafe evidence=0.087, source attribution failure=0.087, residual grounding risk=0.109, Evidence-F1=0.428
- provenance_balanced: Macro-F1=0.337, false compliance=0.500, abstention=0.196, unsafe evidence=0.109, source attribution failure=0.109, residual grounding risk=0.326, Evidence-F1=0.665
- provenance_conservative: Macro-F1=0.227, false compliance=0.261, abstention=0.826, unsafe evidence=0.000, source attribution failure=0.000, residual grounding risk=0.000, Evidence-F1=0.774
- provenance_conservative_with_guard: Macro-F1=0.227, false compliance=0.261, abstention=0.826, unsafe evidence=0.000, source attribution failure=0.000, residual grounding risk=0.000, Evidence-F1=0.774

## Interpretation

This split reduces document-generation dependence because the evidence passages are derived from real public incident-response plans, policies, templates, and assessment/provenance references. It does not remove label-author dependence: expected statuses and evidence decisions are project-initial and require independent review before being described as validation evidence.
