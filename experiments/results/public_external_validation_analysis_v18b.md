# Public External Validation Analysis v18b

- Evaluable cases: 46
- Evidence passages: 52
- Label status: project-initial; external review pending.
- LLM status: LLM methods were not run; deterministic v18b evaluator makes no provider calls by default.

## Results

- metadata_aware: Macro-F1=0.267, false compliance=0.283, abstention=0.565, unsafe evidence=0.087, source attribution failure=0.087, residual grounding risk=0.109, Evidence-F1=0.428
- provenance_balanced: Macro-F1=0.319, false compliance=0.500, abstention=0.196, unsafe evidence=0.109, source attribution failure=0.109, residual grounding risk=0.304, Evidence-F1=0.665
- provenance_conservative: Macro-F1=0.209, false compliance=0.283, abstention=0.783, unsafe evidence=0.000, source attribution failure=0.000, residual grounding risk=0.000, Evidence-F1=0.774
- provenance_conservative_with_guard: Macro-F1=0.209, false compliance=0.283, abstention=0.783, unsafe evidence=0.000, source attribution failure=0.000, residual grounding risk=0.000, Evidence-F1=0.774

## Interpretation

v18b uses canonical public source types and explicit implementation-evidence flags. The split remains project-initial and should be treated as a public-document-derived diagnostic stress test until external review is complete.
