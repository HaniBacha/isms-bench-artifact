# Claims and Evidence

This file maps submitted-paper claims to repository evidence. A machine-readable companion is maintained in `CLAIMS_AND_EVIDENCE.csv`..

| Claim | Evidence files | Status | Safe wording |
|---|---|---|---|
| False compliance is a security-relevant failure mode in AI-assisted ISMS Incident Response pre-assessment. | `experiments/results/summary_v04.csv`, `experiments/results/attack_metrics_by_method_v04.csv`, `CLAIMS_AND_EVIDENCE.csv` | Supported under benchmark conditions | "False compliance is measurable and security-relevant in this pre-assessment benchmark." |
| ISMS-Bench is reproducible. | `scripts/`, `tests/`, `data/benchmark/`, `data/attacks/`, `REPRODUCIBILITY.md` | Supported | "Reproducible benchmark artifact"; not "real-world validated system". |
| Provenance-aware assessment reduces false compliance compared with metadata-aware rules. | `experiments/results/summary_v04.csv`, `experiments/results/bootstrap_ci_v04.csv`, `experiments/results/method_comparison_tests_v04.csv` | Supported for reported deterministic benchmark | "Reduces false compliance"; not "improves general accuracy". |
| Conservative provenance reduces false compliance further but increases abstention. | `experiments/results/summary_v04.csv`, `experiments/results/bootstrap_ci_v04.csv` | Supported | "Risk/coverage trade-off." |
| Provenance-aware methods reduce residual attack risk but do not eliminate attack risk. | `experiments/results/attack_metrics_by_method_v04.csv`, `experiments/results/attack_metrics_by_type_v04.csv` | Supported | "Attack risk is reduced; partial unsafe-evidence acceptance remains." |
| Real LLM/RAG baselines show the false-compliance failure mode. | `experiments/results/llm_medium_150_summary_v14.csv`, `experiments/results/llm_attack_150_summary_v14.csv` | Supported for one model family and subsets | "Subset/model-specific diagnostic evidence." |
| Public-document-derived split reduces document-generation dependence. | `data/benchmark/public_external_validation_cases_v18c.jsonl`, `data/benchmark/public_external_review_sheet_v18c.csv`, `data/external_public/public_ir_evidence_corpus_v18b.jsonl` | Partially supported | "Diagnostic stress evidence"; not "independent external validation"; labels remain project-initial. |
| The benchmark generalizes to all ISMS domains. | None | Unsupported | Move to future work. |
| The system can certify compliance or replace auditors. | None | Unsupported | Must not be claimed. |
| The LLM results generalize across all LLMs. | None | Unsupported | State one model family and subset runs only. |
| No completed independent expert validation is reported. | `external_validation_protocol/`, `BENCHMARK_CARD.md`, `SCOPE_AND_LIMITATIONS.md` | Supported as limitation | "The artifact contains a protocol for future expert review, not completed expert annotations." |
| The benchmark includes several diagnostic surfaces that reduce generator-coupling concerns, but no completed external expert validation is reported. | Heldout templates; independent challenge set; alternative-generator set; manual challenge set; public-document-derived diagnostic split; mutation tests; metadata-spoofing diagnostics; adversarial fixtures; leakage checks | Partially supported | Labels remain project-authored unless stated otherwise; not field or expert validation. |
| Diagnostic checks mitigate but do not eliminate synthetic-data and generator-coupling concerns. | `scripts/check_generator_coupling.py`, `data/benchmark/manual_challenge_cases_v09.jsonl`, `data/benchmark/public_external_validation_cases_v18c.jsonl`, `experiments/results/external_validity_v07.csv`, `experiments/results/metadata_spoofing_ablation_v23.csv` | Partially supported | "Diagnostic and robustness checks"; not "field validation". |
| Residual attack-risk findings are not solely an artifact of one weighting. | `scripts/run_residual_attack_risk_sensitivity.py`, `experiments/results/residual_attack_risk_sensitivity_v29.csv` | Supported as diagnostic sensitivity check | Keep component metrics primary; do not call the aggregate a validated loss function. |

## Traceability Checklist for New Claims

Before adding a claim to the paper, identify:

1. the script that generated the evidence,
2. the exact result file,
3. the table or figure where it appears,
4. the limitation attached to the claim,
5. whether it is deterministic or provider-dependent.

Claims without this mapping should be softened or moved to future work.
