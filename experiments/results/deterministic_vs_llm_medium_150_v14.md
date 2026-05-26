# Deterministic vs LLM Medium 150 v1.4

- Real API available: yes
- Model: `GPT OSS 120B`
- LLM cases: 150
- LLM methods: 5
- Provider requests: 525
- Cache hits: 225
- Parse error rate: 0.000
- Attack rows included: no

| Method | Macro-F1 | False compliance | Abstention | Residual risk | Unsafe evidence | Source attr. fail | Parse error |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| metadata_aware_deterministic | 0.639 | 0.153 | 0.203 | 0.414 | 0.347 | 0.327 | n/a |
| provenance_balanced_deterministic | 0.543 | 0.113 | 0.170 | 0.030 | 0.000 | 0.000 | n/a |
| provenance_conservative_deterministic | 0.512 | 0.030 | 0.383 | 0.000 | 0.000 | 0.000 | n/a |
| llm_zero_shot | 0.566 | 0.107 | 0.153 | 0.058 | 0.000 | 0.040 | 0.000 |
| bm25_rag_llm | 0.497 | 0.107 | 0.233 | 0.049 | 0.000 | 0.093 | 0.000 |
| bm25_rag_llm_metadata | 0.540 | 0.067 | 0.220 | 0.093 | 0.000 | 0.207 | 0.000 |
| bm25_rag_llm_provenance_prompt | 0.636 | 0.020 | 0.173 | 0.088 | 0.007 | 0.187 | 0.000 |
| bm25_rag_llm_conservative | 0.549 | 0.047 | 0.167 | 0.081 | 0.000 | 0.180 | 0.000 |

Key comparison:

- Deterministic provenance-conservative remains the lowest-risk comparison point for residual risk (0.000) and false compliance (0.030), but has high abstention (0.383).
- Real `bm25_rag_llm_provenance_prompt` has the highest Macro-F1 in this comparison (0.636) and the lowest LLM false-compliance rate (0.020).
- Real naive LLM/RAG methods show nontrivial false compliance (0.107), directly supporting the ACSAC motivation.
- LLM conservative prompting did not dominate: false compliance was 0.047 and residual risk 0.081.
- Because no attack cases are included, this comparison should not be used for attack-risk claims.
