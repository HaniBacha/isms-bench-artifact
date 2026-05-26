# LLM Medium 150 Analysis v1.4

Real provider-backed JGU LLM baseline completed successfully.

- Model: `GPT OSS 120B`
- Cases: 150
- Methods: 5
- Parsed predictions: 750
- Provider requests: 525
- Cache hits: 225
- Parse errors: 0
- Parse error rate: 0.000
- Raw provider responses stored: no
- Attack rows included: no

| Method | Macro-F1 | False compliance | Abstention | Residual risk | Unsafe evidence | Source attr. fail | Parse error |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| llm_zero_shot | 0.566 | 0.107 | 0.153 | 0.058 | 0.000 | 0.040 | 0.000 |
| bm25_rag_llm | 0.497 | 0.107 | 0.233 | 0.049 | 0.000 | 0.093 | 0.000 |
| bm25_rag_llm_metadata | 0.540 | 0.067 | 0.220 | 0.093 | 0.000 | 0.207 | 0.000 |
| bm25_rag_llm_provenance_prompt | 0.636 | 0.020 | 0.173 | 0.088 | 0.007 | 0.187 | 0.000 |
| bm25_rag_llm_conservative | 0.549 | 0.047 | 0.167 | 0.081 | 0.000 | 0.180 | 0.000 |

Interpretation:

- Naive LLM baselines produced false compliance: zero-shot and BM25 RAG were both 0.107.
- Metadata prompting reduced false compliance to 0.067.
- Provenance prompting produced the best LLM Macro-F1 (0.636) and lowest LLM false-compliance rate (0.020).
- Conservative prompting improved false compliance over naive LLM baselines (0.047) but did not beat the provenance prompt on this subset.
- Residual risk did not monotonically improve with richer prompting because source-attribution warnings increased for metadata/provenance prompts.
- The 150-case prefix still did not include attack cases, so attack success cannot be reported from this run.

Recommendation:

The result is strong enough to support a compact LLM/RAG baseline discussion after an attack-specific LLM run is added or after a subset selection is changed to include attacks. The safest paper wording is that real LLM/RAG baselines exhibit false-compliance failures, and that provenance prompting reduced false compliance on the 150-case non-attack subset. Do not claim that conservative LLM prompting dominates.
