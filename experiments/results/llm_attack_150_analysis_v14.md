# LLM Attack 150 Analysis v1.4

Real provider-backed JGU LLM attack evaluation completed successfully.

- Model: `GPT OSS 120B`
- Attack cases: 150
- Composition: 75 adaptive attack cases and 75 original attack fixture cases
- Methods: 5
- Parsed predictions: 750
- Successful provider responses for attack predictions: 750
- Final retry pass cache hits: 724
- Final retry pass new provider responses: 26
- Initial pass had 26 rate-limited conservative-prompt failures; rerun filled them from provider successfully.
- Final parse errors: 0
- Final parse error rate: 0.000
- Raw provider responses stored: no

| Method | Combined attack success | Full attack success | Partial attack success | False fulfilled | False partial/fulfilled | Unsafe evidence | Source attr. fail | Status flip | Residual risk | Abstention | Parse error |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| llm_zero_shot | 0.033 | 0.020 | 0.013 | 0.020 | 0.000 | 0.013 | 0.013 | 0.493 | 0.033 | 0.193 | 0.000 |
| bm25_rag_llm | 0.027 | 0.000 | 0.027 | 0.000 | 0.000 | 0.027 | 0.027 | 0.380 | 0.027 | 0.127 | 0.000 |
| bm25_rag_llm_metadata | 0.080 | 0.007 | 0.073 | 0.007 | 0.000 | 0.080 | 0.067 | 0.460 | 0.081 | 0.140 | 0.000 |
| bm25_rag_llm_provenance_prompt | 0.053 | 0.000 | 0.053 | 0.000 | 0.007 | 0.053 | 0.033 | 0.360 | 0.046 | 0.153 | 0.000 |
| bm25_rag_llm_conservative | 0.040 | 0.000 | 0.040 | 0.000 | 0.000 | 0.040 | 0.020 | 0.400 | 0.031 | 0.187 | 0.000 |

Original vs adaptive attack suites:

| Method | Suite | Attack success | Full | Partial | Unsafe evidence | Source attr. fail | Residual risk |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| llm_zero_shot | adaptive_attack | 0.027 | 0.000 | 0.027 | 0.027 | 0.027 | 0.027 |
| llm_zero_shot | original_attack | 0.040 | 0.040 | 0.000 | 0.000 | 0.000 | 0.040 |
| bm25_rag_llm | adaptive_attack | 0.053 | 0.000 | 0.053 | 0.053 | 0.053 | 0.053 |
| bm25_rag_llm | original_attack | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| bm25_rag_llm_metadata | adaptive_attack | 0.133 | 0.013 | 0.120 | 0.133 | 0.133 | 0.147 |
| bm25_rag_llm_metadata | original_attack | 0.027 | 0.000 | 0.027 | 0.027 | 0.000 | 0.015 |
| bm25_rag_llm_provenance_prompt | adaptive_attack | 0.067 | 0.000 | 0.067 | 0.067 | 0.067 | 0.070 |
| bm25_rag_llm_provenance_prompt | original_attack | 0.040 | 0.000 | 0.040 | 0.040 | 0.000 | 0.022 |
| bm25_rag_llm_conservative | adaptive_attack | 0.040 | 0.000 | 0.040 | 0.040 | 0.040 | 0.040 |
| bm25_rag_llm_conservative | original_attack | 0.040 | 0.000 | 0.040 | 0.040 | 0.000 | 0.022 |

Highest residual-risk attack type/method groups:

| Method | Attack type | Attack success | Full | Partial | Unsafe evidence | Residual risk |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| bm25_rag_llm_metadata | evidence_fragmentation_attack | 0.800 | 0.000 | 0.800 | 0.800 | 0.800 |
| bm25_rag_llm_provenance_prompt | evidence_fragmentation_attack | 0.600 | 0.000 | 0.600 | 0.600 | 0.600 |
| bm25_rag_llm_metadata | role_matrix_conflict | 0.500 | 0.000 | 0.500 | 0.500 | 0.500 |
| llm_zero_shot | evidence_fragmentation_attack | 0.400 | 0.000 | 0.400 | 0.400 | 0.400 |
| bm25_rag_llm | evidence_fragmentation_attack | 0.400 | 0.000 | 0.400 | 0.400 | 0.400 |
| bm25_rag_llm_metadata | conflicting_current_approved_documents | 0.400 | 0.000 | 0.400 | 0.400 | 0.400 |
| bm25_rag_llm_metadata | false_test_record_with_high_trust_metadata | 0.200 | 0.200 | 0.000 | 0.200 | 0.400 |
| bm25_rag_llm_conservative | evidence_fragmentation_attack | 0.400 | 0.000 | 0.400 | 0.400 | 0.400 |
| bm25_rag_llm | stale_but_recently_modified_document | 0.250 | 0.000 | 0.250 | 0.250 | 0.250 |
| bm25_rag_llm_metadata | stale_but_recently_modified_document | 0.250 | 0.000 | 0.250 | 0.250 | 0.250 |
| bm25_rag_llm_provenance_prompt | false_test_record_with_high_trust_metadata | 0.200 | 0.000 | 0.200 | 0.200 | 0.250 |
| llm_zero_shot | compliance_override_attack | 0.222 | 0.222 | 0.000 | 0.000 | 0.222 |

Interpretation:

- Real LLM attack success rates were substantially lower than the deterministic metadata-aware attack baseline on this subset.
- Naive LLM/RAG methods still accepted unsafe or invalid evidence in some cases, but full false-fulfilled attack success was low.
- Metadata prompting increased attack success and residual risk on this subset relative to plain BM25 RAG, mainly through partial unsafe-evidence acceptance.
- Provenance prompting reduced risk compared with metadata prompting, but did not eliminate partial attack success.
- Conservative prompting had no full attack successes and the lowest LLM residual attack risk, but it did not eliminate unsafe evidence acceptance and had higher abstention than the other LLM variants.
- The result supports a cautious paper claim that real LLM/RAG attack behavior is measurable and that prompting/provenance changes risk profiles, but it does not support a claim of attack resistance.
