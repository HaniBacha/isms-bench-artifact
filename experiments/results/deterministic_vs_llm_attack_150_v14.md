# Deterministic vs LLM Attack 150 v1.4

- Real API available: yes
- Model: `GPT OSS 120B`
- Attack cases: 150
- Attack composition: 75 adaptive, 75 original
- LLM methods: 5
- Final parse error rate: 0.000
- Raw provider responses stored: no

| Method | Combined attack success | Full attack success | Partial attack success | False fulfilled | False partial/fulfilled | Unsafe evidence | Source attr. fail | Status flip | Residual risk | Abstention | Parse error |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| metadata_aware_deterministic | 0.740 | 0.147 | 0.593 | 0.147 | 0.033 | 0.640 | 0.553 | 0.487 | 0.756 | 0.167 | n/a |
| provenance_balanced_deterministic | 0.353 | 0.007 | 0.347 | 0.007 | 0.013 | 0.353 | 0.293 | 0.513 | 0.336 | 0.140 | n/a |
| provenance_conservative_deterministic | 0.353 | 0.000 | 0.353 | 0.000 | 0.007 | 0.353 | 0.293 | 0.467 | 0.328 | 0.253 | n/a |
| llm_zero_shot | 0.033 | 0.020 | 0.013 | 0.020 | 0.000 | 0.013 | 0.013 | 0.493 | 0.033 | 0.193 | 0.000 |
| bm25_rag_llm | 0.027 | 0.000 | 0.027 | 0.000 | 0.000 | 0.027 | 0.027 | 0.380 | 0.027 | 0.127 | 0.000 |
| bm25_rag_llm_metadata | 0.080 | 0.007 | 0.073 | 0.007 | 0.000 | 0.080 | 0.067 | 0.460 | 0.081 | 0.140 | 0.000 |
| bm25_rag_llm_provenance_prompt | 0.053 | 0.000 | 0.053 | 0.000 | 0.007 | 0.053 | 0.033 | 0.360 | 0.046 | 0.153 | 0.000 |
| bm25_rag_llm_conservative | 0.040 | 0.000 | 0.040 | 0.000 | 0.000 | 0.040 | 0.020 | 0.400 | 0.031 | 0.187 | 0.000 |

Key comparison:

- Deterministic metadata-aware is highly vulnerable on this attack subset: attack success 0.740 and residual risk 0.756.
- Deterministic provenance variants reduce deterministic attack risk but still show substantial partial attack success around 0.353.
- Real LLM/RAG variants show much lower attack success on this subset, with the lowest combined attack success for plain BM25 RAG (0.027) and low residual risk for conservative prompting (0.031).
- Metadata prompting is not a monotonic defense: its LLM attack success is 0.080, higher than plain BM25 RAG.
- Provenance and conservative prompting eliminate full attack success in this run, but partial unsafe-evidence acceptance remains.
- These results strengthen the adversarial-document evaluation story, but should be described cautiously because the attack subset is synthetic/project-authored and uses one model.
