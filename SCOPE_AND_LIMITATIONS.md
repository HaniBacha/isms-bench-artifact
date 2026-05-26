# Scope and Limitations

## "The data are synthetic."

Response: Correct. The core benchmark is synthetic and project-generated to support controlled ground truth for false-compliance risk, provenance, metadata, mutation, and adversarial-document conditions. The paper does not claim real-world audit validation. Artifact evidence: `data/benchmark/`, `data/synthetic_cases/`, `scripts/generate_synthetic_cases.py`, `scripts/check_generator_coupling.py`.

## "Only Incident Response is covered."

Response: Correct. Incident Response is the first ISMS scope because it has concrete evidence types such as plans, roles, reporting channels, escalation paths, testing records, supplier escalation, and lessons learned. The artifact does not claim full ISO 27001 or all-domain ISMS coverage. Future work should add asset management, access control, supplier management, business continuity, and risk management.

## "Only one LLM is evaluated."

Response: Correct for stable real results. The reported LLM/RAG evidence uses `gpt-oss-120b` subset runs. The code supports OpenAI-compatible endpoints and dry-run mode, but the paper should frame LLM/RAG evidence as a subset diagnostic, not a broad model comparison. Artifact evidence: `src/kisec/llm/`, `scripts/run_llm_baselines_v13.py`, `experiments/results/llm_medium_150_summary_v14.csv`, `experiments/results/llm_attack_150_summary_v14.csv`.

## "The methods are mostly rule-based."

Response: Correct. The deterministic methods are policy probes, not claims of algorithmic novelty. Their purpose is to isolate metadata, provenance, source-type, and conservative decision-policy effects under controlled conditions. This is appropriate for a benchmark paper focused on risk characterization.

## "There is no real audit validation."

Response: Correct. The repository contains no confidential real audit outcomes and should not claim deployment validity. The public-document-derived split uses real public documents but project-initial labels. External expert review is documented as a protocol unless completed annotations are present.

## "There is no expert validation."

Response: Correct. The paper does not claim completed expert validation. It contributes a controlled diagnostic benchmark for studying false-compliance risk under reproducible conditions. To mitigate internal-validity and generator-coupling concerns, the artifact includes heldout templates, an independent challenge set, an alternative generator, fixed manual cases, public-document-derived diagnostics, mutation tests, metadata-spoofing diagnostics, leakage checks, adversarial fixtures, and residual-risk sensitivity checks. The artifact includes `external_validation_protocol/` for future expert review, but no completed expert annotations are reported.

## "The paper says independent cases exist, but also says independent cases are future work."

Response: The terms refer to different levels of independence. The current artifact includes project-authored independent challenge cases outside the main generator path, a separate alternative-generator path, and fixed manual cases. Externally authored, expert-adjudicated, or real audit cases remain future work. The paper should describe the current cases as diagnostic checks that reduce generator-coupling concerns, not as completed external validation.

## "The benchmark may be generator-coupled."

Response: This risk remains. The repository mitigates it through heldout splits, alternative generator checks, mutation/paraphrase/manual challenge surfaces, coupling checks, and public-document diagnostics. These reduce but do not eliminate generator-dependence concerns. Artifact evidence: `scripts/check_generator_coupling.py`, `data/benchmark/manual_challenge_cases_v09.jsonl`, `data/benchmark/public_external_validation_cases_v18c.jsonl`.

## "Residual attack risk is heuristic."

Response: Correct. Residual attack risk is a diagnostic severity-weighted aggregate. The paper reports component rates separately and documents the weighting. Reviewers should inspect full attack success, partial success, unsafe evidence acceptance, and source-attribution failure alongside the aggregate.

## "Why is this security and not just compliance NLP?"

Response: The security failure is accepting invalid, low-trust, outdated, draft, normative, or attacker-injected material as evidence that a missing control is implemented. In Incident Response, that can hide unresolved response gaps. The benchmark measures false fulfilled decisions, unsafe evidence acceptance, source-attribution failure, and residual attack risk rather than only semantic classification accuracy.

## "Public-document split is not independent validation."

Response: Correct. It is diagnostic stress evidence only. It uses real public documents and separates implementation-capable organizational evidence from guidance/template/control-catalog context, but labels remain project-initial and external review is pending.

## "Why include trivial constant baselines?"

Response: They bound false-compliance behavior and make the utility trade-off explicit. Always-unclear and always-not-fulfilled can drive false compliance down but have poor triage utility. They are useful sanity baselines, not useful systems.
