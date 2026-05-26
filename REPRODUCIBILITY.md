# Reproducibility Guide

## Environment

The artifact is Python-based and tested with Python 3.12. It should work with Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Fast Verification

```bash
python -m pytest
python scripts/check_label_leakage.py
python scripts/check_generator_coupling.py
python scripts/run_label_audit.py
```

Expected result in the current repository state: all tests pass, and both leakage/coupling checks report `passed: True`.

## Deterministic Benchmark Generation

The core synthetic benchmark is generated with deterministic seeds.

```bash
python scripts/build_corpus.py
python scripts/generate_synthetic_cases.py --version v03 --split development_template --seed 42
python scripts/generate_synthetic_cases.py --version v03 --split heldout_template --seed 42
python scripts/generate_synthetic_cases.py --version v03 --split stress_test --seed 42
python scripts/generate_mutation_cases.py --seed 42
python scripts/generate_paraphrase_stress_v04.py --seed 42
```

These commands regenerate synthetic and controlled stress data. They do not produce real audit data.

## Deterministic Evaluation

```bash
python scripts/run_retrieval_eval.py --method bm25 --k 5 --version v04
python scripts/run_compliance_eval.py --method bm25 --k 5 --version v04
python scripts/run_attack_eval.py --method bm25 --k 5 --version v04
python scripts/run_bootstrap_ci.py
python scripts/run_ablation.py
```

The compliance evaluator includes the main deterministic methods and trivial constant-status baselines for future trade-off checks. The submitted-paper tables are based on the reported result files, not on uncomputed assumed rows.

## Residual Attack-Risk Sensitivity

```bash
python scripts/run_residual_attack_risk_sensitivity.py
```

This recomputes residual attack risk from existing component metrics under alternative weight settings. It does not add new predictions.

## Public-Document Diagnostic Split

```bash
python scripts/build_public_external_validation_v18c.py
python scripts/run_public_external_validation_eval_v18c.py
```

The public-document-derived split is a diagnostic stress split from public Incident Response documents. Labels are project-initial and external review is pending. Do not interpret these results as real-world audit validation.

## LLM/RAG Evaluation

The LLM/RAG pipeline is provider-agnostic for OpenAI-compatible chat endpoints. It supports configured real API runs and dry-run/mock runs.

Documented implementation files:

- `src/kisec/llm/jgu_client.py`: provider-compatible client and environment loading.
- `src/kisec/llm/prompts.py`: system prompt, user templates, provenance/conservative prompt additions, JSON schema instructions.
- `src/kisec/llm/parsing.py`: strict JSON parsing, repair attempt, and fallback to `unclear`.
- `scripts/run_llm_baselines_v13.py`: subset runner.

Real API smoke test:

```bash
python scripts/check_llm_env_v14.py
python scripts/run_llm_baselines_v13.py --seed 42 --max-cases 5 --real-api --output-stem llm_smoke_local
```

Dry-run parser/pipeline check:

```bash
python scripts/run_llm_baselines_v13.py --seed 42 --max-cases 5 --dry-run --output-stem llm_mock_smoke
```

Mock/dry-run outputs are not empirical model results.

## Table and Figure Generation

```bash
python scripts/make_tables.py --version v04
```

## Deterministic Versus Provider-Dependent Results

Deterministic:

- synthetic benchmark generation,
- retrieval metrics,
- rule/provenance baselines,
- attack fixtures and attack evaluation,
- public-document diagnostic deterministic methods,
- table/figure generation from existing result files.

Provider-dependent:

- real LLM/RAG predictions,
- token usage,
- provider parse/error behavior,
- results for any new model or endpoint.

## Non-Claims

The artifact does not provide:

- certification decisions,
- replacement for auditors,
- deployment validation,
- confidential real audit evidence,
- completed independent expert labels for the public-document split,
- broad claims across all LLMs.
