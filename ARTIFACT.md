# ACSAC Artifact Guide

This artifact supports the paper "False Compliance in AI-Assisted Incident Response Pre-Assessment: Evidence Grounding, Provenance, and Adversarial Documents."

## Artifact Contents

- `src/kisec/`: implementation of benchmark data models, synthetic generation, retrieval, compliance assessment, provenance policies, attack generation, metrics, and LLM/RAG utilities.
- `scripts/`: command-line entry points for benchmark generation, evaluation, leakage/coupling checks, LLM/RAG runs, public-document diagnostics, and table/figure generation.
- `data/benchmark/`: benchmark cases, mutation/paraphrase/manual/public diagnostic cases, and LLM subsets.
- `data/attacks/`: original and advanced static adversarial cases.
- `data/external_public/`: source inventory and short public-document evidence paraphrases/excerpts.
- `experiments/results/`: aggregate outputs and parsed predictions used by submitted-paper tables and figures.
- `artifact_outputs/`: generated tables and figures for traceability.

## What Is Synthetic

The core benchmark, stress cases, mutation cases, paraphrase/multilingual cases, original attack fixtures, and advanced static adversarial fixtures are project-generated. They are designed to test controlled evidence-grounding and provenance conditions. They are not real audit outcomes.

## What Is Public-Document-Derived

The public-document-derived split uses real public Incident Response plans, policies, templates, and guidance documents as source material. The repository stores URLs, section references, short paraphrases, and short excerpts only. Labels remain `project_initial` unless an external reviewer completes the review sheet. This split is diagnostic stress evidence, not independent external validation.

## What Is LLM-Dependent

The deterministic benchmark generation, retrieval, rule/provenance evaluation, attack evaluation, and table generation do not require a paid API. Real LLM/RAG results require an OpenAI-compatible endpoint and local credentials. The repository includes parsed predictions and aggregate metrics for reported real runs, but no API keys and no raw provider responses.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Core Checks

```bash
python -m pytest
python scripts/check_label_leakage.py
python scripts/check_generator_coupling.py
python scripts/run_label_audit.py
```

## Label and Risk Sensitivity Audits

```bash
python scripts/run_label_audit.py
python scripts/run_residual_attack_risk_sensitivity.py
```

The label audit checks structural consistency and evidence-ID references. It is not expert adjudication. The residual-risk sensitivity script recomputes the diagnostic aggregate under alternative weights using existing component metrics.

## Regenerate Deterministic Tables and Figures

```bash
python scripts/make_tables.py --version v04
```

The generated files are written under `artifact_outputs/tables/` and `artifact_outputs/figures/`.

## Run Deterministic Evaluation

```bash
python scripts/build_corpus.py
python scripts/run_retrieval_eval.py --method bm25 --k 5 --version v04
python scripts/run_compliance_eval.py --method bm25 --k 5 --version v04
python scripts/run_attack_eval.py --method bm25 --k 5 --version v04
```

## Run LLM/RAG Baselines

Real provider-backed runs require local environment variables such as `JGU_API_KEY`, `JGU_API_BASE`, and `JGU_MODEL`, or compatible aliases supported by `src/kisec/llm/jgu_client.py`.

```bash
python scripts/check_llm_env_v14.py
python scripts/run_llm_baselines_v13.py --seed 42 --max-cases 5 --real-api --output-stem llm_smoke_local
```

Dry-run/mock mode can be used for parser and pipeline tests, but mock results must not be reported as empirical LLM performance.

## Exclusions

Do not include `.env`, API keys, raw provider responses, raw LLM caches/logs, private local literature folders, confidential documents, manuscript source/PDF files, or local absolute paths in any submitted artifact.
