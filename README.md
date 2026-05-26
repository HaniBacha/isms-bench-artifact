# KI-SEC Assist / ISMS-Bench

This repository contains the research artifact for an ACSAC 2026 submission on false compliance in AI-assisted ISMS Incident Response pre-assessment.

The narrow claim is:

> False compliance is a measurable security risk in AI-assisted ISMS Incident Response pre-assessment, and provenance-aware assessment reduces false-fulfilled decisions under controlled benchmark conditions.

The artifact does not certify compliance, replace auditors, or validate deployment performance on confidential real-world audits.

## What Is Included

- Deterministic synthetic Incident Response benchmark generation.
- Evidence passages, benchmark cases, mutation cases, paraphrase/multilingual stress cases, manual challenge cases, public-document-derived diagnostic stress cases, and adversarial fixtures.
- Retrieval and assessment baselines: BM25, TF-IDF, metadata-aware rules, provenance-balanced, provenance-conservative, provenance-conservative with source guard, and trivial constant-status baselines for bounding false-compliance trade-offs.
- Modular LLM/RAG baseline runner for OpenAI-compatible endpoints, with dry-run/mock mode and parsed prediction outputs.
- Evaluation scripts for retrieval, compliance classification, attacks, public-document diagnostics, metadata spoofing, bootstrap intervals, and table/figure generation.
- Generated tables/figures, claim-evidence matrix, benchmark card, and reproducibility notes.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest
python scripts/check_label_leakage.py
python scripts/check_generator_coupling.py
python scripts/run_label_audit.py
python scripts/make_tables.py --version v04
```

If `rank_bm25` is unavailable, the BM25 retriever falls back to a deterministic local implementation.

## Reproduce Main Deterministic Results

```bash
python scripts/build_corpus.py
python scripts/generate_synthetic_cases.py --version v03 --split development_template --seed 42
python scripts/generate_synthetic_cases.py --version v03 --split heldout_template --seed 42
python scripts/generate_synthetic_cases.py --version v03 --split stress_test --seed 42
python scripts/generate_mutation_cases.py --seed 42
python scripts/generate_paraphrase_stress_v04.py --seed 42
python scripts/run_retrieval_eval.py --method bm25 --k 5 --version v04
python scripts/run_compliance_eval.py --method bm25 --k 5 --version v04
python scripts/run_attack_eval.py --method bm25 --k 5 --version v04
python scripts/make_tables.py --version v04
```

## LLM/RAG Baselines

Real LLM/RAG runs require an OpenAI-compatible endpoint and local environment variables. No API keys are included in this repository.

```bash
JGU_API_BASE="https://your-openai-compatible-endpoint.example/v1" JGU_MODEL="gpt-oss-120b" python scripts/run_llm_baselines_v13.py --seed 42 --max-cases 150 --real-api --output-stem llm_medium_150_v14
python scripts/run_llm_baselines_v13.py --seed 42 --max-cases 5 --dry-run --output-stem llm_mock_smoke
```

The paper reports one real model family (`gpt-oss-120b`) on subset evaluations. These results are model-specific diagnostics, not a broad model comparison.

## Repository Layout

```text
src/kisec/             Package code for data models, generation, retrieval, assessment, attacks, metrics, and LLM/RAG utilities
scripts/               Reproducibility entry points
tests/                 Fast pytest suite and leakage/coupling checks
data/benchmark/        Synthetic, manual, LLM subset, and public-document-derived benchmark files
data/attacks/          Original and advanced static adversarial cases
data/external_public/  Public source inventory and short paraphrase/excerpt evidence corpus
data/synthetic_cases/  Synthetic evidence passages
experiments/results/   Result CSV/JSON/MD files used by submitted-paper tables and figures
artifact_outputs/      Generated tables and figures for traceability
```

## Important Scope Notes

- Most benchmark labels are synthetic or project-authored.
- The public-document-derived split uses real public Incident Response documents, but its labels remain project-initial and have not been independently reviewed; it is diagnostic stress evidence, not independent validation.
- The benchmark currently covers Incident Response, not the full ISMS control space.
- LLM/RAG evidence uses one available model family and subset runs.
- Human/expert validation is documented as a protocol unless completed annotations are present.

See `ARTIFACT.md`, `REPRODUCIBILITY.md`, `BENCHMARK_CARD.md`, `CLAIMS_AND_EVIDENCE.md`, and `SCOPE_AND_LIMITATIONS.md` for reviewer-facing details.

Useful Make targets:

```bash
make artifact-check
make eval-small
make sensitivity
```
