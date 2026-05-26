# ISMS-Bench Benchmark Card

## Intended Use

ISMS-Bench is intended for research on false-compliance risk in AI-assisted Information Security Management System (ISMS) Incident Response pre-assessment. It evaluates whether systems can assign evidence-grounded labels from document bundles without accepting invalid, outdated, draft, normative, low-trust, or adversarial evidence as implementation proof.

## Not Intended Use

ISMS-Bench must not be used to certify compliance, replace auditors, validate production audit systems, or estimate real-world organizational compliance rates.

## Label Space

- `fulfilled`: evidence supports all required criteria.
- `partially_fulfilled`: evidence supports some but not all required criteria.
- `not_fulfilled`: core required evidence is missing or contradicted.
- `unclear`: evidence is insufficient, ambiguous, stale, draft-only, source-confused, or not reliable enough for a stronger decision.

## Data Surfaces

- Synthetic core benchmark: project-generated Incident Response cases.
- Heldout/stress/mutation/paraphrase splits: controlled variants for template and evidence-condition robustness.
- Manual challenge set: project-authored fixed challenge cases.
- Public-template and public-document-derived diagnostics: real public source URLs, short paraphrases/excerpts, and project-initial labels.
- Attack suites: original and advanced static adversarial documents, prompt-injection-like notes, poisoned evidence, source-confusion fixtures, and low-trust contradictions.

## Public-Document Diagnostic Status

The public-document-derived split uses real public Incident Response plans, policies, templates, and guidance documents. Its labels remain `project_initial` and have not been independently reviewed. It reduces document-generation dependence but not label-author dependence.

## Evaluation Metrics

Primary risk metrics:

- false compliance rate,
- false fulfilled decisions,
- unsafe evidence acceptance,
- source-attribution failure,
- residual attack risk,
- abstention rate.

Utility/context metrics:

- Macro-F1,
- per-class F1,
- Evidence-F1,
- retrieval Recall@5 / Precision@k / nDCG.

Residual attack risk is a diagnostic severity-weighted aggregate. Component rates should be inspected alongside the aggregate.

## Known Limitations

- Synthetic/project-authored data dominate the current benchmark.
- Incident Response is the only ISMS domain covered.
- Public-document labels do not have completed independent expert review.
- An expert-review protocol is included, but completed independent expert annotations are not reported in this submission.
- LLM/RAG evidence uses one stable model family in reported subset runs.
- Attacks are static fixtures rather than interactive adaptive red-team loops.
- Metadata spoofing is a small diagnostic, not a complete ingestion-security evaluation.

## Recommended Reporting Language

Use:

> ISMS-Bench is a reproducible diagnostic benchmark for false-compliance risk in AI-assisted ISMS Incident Response pre-assessment.

Avoid:

> ISMS-Bench validates AI compliance automation for real audits.
