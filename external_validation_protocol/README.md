# External Validation Protocol

This folder contains a protocol for future expert review of ISMS-Bench cases. It is a protocol only unless completed expert annotations are added to the repository.

## Goal

Assess whether ISMS or audit experts agree with the project-initial labels and evidence sufficiency decisions for a small sample of benchmark cases.

## Proposed Sample

- 30 to 50 cases.
- Include a balanced mix of:
  - fulfilled,
  - partially fulfilled,
  - not fulfilled,
  - unclear.
- Include both synthetic controlled cases and public-document-derived diagnostic cases.
- Prioritize false-compliance-sensitive cases and high-priority public-document cases.

## Expert Profile

Target reviewers:

- ISMS auditors,
- ISO 27001 consultants,
- incident-response managers,
- security governance / GRC practitioners,
- KMU/SME cybersecurity practitioners with incident-response responsibility.

## Annotation Task

For each case, the reviewer sees:

- requirement text,
- evidence IDs,
- short evidence passages or paraphrases,
- source type and metadata,
- project-initial expected status,
- project-initial accepted and rejected evidence IDs.

The reviewer marks:

- whether the expected status is correct,
- corrected status if needed,
- evidence IDs sufficient for the corrected status,
- evidence IDs that should be rejected,
- rationale,
- uncertainty,
- confidentiality/copyright concerns.

## Label Definitions

- `fulfilled`: evidence clearly supports all required criteria.
- `partially_fulfilled`: evidence supports some required criteria but at least one required criterion is missing or insufficient.
- `not_fulfilled`: the core process/evidence is absent or contradicted.
- `unclear`: evidence is ambiguous, stale, draft-only, template/guidance-only, source-confused, or insufficient to justify a stronger label.

## Inter-Annotator Agreement Plan

If two or more experts annotate the same cases:

1. Report raw agreement on `expected_status`.
2. Report Cohen's kappa for two annotators or Fleiss' kappa for three or more.
3. Separately report agreement on evidence sufficiency.
4. Resolve disagreements through adjudication notes.
5. Keep original project-initial labels and expert labels versioned separately.

## Data Protection

- Do not collect confidential customer or audit data.
- Use only artifact cases or public-document-derived cases with URLs and short excerpts/paraphrases.
- Do not ask reviewers to upload proprietary documents.
- Store reviewer names separately from annotations if anonymity is required.
- Remove free-text comments that reveal confidential organizations before public release.

## Recruitment Plan

Recruit 3 to 5 reviewers through professional ISMS, GRC, incident-response, or KMU cybersecurity networks. Record reviewer role category and years of relevant experience, but avoid collecting unnecessary personal data.

## Reporting Rule

Until completed review sheets are present, the paper and artifact must say:

> Expert validation is planned using the protocol in `external_validation_protocol/`; no completed independent expert labels are included in this artifact.
