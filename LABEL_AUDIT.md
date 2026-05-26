# Label Audit

This document explains the project label semantics used in ISMS-Bench. It is a consistency aid, not evidence of completed expert adjudication.

## Label Definitions

- `fulfilled`: current, implementation-capable evidence supports all criteria required by the case.
- `partially_fulfilled`: at least one required criterion is supported, but one or more required criteria are missing, outdated, ambiguous, contradicted, or unsupported.
- `not_fulfilled`: the core required process/evidence is absent, contradicted, or supported only by non-implementation evidence.
- `unclear`: evidence is relevant but not strong enough for a fulfilled, partially fulfilled, or not fulfilled decision because it is vague, stale, draft-only, future-tense, source-confused, contradictory, or metadata-insufficient.

## Criteria-to-Label Mapping

The Incident Response criteria include:

- documented process,
- assigned roles,
- reporting channel,
- escalation procedure,
- supplier or third-party escalation,
- periodic test/tabletop exercise,
- post-incident review or lessons learned,
- evidence preservation,
- management approval or owner,
- version or review validity.

`fulfilled` requires all case-required criteria to be covered by sufficient implementation evidence. `partially_fulfilled` requires some but not all required criteria. `not_fulfilled` applies when the core process or implementation evidence is missing or contradicted. `unclear` applies when evidence exists but is not reliable or complete enough for a stronger status.

## Examples

- Fulfilled: an approved incident-response procedure, role matrix, reporting channel, recent tabletop record, supplier escalation clause, and lessons-learned evidence collectively cover the required criteria.
- Partially fulfilled: an approved policy defines reporting and roles, but no recent test record or supplier escalation evidence is present.
- Not fulfilled: only a copied requirement, blank template, or public guidance describes what should exist, with no organization-specific implementation evidence.
- Unclear: a draft policy or future-tense plan suggests intended controls, but approval, validity, or implementation evidence is missing.

## Evidence Handling Rules

- Draft evidence cannot by itself support `fulfilled`.
- Expired test records cannot count as recent testing evidence.
- Low-trust evidence cannot override a high-trust contradiction.
- Norm text, public guidance, templates, control catalogs, OSCAL/FedRAMP/BSI control text, and blank assessment templates are not organization implementation evidence unless a case explicitly asks for guidance-level context.
- Future-tense statements such as "will define" or "planned for" are not implementation evidence.
- Contradictions should lead to `unclear` or a lower status unless sufficient high-trust evidence resolves them.
- Public-document-derived cases use source-type taxonomy fields to separate implementation-capable organizational evidence from guidance/template/control-catalog context.

## Known Ambiguities

- Some public organizational policies are implementation-like but do not prove operation or testing. These cases may be `partially_fulfilled` or `unclear` depending on criteria coverage.
- Some public-template cases could be stricter as `not_fulfilled`; conservative `unclear` labels are acceptable when they avoid false compliance and evidence relevance is ambiguous.
- Metadata-spoofing cases are diagnostics; their labels remain fixed while metadata is perturbed to test method behavior.

## Audit Checks

Run:

```bash
python scripts/run_label_audit.py
```

The script checks valid labels, consistency between `expected_status` and `ground_truth_status`, evidence-ID existence, fulfilled/missing-evidence consistency, and pending review status for public-document-derived cases.

## Review Status

Labels are project-authored unless a completed external review sheet is present and documented. The current repository includes an expert-review protocol for future validation, but no completed independent expert annotations are reported in this submission.
