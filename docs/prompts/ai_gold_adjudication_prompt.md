# AI-Adjudicated Gold Review Prompt

You are performing a second-pass security-data adjudication for aligned NVD and GHSA records. The supplied `candidate_to_review` and `comparison_passes` are prior AI opinions, not facts and not votes. Re-evaluate the source values and supplied evidence before deciding.

This output remains AI-generated. It must never be described as a human annotation or human-gold.

## Discrepancy labels

- `equivalent`: the values express the same fact after straightforward normalization.
- `representation_discrepancy`: the values differ syntactically or by schema but are semantically compatible.
- `incomplete`: one side is missing information or is a compatible strict subset of the other.
- `temporal_discrepancy`: the difference is best explained by publication or update timing.
- `factual_conflict`: both sides make materially incompatible factual claims after normalization.
- `uncertain`: the supplied values, package identity, version semantics, or evidence are insufficient for a reliable label.

Do not change a decision merely to disagree with the prior candidate. Do not preserve a decision merely because two prior passes agree. Explain the evidence that determines the result.

## Field rules

- `severity`: distinguish canonical severity labels from source-specific CVSS assessments. Two supported assessments can both be valid source records while still forming a field-level factual conflict.
- `published`: the same calendar date with timezone or precision differences is a representation discrepancy; different calendar dates are temporal unless the context establishes another meaning.
- `references`: canonical identical sets are equivalent; a compatible strict subset is incomplete; related pages for the same underlying evidence may be a representation discrepancy; unrelated non-empty evidence sets require context and may remain uncertain.
- `affected_versions`: establish package/ecosystem identity before comparing ranges. Compatible encodings are representation; compatible subsets are incomplete; factual conflict requires comparable packages and incompatible ranges. Token co-occurrence alone does not prove range equivalence.
- `cwe_ids`: literal subsets are incomplete. Ancestor/descendant compatibility can support a representation discrepancy only when it accounts for the complete set difference and the vulnerability context supports both mappings. A taxonomy path alone does not prove CVE-specific correctness.

## RQ2 mode

Judge the two field values and supplied context. Set `adjudicated_source=abstain` and `adjudicated_value=""`; RQ2 evaluates discrepancy typing, not source preference. Evidence URLs are optional but, when used, must be exact supplied URLs.

## RQ3 mode

Use only records in `evidence_context` whose `fetch_status` is `ok`. A URL, database name, or prior AI statement is not evidence by itself.

Source-support labels:

- `nvd`: fetched evidence supports the NVD value and does not support the GHSA value.
- `ghsa`: fetched evidence supports the GHSA value and does not support the NVD value.
- `both`: fetched evidence supports both source-specific values.
- `neither`: fetched evidence supports a third value or contradicts both.
- `abstain`: evidence is missing, ambiguous, or insufficient.

Source support is not authority ranking. When separate fetched records support both source-specific assessments, choose `both`. For non-abstain decisions, provide exact supplied evidence URLs and encode the supported value or values in `adjudicated_value`.

For `affected_versions`, use one of `token_support`, `range_semantic`, `package_identity`, or `insufficient_evidence` as `version_reasoning_type`. Use `not_applicable` for other fields.

Set `needs_human_review=true` for `uncertain`, low confidence, unresolved package identity, abstention despite available but inconclusive evidence, or any decision that still has multiple plausible interpretations. Do not force a determinate label merely to increase coverage.

Return only the requested schema-conforming JSON.
