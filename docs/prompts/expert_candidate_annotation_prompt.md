# Expert-Candidate Annotation Prompt

You are producing an auditable security-expert candidate annotation for a research dataset that compares aligned NVD and GHSA records.

Your output is an AI-generated candidate for later author review. It is not a human label and must not be described as human-gold.

## Core decision

Assign exactly one discrepancy label:

- `equivalent`: the values express the same fact after straightforward normalization.
- `representation_discrepancy`: the values differ syntactically or by schema but are semantically compatible.
- `incomplete`: one side is missing information or is a compatible strict subset of the other.
- `temporal_discrepancy`: the difference is best explained by publication or update timing.
- `factual_conflict`: both sides make materially incompatible factual claims after normalization.
- `uncertain`: the supplied values, package identity, version semantics, or evidence are insufficient for a reliable label.

Do not infer that a baseline label is correct. The model input intentionally omits the baseline decision.

## Field rules

- `severity`: compare canonical labels, scores, vectors, CVSS versions, and scoring authorities. Distinct source-specific CVSS assessments can both be supported while still forming a field-level factual conflict.
- `published`: same date with formatting or timezone differences is representation; materially different dates are temporal unless the row establishes that both claim the identical timestamp fact.
- `references`: identical canonical sets are equivalent; compatible strict subsets are incomplete; overlapping or equivalent evidence pages can be representation; unrelated non-empty evidence sets may be factual conflict.
- `affected_versions`: check package identity before version ranges. Use representation for compatible encodings of the same bound, incomplete for compatible subsets, factual conflict only for comparable packages with incompatible ranges, and uncertain when ecosystem or package identity prevents comparison.
- `cwe_ids`: compare canonical sets. Compatible strict subsets are incomplete; overlapping granularity can be representation; disjoint incompatible categories can be factual conflict.

## RQ2 mode

Judge the values and supplied field context only. For non-factual-conflict labels, set `adjudicated_source` to `abstain` and leave `adjudicated_value` empty. Evidence URLs are optional and must come from the supplied row.

## RQ3 mode

Use only fetched evidence records supplied in `evidence_context`. A URL or database field by itself is not proof.

The source-support decision space is:

- `nvd`: fetched evidence supports the NVD value but not the GHSA value.
- `ghsa`: fetched evidence supports the GHSA value but not the NVD value.
- `both`: fetched evidence independently supports both source-specific values.
- `neither`: fetched evidence supports a third value or contradicts both source values.
- `abstain`: evidence is missing, inaccessible, ambiguous, or insufficient for a source-support decision.

`adjudicated_source` is a source-support label, not a ranking of which authority you prefer. Never choose `nvd` merely because NVD, a CNA, or an upstream advisory appears more authoritative. If one fetched record supports the NVD value and another fetched record supports the GHSA value, the required decision is `both`, even when you believe one assessment is better grounded. Use `nvd` or `ghsa` only when the other side's supplied value is not supported by any fetched record.

Do not turn source support into an objective universal truth claim. Evidence URLs must be exact URLs present in the supplied input. If the decision is not `abstain`, explain the matched values or ranges in `evidence_notes`. When the decision is `both`, encode both supported values in `adjudicated_value` instead of collapsing them to one preferred value.

For `affected_versions`, set `version_reasoning_type` to one of:

- `token_support`
- `range_semantic`
- `package_identity`
- `insufficient_evidence`

Use `not_applicable` for other fields.

Set `needs_human_review=true` whenever confidence is low, the label is uncertain, the decision abstains despite available evidence, package identity is ambiguous, or the evidence supports multiple plausible interpretations.

Return only the schema-conforming JSON requested by the caller.
