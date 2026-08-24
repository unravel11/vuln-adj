# Affected-Versions Holdout Adjudication Contract

You are reviewing a frozen, development-disjoint affected_versions holdout.
You are a Codex reviewer, not a human annotator. Every output row must set
`label_is_human=false`.

## Isolation

- Read only the assigned frozen evidence JSONL and this contract.
- Do not read the old 100-row Phase D sample, AI-gold files, method predictions,
  another reviewer's output, or result metrics.
- Do not call an external LLM or fetch new evidence. Use only structured source
  values and records already present in `evidence_context`.
- A failed fetch, missing page, absent snippet, or missing mention is not
  contradiction.

## Decisions

Decide both:

1. `discrepancy_label`: `equivalent`, `representation_discrepancy`,
   `incomplete`, `temporal_discrepancy`, `factual_conflict`, or `uncertain`.
2. `reviewed_source`: `nvd`, `ghsa`, `both`, `neither`, or `abstain`.

First establish whether NVD product/CPE and GHSA ecosystem/package describe the
same artifact. Never compare version ranges merely because they share a CVE,
repository, vendor, or advisory. Then interpret boundaries within each package's
own version ordering. Do not infer causality or authority from publication date
alone.

A one-sided source requires positive support for that source and explicit
contradiction or scope exclusion for the other source. `both` requires positive
support for both source values. `neither` requires a supported third value or
explicit contradiction of both. Otherwise use `abstain`.

Use only URLs whose evidence record has `fetch_status=ok` and non-empty
`text_snippet`. Put URLs into exactly these maps:

```json
{"nvd": [], "ghsa": [], "third": []}
```

Set `adjudication_status=abstain` whenever the discrepancy is `uncertain`, the
source is `abstain`, or confidence is `low`; otherwise set it to `determinate`.

## Output schema

Write exactly one JSON object per input row with exactly these keys:

```text
sample_id, cve_id, field, discrepancy_label, reviewed_source,
adjudication_status, confidence, positive_support,
contradiction_or_scope_exclusion, artifact_assessment, range_assessment,
rationale, unresolved, label_is_human
```

`field` must be `affected_versions`. `confidence` is `high`, `medium`, or `low`.
All assessment/rationale fields are strings. Preserve input order and cover every
input row exactly once.
