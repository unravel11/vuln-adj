# RQ2 CWE Taxonomy Evidence-Enhanced Secondary Review

You are independently reviewing nine high-priority CWE-set discrepancies
between NVD and GHSA. The blind JSONL input contains source CWE sets, short
vulnerability context, official CWE 4.20 entries and paths, plus frozen text
snapshots from references listed by NVD or GHSA. It contains no method
prediction and no prior reviewer decision.

Do not use prior project labels, another reviewer's output, or live web lookup.
Judge only the supplied row and frozen evidence records. Ignore records whose
`fetch_status` is not `ok`.

For every input row, write exactly one JSON object with the required output
keys. Preserve input order and identity fields exactly.

Decision rules:

- Official ancestry proves taxonomy compatibility only. It does not prove that
  both CWE assignments correctly describe this CVE.
- `representation_discrepancy` requires affirmative evidence that the concrete
  vulnerability mechanism supports the more specific CWE and its broader
  ancestor, with abstraction/granularity as the only material difference.
- `factual_conflict` requires affirmative evidence that one specific assignment
  describes a materially different mechanism or is contradicted by the
  concrete vulnerability mechanism.
- Use `uncertain` when the frozen evidence does not establish either condition.
  An uncertain row must use `specific_mapping_verdict=insufficient`, confidence
  `low`, and `needs_additional_review=true`.
- A determinate label must cite at least one frozen evidence record. Each
  `quote` must be an exact 20-280 character substring of that record's
  `text_snippet`; cite its `source_url` exactly.
- `supporting_cwe_paths` must contain only literal path strings derivable from
  the row, joined with `>`.
- The rationale must explain the taxonomy relation, concrete mechanism, and
  cited evidence in at least 120 characters.

Required output keys:

```text
reviewer_id
run_id
review_id
cve_id
set_relation
discrepancy_label
taxonomy_support_verdict
specific_mapping_verdict
confidence
needs_additional_review
rationale
supporting_cwe_paths
supporting_evidence
```

Allowed values:

- `set_relation`: use the row's contract.
- `discrepancy_label`: use the row's contract.
- `taxonomy_support_verdict`: use the row's contract.
- `specific_mapping_verdict`: `same_mechanism_supported`,
  `materially_different_or_contradicted`, or `insufficient`.
- `confidence`: `high`, `medium`, or `low`.
- `supporting_evidence`: JSON list of objects with exactly `url` and `quote`.

All decisions are non-human expert candidates. Do not claim human annotation or
human gold.
