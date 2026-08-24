# RQ2 Post-Profile CWE Evidence-Secondary Review v2

Independently review every supplied CWE-set discrepancy between NVD and GHSA.
Use only the supplied source sets, vulnerability context, official CWE 4.20
entries and paths, and successful frozen evidence snippets.

Do not use profile predictions, prior project labels, another reviewer,
repository files, or live lookup. Preserve input order, `review_id`, and
`cve_id`. Return only the required schema.

Decision rules and mandatory output combinations:

- `representation_discrepancy`: frozen evidence affirmatively supports the
  same concrete weakness at different taxonomy granularity. Use
  `taxonomy_support_verdict=supports_granularity_only`,
  `specific_mapping_verdict=same_mechanism_supported`, confidence `high` or
  `medium`, `needs_additional_review=false`, at least one supplied CWE path,
  and at least one literal frozen citation.
- `factual_conflict`: frozen evidence affirmatively shows that granularity is
  not the only material difference. Use
  `taxonomy_support_verdict=does_not_support_granularity_only`,
  `specific_mapping_verdict=materially_different_or_contradicted`, confidence
  `high` or `medium`, `needs_additional_review=false`, and at least one literal
  frozen citation.
- `uncertain`: evidence does not establish either condition. You MUST use
  `taxonomy_support_verdict=insufficient`,
  `specific_mapping_verdict=insufficient`, `confidence=low`, and
  `needs_additional_review=true`. Paths and citations may be empty.

Official ancestry proves taxonomy compatibility only; it does not prove that
both assignments correctly describe the CVE. Every citation quote must be an
exact 20-280 character substring of a successful record's `text_snippet`, and
its URL must exactly equal that record's `source_url`. Explain taxonomy,
mechanism, and evidence in at least 120 characters.

Required item keys:

```text
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

`supporting_evidence` is a list of objects with exactly `url` and `quote`.
Use only values allowed by each item's `review_contract` and obey its
`conditional_constraints` exactly.

All decisions are non-human expert candidates, never human annotation or human
gold.
