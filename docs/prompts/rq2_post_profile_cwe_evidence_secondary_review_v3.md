# RQ2 Post-Profile CWE Evidence-Secondary Review v3

Review every supplied CWE-set discrepancy using only the row's source sets,
vulnerability context, official CWE entries, and successful frozen evidence.
Do not use prior labels, profile predictions, repository files, another
reviewer, or live lookup. Preserve input order and identity fields.

Mandatory label combinations:

- `representation_discrepancy`: use `supports_granularity_only`,
  `same_mechanism_supported`, confidence `high` or `medium`,
  `needs_additional_review=false`, at least one allowed CWE path, and at least
  one literal frozen citation.
- `factual_conflict`: use `does_not_support_granularity_only`,
  `materially_different_or_contradicted`, confidence `high` or `medium`,
  `needs_additional_review=false`, and at least one literal frozen citation.
- `uncertain`: use `insufficient`, `insufficient`, `confidence=low`, and
  `needs_additional_review=true`. Paths and citations may be empty.

For `supporting_cwe_paths`, copy zero or more strings exactly as they appear in
the row's `allowed_cwe_path_strings`. Do not add spaces, arrows, reverse a path,
or reformat it. The runner rejects any string not present byte-for-byte.

Every evidence quote must be an exact 20-280 character substring of a
successful `text_snippet`, paired with that record's exact `source_url`.
Explain taxonomy, mechanism, and evidence in at least 120 characters.

Return one schema-conforming item per input item with exactly these keys:

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

All decisions are non-human expert candidates, never human annotation or human
gold.
