# RQ2 Post-Profile CWE All-50 Evidence Review v2

Review every supplied CWE row using only its NVD/GHSA sets, vulnerability
context, official CWE entries and paths, and successful frozen evidence. Do not
use prior labels, profile predictions, repository files, another reviewer, or
live lookup. Preserve input order and identity fields.

Mandatory combinations:

- `exact_set` -> `equivalent`, `not_needed`,
  `same_mechanism_or_not_needed`, confidence high/medium, no additional review.
- `literal_strict_subset` + `incomplete` -> taxonomy `not_needed`, `full`, or
  `partial`, `same_mechanism_or_not_needed`, confidence high/medium, no
  additional review, and frozen evidence showing compatible extra information.
- `literal_strict_subset` + `factual_conflict` -> taxonomy `full`, `partial`, or
  `none`, `materially_different_or_contradicted`, confidence high/medium, no
  additional review, and frozen evidence showing a material mechanism mismatch.
- `overlap_non_subset` + `representation_discrepancy` -> taxonomy `full` or
  `partial`, `same_mechanism_or_not_needed`, confidence high/medium, no
  additional review, and frozen evidence.
- `disjoint` + `representation_discrepancy` -> taxonomy `full`,
  `same_mechanism_or_not_needed`, confidence high/medium, no additional review,
  at least one exact allowed CWE path, and frozen evidence.
- `overlap_non_subset` or `disjoint` + `factual_conflict` -> taxonomy `full`,
  `partial`, or `none`, `materially_different_or_contradicted`, confidence
  high/medium, no additional review, and frozen evidence.
- Any non-exact row may use `uncertain` only with taxonomy `insufficient`, mapping
  `insufficient`, confidence low, and `needs_additional_review=true`.

A literal subset is not automatically semantically compatible. Decide whether
the extra CWE describes compatible additional information, a materially
different mechanism, or an unresolved mapping. Copy supporting CWE paths
byte-for-byte from `allowed_cwe_path_strings`. Every evidence quote must be an
exact 20--280 character substring of a successful `text_snippet`, paired with
that record's exact `source_url`. Explain the set relation, taxonomy, mechanism,
and evidence in at least 120 characters. Exact-set controls may omit evidence.

Return one schema-conforming item per input item with exactly these keys:

```text
review_id
cve_id
set_relation
discrepancy_label
taxonomy_compatibility
specific_mapping_verdict
confidence
needs_additional_review
rationale
supporting_cwe_paths
supporting_evidence
```

All decisions are non-human expert candidates, never human annotation or human
gold.
