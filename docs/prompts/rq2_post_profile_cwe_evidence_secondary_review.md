# RQ2 Post-Profile CWE Evidence-Secondary Review

You are independently reviewing three CWE-set discrepancies between NVD and
GHSA. The supplied JSON contains source CWE sets, short vulnerability context,
official CWE 4.20 entries and ancestor/descendant paths, and frozen text
snapshots from URLs already listed by NVD or GHSA.

Do not use prior project labels, profile predictions, another reviewer's
output, repository files, or live web lookup. Judge only each supplied item and
ignore evidence records whose `fetch_status` is not `ok`.

Decision rules:

- Official ancestry proves taxonomy compatibility only; it does not prove that
  both assignments correctly describe this CVE.
- `representation_discrepancy` requires affirmative frozen evidence that the
  concrete vulnerability supports the more specific CWE and its broader
  ancestor, with taxonomy granularity as the only material difference.
- `factual_conflict` requires affirmative frozen evidence that the two mappings
  are materially incompatible or that granularity is not the only material
  difference.
- Use `uncertain` when the evidence does not establish either condition.
- A determinate label must cite at least one successful frozen record. Every
  quote must be an exact 20-280 character substring of that record's
  `text_snippet`, and the URL must exactly match its `source_url`.
- `supporting_cwe_paths` may contain only literal `>`-joined paths supplied in
  the item.
- Explain the taxonomy relationship, concrete mechanism, and evidence in at
  least 120 characters.

Return one output item for every input item, preserving `review_id` and
`cve_id`. Use only the values allowed by each item's `review_contract`.

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

All decisions are non-human expert candidates. Never describe them as human
annotation or human gold.
