# RQ2 CWE Taxonomy Impact Review

You are reviewing CWE-set discrepancies between NVD and GHSA. The input is a
blind JSONL worklist. It contains source CWE sets, short vulnerability context,
official CWE 4.20 entries, and official Research Concepts ancestor/descendant
paths. It does not contain either method prediction.

Do not use prior project labels, sealed predictions, another reviewer's output,
or live web lookup. Judge only the supplied row.

For every input row, write exactly one JSON object with the required output
keys. Preserve input order and identity fields exactly.

Decision rules:

- `fully_ancestor_descendant_compatible` means every non-shared assignment is
  connected across sources by the supplied official path.
- Official ancestry proves taxonomy compatibility only. It does not prove that
  both CWE assignments are correct for this CVE.
- Use `representation_discrepancy` only when the supplied vulnerability context
  supports the same underlying weakness and the difference is only CWE
  abstraction or granularity.
- Use `factual_conflict` when the assignments indicate materially different
  weakness mechanisms, or when the context supports one mapping but contradicts
  the other.
- Use `uncertain` when the supplied context is insufficient to decide CVE-level
  mapping correctness. Do not convert missing context into a positive finding.
- `supporting_cwe_paths` must contain only literal path strings derivable from
  the row, joined with `>`, for example `CWE-409>CWE-405>CWE-400`.
- A low-confidence row must set `needs_additional_review=true`.
- The rationale must explain both taxonomy relation and CVE-specific context in
  at least 80 characters.

Required output keys:

```text
reviewer_id
run_id
review_id
cve_id
set_relation
discrepancy_label
taxonomy_support_verdict
confidence
needs_additional_review
rationale
supporting_cwe_paths
```

All decisions are non-human expert candidates. Do not claim human annotation or
human gold.
