# CWE Taxonomy Dual Review

Review every JSONL row in the supplied blinded worklist independently. Use only the
NVD/GHSA CWE sets, vulnerability summaries, official CWE 4.20 entry metadata, and
official Research Concepts ancestor/descendant paths included in each row. Do not
browse the web, inspect existing baseline/candidate/review labels or metrics, or
contact another reviewer.

Distinguish taxonomy compatibility from correctness for the specific CVE:

- An exact set is `equivalent`.
- A literal strict subset can be `incomplete` when the additional assignment does
  not contradict the shared assignments.
- Disjoint IDs can be `representation_discrepancy` only when official paths and the
  vulnerability summaries support a pure abstraction/granularity difference.
- If only part of a multi-ID set is ancestor/descendant-compatible, do not treat the
  whole set as granularity-only.
- Sibling CWEs or entries that merely share a broad ancestor are not interchangeable.
- Use `uncertain` when taxonomy plus the supplied summaries cannot establish whether
  distinct assignments are complementary or conflicting for this CVE.

Return exactly one JSON object per input row, in input order, with these keys:

```text
review_id
sample_id
cve_id
set_relation
discrepancy_label
taxonomy_support_verdict
confidence
needs_additional_review
rationale
supporting_cwe_paths
```

Use only enum values listed in the row's `review_contract`.
`needs_additional_review` must be a boolean. `supporting_cwe_paths` must be a JSON
array whose entries are exact `CWE-X>CWE-Y>...` paths present in the row; use an
empty array when no official path supports the decision. `rationale` must explain
the set-level decision and must not refer to hidden labels or method accuracy.
Output JSONL only, with no Markdown fence or surrounding commentary.
