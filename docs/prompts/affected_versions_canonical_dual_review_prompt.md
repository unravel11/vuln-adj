# Affected Versions Canonical-Match Dual Review

Review every JSONL row in the supplied blinded worklist independently. Use only the
row's structured NVD/GHSA values, package context, fetched evidence, and
`canonical_only_evidence_matches`. Do not browse the web. Do not consult existing
silver labels, expert-candidate labels, method predictions, metrics, or another
reviewer.

For each row, decide whether canonicalized version-token matches are genuine
contextual support for the affected-version claim. A version appearing in change
history, navigation, CVSS text, an unrelated release, a different package, or a
different release branch is not sufficient support. String similarity alone does
not establish package identity or range equivalence. Preserve `uncertain` and
`abstain` when the fetched evidence cannot support a stronger conclusion.

Return exactly one JSON object per input row, in input order, with these keys:

```text
review_id
sample_id
cve_id
discrepancy_label
adjudicated_source
canonical_match_verdict
recommended_match_policy
confidence
needs_additional_review
rationale
evidence_urls
```

Use only enum values listed in each row's `review_contract`. `needs_additional_review`
must be a boolean. `rationale` must state the package/range/evidence reason without
referring to hidden labels or method accuracy. `evidence_urls` must be a JSON array
containing only URLs present in that row. Output JSONL only, with no Markdown fence
or surrounding commentary.
