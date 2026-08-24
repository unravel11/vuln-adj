# RQ2 Typing Unresolved Evidence Secondary Contract v1

Status: frozen before new evidence retrieval and before reviewer D/E output.

## Scope

This post-unsealing development audit contains all and only the 37 rows that
remain unresolved after the sealed A/B review and reviewer-C tiebreak. It does
not reopen any of the 1,213 existing non-human candidate rows.

The selected field counts are fixed:

- affected_versions: 28
- cwe_ids: 6
- references: 2
- severity: 1

The prior-vote diagnostic groups are also fixed: 17 zero-qualified, 10
one-qualified, 3 two-qualified-split, and 7 three-qualified-split rows.

## Blindness

Reviewer D and reviewer E receive the original blind field row plus frozen URL
evidence. They do not receive the baseline, predictions, A/B/C decisions,
qualified-vote counts, candidate labels, or group assignment. D and E use
opposite deterministic row orders and disjoint ephemeral Codex sessions.

An author-only triage artifact may contain A/B/C decisions and group assignment,
but no baseline or method prediction. It must not be supplied to D or E.

## Evidence Retrieval

Only URLs already present in the row's NVD/GHSA reference context are eligible.
URLs are ranked deterministically, with security advisories and concrete
commit/pull/issue/file records before general pages. Repository roots and NVD
record pages are not selected unless no more specific eligible evidence exists.
At most six URLs are selected per row.

GitHub commit and pull pages may be fetched through their `.patch` forms, and
GitHub blob pages may be fetched through `raw.githubusercontent.com`. The
reviewer-visible citation URL remains the original frozen source URL. HTTP
failure, missing text, truncation, or a source merely repeating its own claim is
not affirmative support for a relationship between both source values.

## Review Contract

Both reviewers use the same discrepancy taxonomy and field contract. They may
use only supplied structured values, field context, and frozen evidence records.
For affected_versions, cwe_ids, and references, a resolved secondary row must
have strict D/E consensus and each reviewer must cite at least one supplied URL
whose frozen record has `fetch_status=ok` and non-empty text. Severity may be
resolved from the supplied structured CVSS values without a URL citation.

Strict D/E consensus requires the same determinate label, confidence other than
low, and `needs_human_review=false` from both reviewers. Prior A/B/C votes are
not added to the secondary decision.

## Fixed Advancement Gate

The development gate is fixed before evidence retrieval:

- at least 75% of the 37 rows have one successful non-empty evidence record;
- at least 40% of the 37 rows obtain evidence-qualified strict D/E consensus;
- combined non-human candidate coverage reaches at least 0.982 over 1,250 rows;
- every artifact preserves `label_is_human=false`.

Passing this gate permits only a broader non-human development candidate. It
does not permit an accuracy, human-gold, independent-human agreement,
confirmatory-performance, or production-switch claim. Failure does not permit a
threshold change or a fallback to A/B/C majority voting.
