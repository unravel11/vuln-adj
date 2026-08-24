# RQ2 Post-Profile Unresolved Evidence Secondary Contract v1

Status: frozen before evidence retrieval and before reviewer G/H output.

## Scope

This post-unsealing development audit contains all and only the 16 non-CWE rows
that remain unresolved after the sealed 250-row A/B review. The three unresolved
`cwe_ids` rows are excluded because the separately frozen all-50 CWE evidence
audit already supplies field-complete secondary decisions for them.

The selected field counts are fixed:

- affected_versions: 12
- references: 2
- severity: 2

The stage does not reopen any of the 231 sealed strict rows or any CWE row.

## Blindness

Reviewer G and reviewer H receive the original blind field row plus frozen URL
evidence. They do not receive baseline or candidate predictions, A/B decisions,
CWE-audit decisions, consensus labels, selection strata, or correctness fields.
G and H use opposite deterministic row orders and disjoint ephemeral Codex
sessions.

An author-only triage artifact records the prior A/B disagreement for auditability.
It is never supplied to G or H.

## Evidence Retrieval

Only URLs already present in the original row's NVD/GHSA reference context are
eligible. At most six URLs are selected deterministically. Security advisories,
commits, pull requests, issues, files, releases, and vendor records rank before
repository roots or NVD record pages.

GitHub commit and pull pages may be fetched through their `.patch` forms, and
GitHub blob pages may be fetched through `raw.githubusercontent.com`. Reviewers
see and cite the original frozen URL. HTTP failure, empty or truncated text, and
a source merely repeating its own field value do not establish the relationship
between NVD and GHSA.

## Review Contract

Both reviewers use the existing six-label discrepancy contract. A strict
secondary decision requires the same determinate label, confidence above low,
and `needs_human_review=false` from both reviewers. The A/B votes are not added
to G/H.

For `affected_versions` and `references`, both reviewers must cite at least one
supplied URL with `fetch_status=ok` and a non-empty frozen text snippet. Severity
may be resolved from supplied structured CVSS values without URL evidence.

## Fixed Development Gate

Before evidence retrieval, the following no-go thresholds are fixed:

- at least 75% of the 16 rows have one successful non-empty evidence record;
- at least 40% of the 16 rows obtain evidence-qualified strict G/H consensus;
- the staged non-human candidate reaches at least 0.95 coverage over 250 rows;
- every artifact preserves `label_is_human=false`.

The staged candidate starts with the 231 sealed strict A/B rows, adds only the
three previously unresolved CWE rows that are strict in the frozen all-50 CWE
audit, and then adds strict G/H decisions from this stage. Passing permits only
a broader post-selected non-human diagnostic. It does not permit human-gold,
accuracy, independent-human agreement, confirmatory gain, temporal
generalization, candidate promotion, or production-switch claims. Failure does
not permit threshold relaxation or another same-model vote.
