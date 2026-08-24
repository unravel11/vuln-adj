# RQ2 Post-Profile CWE All-50 Evidence Contract v3

## Supersession

V3 preserves the v2 semantic contract and supersedes two rejected attempts.
V1 forced every literal set subset to `incomplete`, conflating set inclusion
with semantic compatibility. V2 corrected that construct and produced two
complete 50-row reviewer files, but merge rejected reviewer E row 3 because a
quoted string was not a literal substring of its frozen snippet. The v2 runner
checked evidence presence before writing but deferred literal validation to
merge. Neither attempt produced a merged result. Exact archives of both failed
attempts are hash-bound as v3 inputs; unavailable rejected-response text is not
reconstructed.

V3 changes only validation timing. Before any batch is appended, the runner now
checks rationale length, citation schema, successful frozen URL membership,
20--280 character quote length, literal substring identity, duplicate
citations, and exact allowed CWE paths. Set, taxonomy, mechanism, confidence,
selection, evidence, ordering, and claim boundaries remain those of v2.

## Scope And Decisions

The audit covers all 50 `cwe_ids` rows in the sealed 250-row
snapshot-external cohort. Profile predictions, A/B labels, consensus, and the
identity of the three profile-difference rows are absent from both worklists.
At most three already-listed NVD/GHSA URLs are frozen per row, and live lookup
is forbidden.

- Exact sets map to `equivalent`.
- Literal subsets may be `incomplete`, `factual_conflict`, or `uncertain` based
  on whether the extra CWE is compatible information about the same mechanism.
- Overlap rows may be `representation_discrepancy`, `factual_conflict`, or
  `uncertain`.
- Disjoint representation discrepancies require full official taxonomy
  compatibility, an exact path, and same-mechanism evidence.
- Every determinate non-exact label requires literal frozen evidence.
- `uncertain` requires both semantic verdicts `insufficient`, low confidence,
  and a review request.

Reviewer E uses source order and set-first reasoning. Reviewer F uses reverse
order and mechanism-first reasoning. Every five-row batch uses a new ephemeral
session. Strict consensus requires exact agreement on set relation, label,
taxonomy compatibility, and mapping verdict, high/medium confidence, and no
review request.

## Claim Boundary

This is a post-hoc, field-complete, same-model-family diagnostic. It is not
human gold, confirmatory gain, strict event-time evidence, or a production
switch. Candidate promotion and changes to the sealed 250-row evaluation remain
disabled. Human gold still requires externally verified real reviewers and
signed author resolution.
