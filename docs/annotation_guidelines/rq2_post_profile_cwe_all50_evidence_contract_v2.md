# RQ2 Post-Profile CWE All-50 Evidence Contract v2

## Supersession

V2 supersedes the rejected v1 fixed-subset contract. V1 incorrectly treated a
literal set subset as proof of a semantically compatible information subset.
Reviewer E twice rejected that forced combination on its first row; Reviewer F
accepted 20 rows and then rejected the same forced combination on another
subset row. No E row and no v1 merged label exists. The complete v1 seal,
accepted F prefix, request logs, prompt, contract, and execution code are
retained in a hash-bound failed-attempt archive. Rejected raw responses were
not preserved by the v1 runner and cannot be reconstructed.

V2 keeps all 50 source rows, URL snapshots, profile blindness, ordering, model,
and strict merge components. It changes only literal-subset semantics:

- `incomplete` requires frozen evidence that the extra assignment is compatible
  information about the same mechanism;
- `factual_conflict` requires frozen evidence of a materially different or
  contradicted mechanism;
- `uncertain` remains fail-closed when the evidence cannot decide compatibility.

## Scope And Inputs

The audit covers every `cwe_ids` row in the sealed 250-row snapshot-external
cohort. The three current-versus-taxonomy profile differences are not identified
in either worklist. The original seal, source rows, predictions, A/B outputs,
consensus, profile evaluation, CWE 4.20, frozen evidence, failed v1 archive,
prompt, and execution code are hash-bound before any v2 reviewer output.

At most three URLs already listed by NVD or GHSA are frozen per row. Reviewers
may use only successful frozen snippets. Live lookup, prior labels, profile
predictions, and difference membership are forbidden.

## Decisions And Gates

Each reviewer returns set relation, discrepancy label, taxonomy compatibility,
specific-mechanism verdict, confidence, rationale, exact paths, and literal
evidence.

- Exact sets map to `equivalent`, `not_needed`, and
  `same_mechanism_or_not_needed`.
- Literal subsets may map to `incomplete`, `factual_conflict`, or `uncertain`.
  Every determinate subset label requires frozen evidence.
- Overlap rows may map to `representation_discrepancy`, `factual_conflict`, or
  `uncertain`.
- Disjoint representation discrepancies require full official taxonomy
  compatibility, an exact allowed path, and same-mechanism frozen evidence.
- Every determinate non-exact label requires a literal 20--280 character quote.
- `uncertain` requires taxonomy and mapping `insufficient`, low confidence, and
  `needs_additional_review=true`.

Reviewer E uses source order and set-first reasoning. Reviewer F uses reverse
order and mechanism-first reasoning. Each five-row batch uses a new ephemeral
session. Strict consensus requires exact agreement on set relation, label,
taxonomy compatibility, and mapping verdict, high/medium confidence, and no
review request.

## Claim Boundary

The audit is post-hoc and field-complete, not confirmatory. Every artifact must
keep `label_is_human=false`, human-gold and confirmatory-gain eligibility false,
strict-event-time eligibility false, promotion false, production change false,
and sealed-250-row change false. Real human gold still requires externally
verified real reviewers and signed author resolution.
