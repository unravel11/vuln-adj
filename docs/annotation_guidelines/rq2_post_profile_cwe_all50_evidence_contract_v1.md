# RQ2 Post-Profile CWE All-50 Evidence Contract v1

## Scope

This post-hoc development audit covers every `cwe_ids` row in the sealed
250-row snapshot-external cohort. It includes 50 rows: exact-set controls,
literal-subset controls, overlapping non-subset rows, and disjoint rows. The
three rows where `current` and `cwe_taxonomy_v1` differ are not identified in
either reviewer worklist.

Selection follows unsealing of the original A/B review and profile evaluation.
The audit can test whether the earlier three-row direction persists inside a
field-complete evidence review, but it cannot provide an unbiased method-gain,
temporal-generalization, human-gold, or production-switch estimate.

## Frozen Inputs

- The original 250-row cohort seal, source rows, six profile predictions,
  A/B outputs, merge output, and profile evaluation are hash-bound.
- Every CWE row carries its original NVD/GHSA sets, vulnerability context,
  official CWE 4.20 entries, and deterministic taxonomy relation profile.
- At most three ranked URLs already listed by NVD or GHSA are frozen per row.
- Reviewers may use only successful frozen snippets. Live lookup is forbidden.
- Profile predictions, prior labels, consensus, and difference membership are
  forbidden in blind worklists.

## Decisions

Each reviewer returns four strict components plus confidence and evidence:

1. `set_relation`: `exact_set`, `literal_strict_subset`,
   `overlap_non_subset`, or `disjoint`.
2. `discrepancy_label`: `equivalent`, `incomplete`,
   `representation_discrepancy`, `factual_conflict`, or `uncertain`.
3. `taxonomy_compatibility`: `not_needed`, `full`, `partial`, `none`, or
   `insufficient`.
4. `specific_mapping_verdict`: `same_mechanism_or_not_needed`,
   `materially_different_or_contradicted`, or `insufficient`.

Exact sets map to `equivalent`; literal strict subsets map to `incomplete`.
These set-theoretic controls use `not_needed` and
`same_mechanism_or_not_needed`. For overlap or disjoint rows, a determinate
representation/factual-conflict label requires a literal 20--280 character
quote from a successful frozen record. A disjoint representation discrepancy
also requires full official taxonomy coverage and at least one exact allowed
CWE path. `uncertain` requires both semantic verdicts `insufficient`, low
confidence, and `needs_additional_review=true`.

Reviewer E sees sealed source order and reasons from sets/taxonomy before
evidence. Reviewer F sees exact reverse order and reasons from the concrete
mechanism before taxonomy. Every batch uses a new ephemeral session.

## Strict Consensus

Strict consensus requires exact agreement on all four decision components, a
determinate label, high/medium confidence from both reviewers, and no request
for additional review. Reviewer, run, and session identifiers must be disjoint
under the sealed request contract.

## Claim Boundary

Every artifact preserves:

- `post_hoc_field_complete=true`
- `selected_after_a_b_unsealing=true`
- `profile_differences_hidden_from_reviewers=true`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `eligible_for_confirmatory_method_gain_claim=false`
- `strict_event_time_claim_allowed=false`
- `candidate_promotion_allowed=false`
- `production_default_changed=false`
- `sealed_250_row_evaluation_changed=false`

Real human gold still requires two real reviewers with externally verified
identities and signed author resolution.
