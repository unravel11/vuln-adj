# RQ2 Post-Profile CWE Evidence-Secondary Contract v1

## Purpose

This contract governs a targeted evidence-secondary review of the three
`cwe_ids` rows on which the sealed `current` and `cwe_taxonomy_v1` profiles
differ in `rq2_post_profile_snapshot_v1`.

The rows were selected after the original A/B reviews and profile evaluation
were unsealed. The exercise is therefore a post-selection development
diagnostic. It may explain the three observed differences, but it cannot
estimate an unbiased method gain, temporal generalization, or production
readiness.

## Frozen Selection

- The builder must derive the target IDs from the sealed profile evaluation,
  not from a manually edited list.
- Exactly three rows must be selected, all with `field=cwe_ids` and different
  `current` and `cwe_taxonomy_v1` predictions.
- The blind worklists must exclude all profile predictions, prior reviewer
  labels, consensus fields, correctness indicators, and gold terminology.
- Reviewer C receives target order; reviewer D receives the exact reverse.

## Evidence Boundary

- Evidence URLs must already occur in the frozen NVD or GHSA reference context
  for the selected row.
- At most five URLs per row are selected by a deterministic ranking rule.
- GitHub commit and pull-request URLs are fetched as patch snapshots; other
  URLs use the frozen HTTP fetcher contract.
- Reviewers may use only successful frozen snippets. Live web lookup and
  repository-wide search are prohibited.
- A determinate decision must cite a literal 20-280 character substring from a
  successful frozen snippet.

## Decision Contract

- `representation_discrepancy` requires both an official ancestor/descendant
  path and affirmative row-specific evidence that the two assignments describe
  the same concrete weakness at different taxonomy granularity.
- `factual_conflict` requires affirmative row-specific evidence that the
  assignments are materially incompatible or that granularity is not the only
  material difference.
- `uncertain` is mandatory when the frozen evidence cannot establish either
  condition.
- An uncertain decision must use low confidence and request additional review.

Strict evidence consensus requires exact reviewer agreement on set relation,
discrepancy label, taxonomy-support verdict, and specific-mapping verdict; the
label must be determinate and neither reviewer may request additional review.

## Independence and Provenance

- Reviewer outputs must not exist when the worklists are sealed.
- C and D must use different ephemeral Codex session IDs and different run IDs.
- Reviewer files, request logs, prompt, worklists, source artifacts, fetcher,
  builder, runner, and merger are hash-bound.
- Both reviews are non-human expert candidates even if they agree.

## Claim Boundary

Every manifest and summary must preserve all of the following:

- `post_selection_profile_differential=true`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `eligible_for_confirmatory_method_gain_claim=false`
- `strict_event_time_claim_allowed=false`
- `candidate_promotion_allowed=false`
- `production_default_changed=false`

The evidence-secondary result must not replace the sealed 250-row evaluation.
It may report only targeted counts and case-level directions for these three
rows. Real human-gold still requires real annotator and reviewer identities,
independent review, author resolution, and the existing signed gates.
