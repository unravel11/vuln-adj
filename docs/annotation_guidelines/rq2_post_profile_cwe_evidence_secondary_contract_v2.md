# RQ2 Post-Profile CWE Evidence-Secondary Contract v2

## Supersession

This contract supersedes v1 after the v1 merge correctly rejected Reviewer C:
two `uncertain` rows used medium confidence even though the contract required
low confidence. The v1 prompt did not state that conditional requirement
explicitly enough. No v1 reviewer label was merged or used as a result. The
complete failed attempt is retained and hash-bound as a v2 input.

V2 changes only the output-contract wording. It does not change row selection,
source values, taxonomy data, evidence ranking, evidence fetch rules, label
definitions, strict-consensus logic, or claim boundaries.

## Purpose and Selection

V2 reviews exactly the three `cwe_ids` rows on which the sealed `current` and
`cwe_taxonomy_v1` profiles differ in `rq2_post_profile_snapshot_v1`.

The rows were selected after original A/B labels and profile evaluation were
unsealed. This is a post-selection development diagnostic. It cannot estimate
unbiased method gain, temporal generalization, or production readiness.

- Target IDs are derived from the sealed profile evaluation.
- Blind worklists exclude predictions, prior labels, consensus fields,
  correctness indicators, and gold terminology.
- Reviewer C receives target order; reviewer D receives exact reverse order.
- V2 uses new reviewer outputs, run IDs, and ephemeral Codex sessions.

## Evidence Boundary

- URLs must already occur in the frozen NVD or GHSA reference context.
- At most five URLs per row are selected deterministically.
- GitHub commits and pull requests are fetched as patch snapshots.
- Reviewers use only successful frozen snippets and may not perform live lookup
  or repository search.
- Determinate labels require a literal 20-280 character quote from a successful
  frozen snippet.

## Decision and Output Contract

- `representation_discrepancy` requires an official ancestor/descendant path
  and affirmative row-specific evidence of the same concrete weakness at
  different taxonomy granularity. It must use
  `supports_granularity_only`, `same_mechanism_supported`, confidence high or
  medium, `needs_additional_review=false`, a supplied CWE path, and evidence.
- `factual_conflict` requires affirmative evidence that granularity is not the
  only material difference. It must use
  `does_not_support_granularity_only`,
  `materially_different_or_contradicted`, confidence high or medium,
  `needs_additional_review=false`, and evidence.
- `uncertain` is mandatory when neither condition is established. It must use
  `insufficient`, `insufficient`, `confidence=low`,
  `needs_additional_review=true`; citations and paths may be empty.

Strict evidence consensus requires exact agreement on set relation, label,
taxonomy-support verdict, and specific-mapping verdict; the label must be
determinate and neither reviewer may request additional review.

## Provenance and Claim Boundary

- Reviewer outputs must not exist at the v2 seal.
- Reviewer C and D session IDs and run IDs must be disjoint.
- V2 binds the v1 failure archive, source artifacts, prompt, worklists,
  fetcher, builder, runner, merger, verifier, reviewer files, and request logs.
- Both reviews remain non-human expert candidates.

Every v2 artifact must preserve:

- `post_selection_profile_differential=true`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `eligible_for_confirmatory_method_gain_claim=false`
- `strict_event_time_claim_allowed=false`
- `candidate_promotion_allowed=false`
- `production_default_changed=false`

V2 cannot replace or update the sealed 250-row evaluation. Real human-gold
still requires real annotator and reviewer identities, author resolution, and
the existing signed gates.
