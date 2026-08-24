# RQ2 Post-Profile CWE Evidence-Secondary Contract v3

## Supersession

V3 supersedes two rejected attempts. V1 omitted an explicit conditional
confidence instruction for `uncertain`; v2 made that condition explicit but did
not expose the exact serialized CWE path strings, and a reviewer emitted
`CWE-347 -> CWE-345` instead of `CWE-347>CWE-345`. Neither attempt produced a
merged result. Their complete archives are retained and hash-bound as v3
inputs.

V3 changes only the CWE-path interface: each blind row now contains
`allowed_cwe_path_strings`, and the runner rejects any nonliteral path before
writing a reviewer artifact. Row selection, source values, evidence, label
definitions, and claim boundaries are unchanged.

## Scope

The diagnostic covers exactly the three `cwe_ids` rows on which sealed
`current` and `cwe_taxonomy_v1` predictions differ. Selection occurred after
original A/B labels were unsealed. The result is post-selection and cannot
estimate unbiased gain, temporal generalization, or production readiness.

Reviewer C receives target order; Reviewer D receives exact reverse order.
Both use new ephemeral sessions and may see only their blind worklist and the
frozen prompt.

## Evidence and Decisions

- URLs must occur in the frozen NVD/GHSA reference context.
- At most five URLs per row are selected deterministically.
- Reviewers may use only successful frozen snippets, with no live lookup.
- Determinate labels require literal 20-280 character citations.
- `supporting_cwe_paths` must be a duplicate-free subset of the row's exact
  `allowed_cwe_path_strings`; reviewers must copy strings byte-for-byte.
- `representation_discrepancy` requires the same concrete mechanism at
  different taxonomy granularity, high/medium confidence, no additional
  review, a literal allowed path, and frozen evidence.
- `factual_conflict` requires affirmative evidence that granularity is not the
  only material difference, high/medium confidence, no additional review, and
  frozen evidence.
- `uncertain` requires both verdicts `insufficient`, confidence `low`, and
  `needs_additional_review=true`.

Strict consensus requires exact agreement on set relation, label,
taxonomy-support verdict, and specific-mapping verdict; the label must be
determinate and neither reviewer may request additional review.

## Claim Boundary

All v3 artifacts must preserve:

- `post_selection_profile_differential=true`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `eligible_for_confirmatory_method_gain_claim=false`
- `strict_event_time_claim_allowed=false`
- `candidate_promotion_allowed=false`
- `production_default_changed=false`

The v3 result cannot replace the sealed 250-row evaluation. Real human-gold
still requires real annotator/reviewer identities and signed author resolution.
