# RQ2 Post-Profile Snapshot Cohort Contract v1

## Scope

This contract freezes the label-free cohort selection and prediction sealing
stage that follows `rq2_post_profile_snapshot_v1` acquisition. It does not
modify the hash-bound acquisition contract or convert the cohort into human
gold.

The independently verified acquisition result is:

- strict event-time eligible CVEs: `0`;
- snapshot-external eligible CVEs: `5948`;
- selected tier: `snapshot_external`;
- selected size: `50` rows per field, `250` rows total.

Because the strict tier is empty, this cohort is development-only. It cannot
support a post-profile event-time or temporal-generalization claim.

## Eligible universe

Every selected CVE must:

1. have exactly one aligned reviewed GHSA record in the isolated 2026
   acquisition;
2. begin with `CVE-2026-`;
3. be absent from the existing aligned CVE universe used before the profile
   seal.

The selected tier and row count are read from the verified acquisition
manifest. They may not change after reviewer output exists.

## Label-free sampling

The five fields are `severity`, `published`, `references`,
`affected_versions`, and `cwe_ids`.

For each field, the builder allocates 70% of the 50 rows proportionally across
the non-empty current-baseline status strata and uses the remaining 30% as an
equal-coverage audit supplement. Within each field/status stratum, rows are
ranked by ascending
`sha256(seed + ":" + field + ":" + status + ":" + cve_id)` using seed
`rq2_post_profile_snapshot_v1_20260719`.

A deterministic bipartite quota match enforces one globally unique CVE per
selected field row. Sampling uses only tier eligibility and the already
computed current-baseline status. It must not use candidate-profile
predictions, Codex labels, confidence, agreement, or correctness.

## Predictions sealed before review

The builder seals these six prediction columns before either reviewer output
exists:

- `current`;
- `reference_resource_identity_original_v1`;
- `reference_resource_identity_audited_v1`;
- `cwe_taxonomy_v1`;
- `combined_original_v1`;
- `combined_audited_v1`.

Reference and CWE candidate predictions use the already implemented callable
profiles and the same CWE 4.20 catalog. Prediction differences remain in the
natural sample and are reported, but they do not affect selection.

## Blind review

Two isolated Codex reviewer passes receive raw aligned field values, source
summaries, package names, reference URLs, and individual official CWE entries.
They receive no baseline status, sampling stratum, candidate prediction,
prior annotation, or correctness field. Reviewer B receives the exact reverse
of reviewer A's worklist.

The execution backend, executable version/hash, model, reasoning effort,
prompt hash, worklist hashes, pass identifiers, and output paths are sealed in
the cohort manifest. Both passes use the strict RQ2 typing contract.

## Boundary

- `selected_tier=snapshot_external`
- `strict_event_time_claim_allowed=false`
- `snapshot_external_is_time_confirmatory=false`
- `selection_uses_reviewer_outputs=false`
- `selection_uses_candidate_predictions=false`
- `contains_annotations=false`
- `contains_human_labels=false`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `production_switch_allowed=false`

Codex decisions are expert-candidate annotations only. Human gold still
requires two real human reviewers and author signoff under the existing human
review contract.
