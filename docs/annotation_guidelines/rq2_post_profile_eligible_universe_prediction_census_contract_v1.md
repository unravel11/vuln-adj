# RQ2 Post-profile Eligible-universe Prediction Census Contract v1

## Purpose

This diagnostic measures how often the six frozen RQ2 profiles disagree across
the complete 5,948-CVE snapshot-external eligible universe. It is a
prediction-only census for future cohort design. It does not draw another
sample, create a review worklist, read any annotation, or estimate accuracy.

## Bound universe and profiles

- Parent cohort: `rq2_post_profile_snapshot_v1`.
- Eligible tier: the already frozen `snapshot_external` tier containing 5,948
  unique CVEs with exactly one reviewed GHSA record.
- Census rows: all five target fields for every eligible CVE, for 29,740 field
  instances. Repeated fields from the same CVE are retained in the census but
  must be reported as one dependency cluster for future design.
- Profiles: the six prediction columns sealed by the parent cohort.
- Every acquisition, aligned-data, field-view, profile, taxonomy, predictor,
  and parent-builder hash must still match the parent sealed manifest.

Before extending predictions to the universe, the implementation must replay
the existing 250 sealed predictions exactly from their source rows. Any replay
drift fails closed.

## Required census outputs

- Eligible CVE and field-instance totals.
- Current-status counts by field.
- Complete prediction-vector equivalence classes across all six profiles.
- Difference counts versus current by profile and field.
- Pairwise profile difference rows, unique CVEs, multi-field CVE clusters,
  minimum attainable exact two-sided McNemar p-value under the extremal
  all-one-direction assignment, and availability against the previously fixed
  6/12/20/49 effective-discordance planning thresholds.
- A hash-bound JSONL containing only prediction-difference rows. It contains no
  reviewer or correctness field.
- Comparison with the existing 250-row prediction-only sample, without treating
  either sample rate as a future population estimate.

## Statistical boundary

The census counts deterministic prediction differences in one revealed,
snapshot-external universe. It does not observe correctness discordance. A
prediction-difference row may make either profile correct or both wrong after
gold labeling. Multiple field rows from one CVE are not independent; future
sampling or inference must retain CVE clustering or select at most one field per
CVE.

The exact-test values are theoretical capacity bounds only. Reaching 6, 12, 20,
or 49 prediction-difference CVEs does not establish the corresponding number of
correctness-discordant outcomes or any directional win probability.

## Claim boundary

- `label_is_human=false` and `uses_any_labels=false`.
- `same_snapshot_resampling_performed=false` and
  `review_worklist_created=false`.
- The result cannot support human-gold, accuracy, macro-F1, confirmatory gain,
  temporal generalization, preregistered power, candidate promotion, or a
  production switch.
- The census may only guide the design of a later strict event-time cohort whose
  selection and power contract are frozen before any new labels.
