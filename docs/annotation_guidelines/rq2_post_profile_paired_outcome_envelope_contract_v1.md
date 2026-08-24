# RQ2 Post-profile Paired-outcome Envelope Contract v1

## Purpose

This diagnostic determines the complete paired outcome space for the sealed
`current` and `cwe_taxonomy_v1` predictions without reading any reviewer,
consensus, evidence-secondary, or human label. It is a deterministic
identifiability and effect-size bound, not an accuracy evaluation.

## Bound cohort

- Cohort: `rq2_post_profile_snapshot_v1`.
- Required sealed rows: 250, with 50 rows per field and unique `sample_id`.
- Required prediction profiles: `current` and `cwe_taxonomy_v1` from the
  original sealed cohort manifest.
- The diagnostic must reject source or prediction hash drift.

## Label universe and enumeration

Each profile-difference row is independently assigned one of the five frozen
typing labels:

- `equivalent`
- `representation_discrepancy`
- `incomplete`
- `temporal_discrepancy`
- `factual_conflict`

For every complete assignment, a row contributes `+1` when only the CWE
candidate matches, `-1` when only current matches, and `0` when both are wrong
or both are equal. The diagnostic enumerates all assignments exactly.

Assignment counts are logical case counts. They must not be interpreted as
probabilities, a prior over human labels, or empirical frequencies.

## Required outputs

- Number of equal-prediction and different-prediction rows.
- Difference rows and their two sealed predictions.
- Exact assignment count by paired delta.
- Maximum possible absolute accuracy difference over all 250 rows and within
  each affected field.
- The minimum human-review information needed to determine the paired sign.

## Claim boundary

- `label_is_human=false`.
- No existing non-human or human decision is read.
- The output cannot support a human-gold, accuracy, confirmatory gain,
  temporal-generalization, candidate-promotion, or production-switch claim.
- Reviewing only prediction-difference rows can determine the paired method
  difference, but it cannot estimate absolute accuracy, macro-F1, construct
  validity, or full-cohort error distribution. Those require the full
  real-person review workflow and external identity verification.
