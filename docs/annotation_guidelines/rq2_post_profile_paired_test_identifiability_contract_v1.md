# RQ2 Post-profile Paired-test Identifiability Contract v1

## Purpose

This label-free design diagnostic asks whether the sealed 250-row post-profile
cohort can support a statistically significant paired accuracy difference under
any possible future gold-label assignment. It does not estimate accuracy and it
does not read reviewer, consensus, evidence-secondary, or human labels.

## Bound inputs

- Cohort: `rq2_post_profile_snapshot_v1`.
- Required rows: 250, with 50 rows per field and unique ordered `sample_id`.
- Required predictions: the six profiles in the original sealed cohort
  manifest: `current`, the two reference profiles, `cwe_taxonomy_v1`, and the
  two combined profiles.
- Source and prediction hashes must still match the sealed cohort manifest.

## Exact paired test

For each profile pair, a future gold label can make a prediction-difference row
one of three correctness outcomes: first-profile-only correct,
second-profile-only correct, or both wrong. Rows where the profiles predict the
same label can never be discordant for paired correctness.

The diagnostic uses the conventional conditional exact two-sided McNemar test:

- the null assigns probability 0.5 to either direction among correctness-
  discordant rows;
- the two-sided p-value is twice the lower binomial tail, capped at 1;
- a pair is theoretically test-capable at `alpha=0.05` only if at least one
  possible gold assignment has `p <= 0.05`.

All five frozen discrepancy labels are enumerated on the representative
`current` versus `cwe_taxonomy_v1` difference rows. Assignment counts are
logical cases, not probabilities or a prior over gold labels.

## Planning sensitivity

The diagnostic reports:

- the smallest number of correctness-discordant rows that can ever reject the
  exact two-sided null at `alpha=0.05`;
- exact conditional power requirements for second-profile win probabilities
  0.70, 0.80, and 0.90 at target power 0.80;
- illustrative future cohort sizes needed to observe the theoretical minimum
  number of prediction differences with probabilities 0.80, 0.90, and 0.95 if
  the observed `3/250` prediction-difference rate were stationary.

The power calculations are conditional on correctness-discordant rows. The
future-cohort calculations assume independent random sampling and a stationary
prediction-difference rate. They are design sensitivities, not validated power,
sample-size commitments, or generalization results.

## Required outputs

- Prediction-vector equivalence classes across all six profiles.
- Pairwise prediction-difference counts and minimum attainable exact p-values.
- Complete representative-pair assignment counts by effective discordant-row
  count and exact p-value.
- Whether any label assignment can reject at `alpha=0.05`.
- The theoretical minimum and the explicitly assumption-bound planning
  sensitivities above.

## Claim boundary

- `label_is_human=false` and `uses_any_labels=false`.
- The output cannot support a human-gold, accuracy, confirmatory-gain,
  temporal-generalization, candidate-promotion, production-switch, or
  preregistered-power claim.
- Real-person full-cohort review remains necessary for absolute accuracy,
  macro-F1, construct validity, and error-distribution claims.
