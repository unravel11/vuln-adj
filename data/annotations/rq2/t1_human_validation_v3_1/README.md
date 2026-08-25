# T1/T2 Human Validation V3.1

Status: PREPARATION_ONLY_NOT_FOR_DISTRIBUTION

This directory contains 120 formal cases, 20 calibration-1 cases, and a
presealed 20-case calibration-2 reserve for each of two independent trained
analysts. The ordinary budget is 140 cases per reviewer; the bounded maximum is
160 only when calibration-2 is triggered.

Every phase has action and reason packets. Action returns must be validated,
hashed, and locked before the matching reason packets are released.

Reviewer-visible packets contain no human labels and are not human gold.
Internal files contain deterministic statuses, policy actions, source
identities, selection cells, and weights and must never be distributed.

The current manifest blocks all distribution. A later explicit revision must
allowlist one reviewer, one phase, and one stage after every protocol gate is
satisfied.
