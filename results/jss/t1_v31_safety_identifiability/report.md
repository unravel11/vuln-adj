# V3.1 Label-Free Safety Identifiability Audit

Decision: `GO_FREEZE_V3_1_WITH_DELTA_0_10_AND_N29`

This audit uses no human labels. It freezes what the planned sample can
and cannot identify before reviewer exposure.

## Frozen observations

- Shared no-manual-route audit: 34 formal cases.
- Severity: 15 cases; affected versions: 19 cases.
- If all 34 have zero human-confirmed shared misses, the one-sided 95% sample-conditional upper bound is 0.084.
- That bound is not a population miss-rate bound; weights have small
  effective sample sizes and the sample is deliberately cell-stratified.

## Pre-registered positive-framing safety gate

- Simple-only manual-route loss margin: 0.10.
- The margin was selected substantively, not by inspecting labels.
- At least 29 human conflict-escalation actions are required for each reviewer; 25 remains only the reporting floor.
- Both reviewers must independently clear the gate.

## Margin feasibility with zero observed losses

| Margin | Minimum conflict actions | n=25 sufficient | n=29 sufficient |
|---:|---:|:---:|:---:|
| 0.05 | 59 | no | no |
| 0.10 | 29 | no | yes |
| 0.15 | 19 | yes | yes |

No correctness, superiority, safety, or distribution claim follows
from this label-free audit.
