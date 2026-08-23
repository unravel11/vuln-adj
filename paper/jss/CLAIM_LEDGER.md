# Claim Ledger

| Claim ID | Intended location | Exact claim or decision | Evidence IDs | Allowed strength | Prohibited upgrade | Status |
|---|---|---|---|---|---|---|
| C01 | RQ1 Results | The frozen corpus contains 8,066 CVE-aligned NVD–GHSA rows and deterministic field-level comparison outputs | E01 | Descriptive, snapshot- and pipeline-bounded | Do not call output labels ground truth or infer global database quality | `SUPPORTED` |
| C02 | Introduction and RQ2 | Not every raw or normalized field mismatch should automatically be treated as a factual conflict | E01, E02, E08 | Problem hypothesis now; finding only after T1 | Do not assert a measured proportion before human labels | `ABSTAIN` |
| C03 | Method and RQ2 | The five-way type-first taxonomy is reliably usable across the four primary fields | E02, E08 | Candidate construct; field-specific reporting required | Do not use AI/Codex agreement as human construct validity; do not drop failed fields | `ABSTAIN` |
| C04 | RQ2 Results | The deterministic baseline achieves stated accuracy, macro-F1, or conflict recall | E02, E08 | Report only after the frozen human evaluation, with uncertain coverage and design weights | Do not compute against AI candidates or incomplete labels | `ABSTAIN` |
| C05 | RQ3 Results | Type-first routing reduces unnecessary escalation while preserving factual-conflict recall relative to binary escalate-all | E08, E09 | Fixed T2 estimands on the frozen evaluation sample | Do not change the action map, denominator, fields, or thresholds after outcomes | `ABSTAIN` |
| C06 | RQ3 Results | The current affected-version adjudication method improves on simple named baselines | E06 | State the tested no-go and measured coverage only | Do not select favorable rows, hide abstentions, or call a post-hoc union a method | `REMOVE_FROM_CURRENT_CHAIN` |
| C07 | Discussion | Automated reconciliation was frequently unresolved or evidence-dependent in the tested non-human cohorts | E04, E05, E06 | Retrospective, cohort- and protocol-bounded failure finding | Do not generalize to all tools, all fields, or human performance | `SUPPORTED` |
| C08 | Discussion | The current method generalizes to future NVD/GHSA snapshots | E10 | No current positive wording | Do not call the snapshot-external cohort temporal validation | `REMOVE_FROM_CURRENT_CHAIN` |
| C09 | Related Work | This is the first work to type vulnerability-database discrepancies | E11 | Position the differential as action-oriented routing, abstention, and identifiability limits | Do not claim absence of prior discrepancy taxonomies | `REMOVE_FROM_CURRENT_CHAIN` |
| C10 | Abstract or cover letter | The paper or package is submission ready | E07, E08, E09 | State only `submission_ready=false` until all blocker classes clear | Do not convert mechanical validation into scientific or submission readiness | `REMOVE_FROM_CURRENT_CHAIN` |

## Claim promotion rule

A claim moves from `ABSTAIN` only when the named missing evidence exists under
the frozen protocol. A negative or unresolved result is retained; it is not
repaired by dropping a field, excluding uncertain rows without reporting them,
adding same-model votes, or revising thresholds after unsealing.
