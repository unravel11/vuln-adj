# Claim Ledger

| Claim ID | Intended location | Exact claim or decision | Evidence IDs | Allowed strength | Prohibited upgrade | Status |
|---|---|---|---|---|---|---|
| C01 | RQ1 Results | The frozen corpus contains 8,066 CVE-aligned NVD–GHSA rows and 32,264 field instances in the four-field V3 routing census | E01, E07B | Descriptive, snapshot- and pipeline-bounded | Do not call statuses or actions ground truth or infer global database quality | `SUPPORTED` |
| C02 | RQ1 Results | The strong simple and abstention-aware policies make different actions on 2,332 field instances | E07B | Label-free policy-output census | Do not call either action correct or the differences errors | `SUPPORTED` |
| C03 | RQ1/Discussion | The abstention-aware arm has 74 fewer conflict escalations but 950 more total manual-review routes than the strong simple arm on this corpus | E07B | Deterministic routing-count trade-off | Do not call this saved workload, extra labor, safety, or utility | `SUPPORTED` |
| C04 | Method | V3 provides a frozen action-first/reason-second, two-reviewer design with 20 calibration and 120 formal cases | E07C | Protocol and prepare-only artifact claim | Do not imply recruitment, distribution, annotation, independence, or human gold | `SUPPORTED` |
| C05 | RQ2 Results | Trained analysts can reliably assign maintenance actions and discrepancy reasons across the four fields | E08 | Reviewer-specific and field-specific result only after all V3 gates | Do not use calibration, Codex labels, author adjudication, or dropped fields to claim reliability | `ABSTAIN` |
| C06 | RQ2 Results | Discrepancy reasons explain or associate with maintenance actions | E08 | Cross-reviewer association as primary; same-reviewer association as upper bound | Do not state causality or ignore action-first anchoring | `ABSTAIN` |
| C07 | RQ3 Results | The current type-first efficiency arm aligns better with independent human actions than the strong simple comparator | E08, E09 | Paired pre-adjudication comparison under frozen gate | Do not claim superiority if reviewers disagree in direction or intervals include zero | `ABSTAIN` |
| C08 | RQ3 Results | Added abstention improves safety enough to justify its larger total manual-review route | E08, E09 | Explicit efficiency-safety frontier with separate conflict and abstention accounting | Do not convert abstention into zero cost or infer operational safety without human actions | `ABSTAIN` |
| C09 | RQ3 Results | Raw or canonical non-equality is an adequate main comparator | E07B, E09 | Lower-reference arm only | Do not elevate it over the strong field-aware comparator | `REMOVE_FROM_CURRENT_CHAIN` |
| C10 | Reconciliation Limits | The current affected-version adjudication method improves on named baselines | E06 | State the tested no-go and measured coverage only | Do not select favorable rows, hide abstentions, or call a post-hoc union a method | `REMOVE_FROM_CURRENT_CHAIN` |
| C11 | Discussion | Automated reconciliation was frequently unresolved or evidence-dependent in the tested non-human cohorts | E04, E05, E06 | Retrospective, cohort- and protocol-bounded failure finding | Do not generalize to all tools, all fields, or human performance | `SUPPORTED` |
| C12 | Discussion | The current method generalizes to future NVD/GHSA snapshots | E10 | No current positive wording | Do not call the snapshot-external cohort temporal validation | `REMOVE_FROM_CURRENT_CHAIN` |
| C13 | Related Work | This is the first work to type vulnerability-database discrepancies | E11 | Position the differential as action-oriented routing with a strong comparator, abstention, and human construct test | Do not claim absence of prior discrepancy taxonomies | `REMOVE_FROM_CURRENT_CHAIN` |
| C14 | Abstract or cover letter | The paper or package is submission ready | E07, E08, E09 | State only `submission_ready=false` until every blocker clears | Do not convert mechanical validation or prepare-only packets into readiness | `REMOVE_FROM_CURRENT_CHAIN` |

## Claim promotion rule

A claim moves from `ABSTAIN` only when the named missing evidence exists under
the frozen V3 protocol. Primary evidence is pre-adjudication. A negative or
unresolved result is retained; it is not repaired by dropping a field,
excluding abstain/uncertain outcomes, adding same-model votes, revising sampling
cells, or changing thresholds after human exposure.
