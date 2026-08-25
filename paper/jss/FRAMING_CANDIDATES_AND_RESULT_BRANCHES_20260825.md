# JSS Framing Candidates and Result-Neutral Branches

**Status**: `CANDIDATE_FOR_AUTHOR_DECISION`; none of the title, thesis, RQ, or
contribution candidates in this file is `AUTHOR_LOCKED`.

**Evidence cutoff**: repository evidence through 2026-08-25 and a post-protocol
publication-status refresh on 2026-08-25. The refresh did not alter the frozen
V3.1 sample, policies, thresholds, packet, evaluator, or tag.

## 1. Result-neutral center

The stable research object is a frozen set of CVE-aligned NVD--GHSA record
pairs. A field mismatch is an observed difference, not by itself a factual
conflict or a maintenance decision. The study asks whether trained analysts can
apply an action-first/reason-second construct and whether three frozen routing
strategies occupy different, human-supported positions once uncertainty and
abstention are counted explicitly.

This center is intentionally compatible with a positive result and a boundary
result. The paper does not need a policy win to report the deterministic
landscape, the analyst decision construct, disagreement, uncertainty, or the
identifiability limits of automatic reconciliation.

## 2. Candidate titles

| ID | Candidate title | Best fit | Risk / author decision |
|---|---|---|---|
| T1 | From Field Mismatch to Maintenance Action: Auditing NVD--GHSA Reconciliation Policies under Human Uncertainty | Neutral default | `Auditing` is accurate; `reconciliation` must not imply that the study selects factual truth. |
| T2 | When Vulnerability Metadata Differ: A Human-Gated Study of Field-Level Routing between NVD and GHSA | Strongest result-neutral wording | `Human-gated` is unusual but makes the missing evidence visible. |
| T3 | Field-Level Vulnerability Metadata Routing under Analyst Disagreement and Abstention | Boundary branch | Less specific in the title; NVD--GHSA must then be explicit in the abstract. |
| T4 | Comparing Field-Aware and Type-First Routing for NVD--GHSA Metadata Differences | Positive branch only after both reviewer-specific gates pass | Do not use a superiority verb such as `improves`, `reduces`, or `outperforms`. |

Recommended candidate before human results: **T2**. This is a recommendation,
not an author lock.

## 3. Neutral research questions

- **RQ1 -- Deterministic landscape.** Across the frozen 8,066 CVE-aligned
  NVD--GHSA record pairs, how are deterministic field statuses and routing
  outputs distributed for severity, affected versions, publication date, and
  references?
- **RQ2 -- Analyst decision construct.** To what extent do two independent
  trained analysts agree when assigning maintenance actions and, after action
  lock, discrepancy reasons to the same frozen field pairs, and where do they
  remain uncertain or disagree?
- **RQ3 -- Policy alignment and boundary.** Relative to a strong field-aware
  simple strategy, how do a current type-first strategy and an
  abstention-aware type-first strategy align with each analyst's actions, and
  what efficiency, coverage, abstention, and shared-miss boundaries are
  observed?

The wording deliberately asks `how` and `to what extent`. It does not presuppose
reliability, superiority, non-inferiority, safety, or workload reduction.

## 4. Candidate contributions and claim ceiling

| Candidate contribution | Evidence available now | Evidence still required | Maximum wording |
|---|---|---|---|
| Frozen field and policy census | E01, E07B | None for descriptive counts | A reproducible, snapshot-bounded census of 8,066 aligned rows and 32,264 four-field instances. |
| Three-strategy comparison design | E07B, E07D, E07E | E08/E09 for human-supported comparison | The strategies are frozen and make different outputs; no strategy is currently known to be more correct, efficient, or safe. |
| Action-first/reason-second analyst protocol | E07E, E07F | Valid independent returns and stage locks in E08 | A mechanically frozen V3.1 protocol and distribution gate, not a validated human construct. |
| Empirical policy alignment or boundary | None yet | E08 and E09 under all frozen gates | Promote only the branch licensed by both reviewers' results; preserve disagreement, uncertain, abstain, and failed gates. |
| Reconciliation-limit account | E04--E06 | None for the bounded retrospective account | Report tested cohort/protocol failures and evidence dependence; do not claim a successful adjudication method or a universal limit. |

Hard claim ceiling:

- no database-level accuracy, authority, or quality ranking;
- no human-gold wording before two real independent returns clear the frozen
  return and stage-lock gates;
- no practitioner framing: reviewers are doctoral-student trained analysts;
- no elapsed-time or labor-saving claim from routing counts;
- no policy superiority if reviewers disagree in direction or an interval/gate
  fails;
- no population miss-rate claim from the fixed 34-case falsification audit;
- no temporal-generalization claim from the current snapshot-external cohort;
- no `first discrepancy taxonomy` claim.

## 5. Result branches

### Branch P: positive, human-supported frontier

Use this branch only if both reviewers independently clear the frozen construct,
paired-direction, and `delta_manual=0.10` safety gates. The permitted conclusion
is that, **for the frozen sample and these trained analysts**, the tested
type-first strategy has a reviewer-consistent alignment/coverage trade-off
relative to the strong field-aware comparator. Report each reviewer separately,
then the agreed direction; do not convert manual-route counts into time or
deployment benefit.

### Branch B: boundary, ambiguity, or negative result

Use this branch if reliability is insufficient, reviewers prefer different
policies, fewer than the frozen positive-event floor are observed, either safety
gate fails, or systematic shared misses appear. The contribution becomes an
empirical boundary: deterministic discrepancy types and routing outputs do not
by themselves identify stable maintenance actions under the tested information
contract. Retain field-specific disagreements, abstentions, uncertain outcomes,
and failed gates. Do not add cases, drop fields, alter thresholds, or revise
policies after exposure to rescue Branch P.

### Common conclusion under either branch

The deterministic census remains descriptive and reproducible. The study can
still show where policies differ and which human-evidence conditions are needed
before those differences can support a maintenance recommendation.

## 6. Author-owned decisions

- select or revise one title candidate;
- approve the RQ wording and the trained-analyst scope;
- decide whether the retrospective reconciliation-limit section remains in the
  main paper or moves to supplementary material;
- after real returns, select Branch P or Branch B strictly from the frozen gates;
- approve author order, affiliations, funding, conflicts, CRediT, data/code,
  ethics wording, and the generative-AI declaration.

Until those decisions are recorded, the repository remains
`S1_EVIDENCE_LOCKED` with an S2 candidate and a non-authoritative zero draft.
