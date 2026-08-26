# JSS Framing Candidates and Result-Neutral Branches

**Status**: `AUTHOR_LOCKED_RESULT_NEUTRAL_S2` as of 2026-08-26. The title,
one-sentence thesis, RQ1--RQ3, exactly three contribution ceilings, explicit
non-claims, and the dual result-branch contract are locked. The empirical
selection of Branch P or Branch B remains blocked on E08/E09.

**Decision record**: `paper/jss/FRAMING_LOCK_RECORD_20260826.md`. The author
explicitly delegated the framing decision after a read-only Claude L1 challenge;
the model review is advisory governance evidence, not scientific evidence.

**Evidence cutoff**: repository evidence through 2026-08-25 and a post-protocol
publication-status refresh on 2026-08-25. The refresh did not alter the frozen
V3.1 sample, policies, thresholds, packet, evaluator, or tag.

## 1. Author-locked result-neutral center

**Author-locked one-sentence thesis:** For CVE-aligned NVD–GHSA record pairs,
comparing a strong field-aware strategy with type-first efficiency and safety
variants reveals a deterministic routing trade-off whose validity depends on
whether two independent trained analysts can reliably assign maintenance
actions before assigning discrepancy reasons.

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

## 2. Title decision

| ID | Candidate title | Best fit | Risk / author decision |
|---|---|---|---|
| T1 | From Field Mismatch to Maintenance Action: Auditing NVD--GHSA Reconciliation Policies under Human Uncertainty | Neutral default | `Auditing` is accurate; `reconciliation` must not imply that the study selects factual truth. |
| T2 | When Vulnerability Metadata Differ: A Human-Gated Study of Field-Level Routing between NVD and GHSA | Strongest result-neutral wording | `Human-gated` is unusual but makes the missing evidence visible. |
| T3 | Field-Level Vulnerability Metadata Routing under Analyst Disagreement and Abstention | Boundary branch | Less specific in the title; NVD--GHSA must then be explicit in the abstract. |
| T4 | Comparing Field-Aware and Type-First Routing for NVD--GHSA Metadata Differences | Positive branch only after both reviewer-specific gates pass | Do not use a superiority verb such as `improves`, `reduces`, or `outperforms`. |

**Author-locked title: T2 -- _When Vulnerability Metadata Differ: A Human-Gated
Study of Field-Level Routing between NVD and GHSA_.** T1, T3, and T4 are retained
only as rejected decision history. Changing the title direction reopens S2.

## 3. Author-locked neutral research questions

- **RQ1 -- Deterministic landscape.** Across 8,066 CVE-aligned NVD–GHSA record
  pairs, how do deterministic field statuses and frozen routing-policy outputs
  distribute for severity, affected versions, publication date, and references?
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

## 4. Author-locked contributions and claim ceiling

| Author-locked contribution | Evidence available now | Evidence still required | Maximum wording |
|---|---|---|---|
| **C1. Reproducible four-field deterministic census.** | E01, E07B | None for descriptive counts | A snapshot- and pipeline-bounded census of 8,066 CVE-aligned pairs and 32,264 field instances, with deterministic statuses and routing outputs. No database-quality, ground-truth, broader-prevalence, causal, or correctness claim. |
| **C2. Three-strategy comparison with explicit efficiency--safety accounting.** | E07B | E08/E09 for human-supported alignment | A frozen strong field-aware comparator, type-first efficiency arm, and abstention-aware safety arm whose deterministic outputs differ. The observed 74-fewer-conflict/950-more-manual-route contrast is not correctness, workload, safety, or superiority. |
| **C3. Action-first/reason-second dual-analyst protocol with a preserved boundary path.** | E07D, E07E, E07F | E08/E09 for construct reliability, policy alignment, and branch selection | A mechanically frozen V3.1 protocol, blinding and stage-lock chain, and outcome-independent stop rules. Valid returns license either Branch P or Branch B; before them there is no construct-validity, reliability, policy-utility, or submission-readiness claim. |

The retrospective reconciliation-limit material in E04--E06 is supporting
discussion evidence, not a fourth contribution. Human-backed policy alignment
or an empirical boundary is the result disposition of C2/C3, not an additional
contribution counted before results.

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

## 6. Remaining author-owned decisions

- decide whether the retrospective reconciliation-limit section remains in the
  main paper or moves to supplementary material;
- after real returns, select Branch P or Branch B strictly from the frozen gates;
- approve author order, affiliations, funding, conflicts, CRediT, data/code,
  ethics wording, and the generative-AI declaration.

The repository is `S2_ARGUMENT_LOCKED`. This lock does not approve the zero-draft
prose, supply E08/E09, select a result branch, or establish submission readiness.
If the frozen calibration process shows that the unified action vocabulary is
not stable across the four fields, or if the thesis, RQs, contribution ceiling,
target venue, evidence population, or comparison set changes materially, reopen
S2 rather than silently rewriting the lock.
