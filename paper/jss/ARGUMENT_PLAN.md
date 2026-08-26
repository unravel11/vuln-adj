# JSS Argument Plan

Status: `S2_ARGUMENT_LOCKED` on 2026-08-26. The title, result-neutral thesis,
RQ1--RQ3, exactly three contribution ceilings, section/figure-table plan,
related-work differential, non-claims, and dual-branch stop rule are locked.
Branch P/B selection and all E08/E09-dependent text remain unlocked.

The label-free routing census and V3.1 safety-identifiability audit have passed
their prepare-only gates. The packet, return, stage-lock, and evaluator workflow
is frozen. None of that is a positive empirical result: the argument remains
conditional on two independent human action/reason passes. Failed reliability,
conflicting reviewer preferences, safety-gate failures, abstention, and
uncertain cases must remain visible.

## Author-locked title

When Vulnerability Metadata Differ: A Human-Gated Study of Field-Level Routing
between NVD and GHSA

Rejected alternatives and the positive/boundary result branches are recorded in
`FRAMING_CANDIDATES_AND_RESULT_BRANCHES_20260825.md`. The title direction may not
change without reopening S2.

## Author-locked one-sentence thesis

For CVE-aligned NVD–GHSA record pairs, comparing a strong field-aware strategy
with type-first efficiency and safety variants reveals a deterministic routing
trade-off whose validity depends on whether two independent trained analysts can
reliably assign maintenance actions before assigning discrepancy reasons.

## Narrative spine

1. NVD and GHSA encode many aligned CVEs differently at the field level.
2. Raw or canonical non-equality collapses different maintenance actions and
   is therefore only a lower-reference comparator.
3. A strong field-aware simple strategy and two type-first variants provide
   materially different routings over the full frozen corpus.
4. The abstention-aware variant reduces the deterministic conflict queue but
   increases total manual routing, so the question is an efficiency-safety
   frontier rather than automatic workload reduction.
5. Two independent trained analysts assign actions before reasons on the same
   120 formal cases. Their pre-adjudication decisions determine whether a
   positive routing result, a decision-ambiguity result, or a no-go is honest.
6. Existing evidence-driven adjudication work remains a secondary account of
   evidence dependence and failure, not a successful method contribution.

Steps 5 and the positive interpretation of step 4 remain unobserved.

## Research questions and decision roles

### RQ1 — Deterministic landscape

Locked question: Across 8,066 CVE-aligned NVD–GHSA record pairs, how do
deterministic field statuses and frozen routing-policy outputs distribute for
severity, affected versions, publication date, and references?

Rhetorical job: establish the frozen corpus, deterministic statuses, policy
outputs, and policy-disagreement cells.

Admissible claim: snapshot-bounded counts and label-free identifiability.

Forbidden upgrade: human truth, correctness, unnecessary work, database
quality, or causal explanation.

### RQ2 — Human decision construct

Locked question: To what extent do two independent trained analysts agree when
assigning maintenance actions and, after action lock, discrepancy reasons to the
same frozen field pairs, and where do they remain uncertain or disagree?

Rhetorical job: test whether two real trained analysts can independently assign
maintenance actions and, after action lock, discrepancy reasons.

Admissible result after V3.1: raw agreement, nominal Krippendorff alpha,
abstention/uncertain rates, disagreement matrices, and cross-reviewer
action-reason association.

Forbidden upgrade: treating author-adjudicated agreement as independent
agreement or treating same-reviewer action-reason association as causal
explanation.

### RQ3 — Policy alignment and boundary

Locked question: Relative to a strong field-aware simple strategy, how do a
current type-first strategy and an abstention-aware type-first strategy align
with each analyst's actions, and what efficiency, coverage, abstention, and
shared-miss boundaries are observed?

Rhetorical job: compare `field_aware_simple_v1`,
`type_first_current_v1`, and `type_first_abstention_v1` against the two
independent human action passes.

Admissible result after V3.1: paired action-match differences on policy-
disagreement rows, exact McNemar discordance, conflict/manual-route coverage,
shared-no-manual misses, abstention, agreement-control failures, and
design-weighted sensitivity.

Forbidden upgrade: deployment benefit, elapsed-time savings, practitioner
relevance without practitioner reviewers, or superiority when reviewers favor
different policies.

## Author-locked contribution-to-evidence map

| Author-locked contribution | Required evidence | Current disposition |
|---|---|---|
| **C1. Reproducible four-field deterministic census** | E01, E07B | Available and bounded to the frozen snapshot/pipeline; no human evidence required for descriptive counts |
| **C2. Three-strategy comparison with explicit efficiency–safety accounting** | E07B plus E08/E09 for human alignment | Deterministic differences available; correctness, safety, and superiority remain absent |
| **C3. Action-first/reason-second dual-analyst protocol with a preserved boundary path** | E07D–E07F plus E08/E09 | Protocol and stop rules are frozen; human construct, policy alignment, and branch outcome remain missing |

E04--E06 remain supporting retrospective failure evidence rather than a fourth
contribution. The 34-case falsification audit is part of C2/C3's safety contract,
not a standalone empirical contribution before human returns.

## Section outline

1. Introduction
   - Define field observation, maintenance action, and abstention.
   - State the human gate and frontier framing; do not lead with superiority.
2. Background and Task Definition
   - Define CVE-aligned record, field instance, discrepancy reason, maintenance
     action, conflict escalation, abstention, and source adjudication.
   - Separate routing from choosing which database is factually correct.
3. Related Work
   - Compare cross-database inconsistency studies, VuldiffFinder,
     affected-version benchmarks, selective prediction, and human routing.
   - Position the differential as action-first routing plus a frozen strong
     comparator and explicit efficiency-safety accounting.
4. Corpus and Deterministic Policies
   - Describe inputs, CVE alignment, fields, normalization, seven frozen arms,
     and the label-free 8,066-row census.
5. Human Protocol
   - Describe evaluation-first stable-hash sampling, bounded two-round
     calibration, CVE-disjoint phases, action-stage lock, reason stage, dual
     independent review, recursive allowlist blinding, uncertainty, weights,
     the 34-case shared-no-manual audit, and stop rules.
6. RQ1 Results
   - Report deterministic status, policy-output, and disagreement counts only.
7. RQ2 Results
   - Report pre-adjudication action and reason reliability, uncertainty, and
     cross-reviewer associations.
8. RQ3 Results
   - Compare the three main policies on disagreement rows; keep agreement
     controls and weighted sensitivity separate.
9. Reconciliation Limits
   - Present older adjudication no-go and evidence-dependence findings without
     merging incompatible cohorts or label sources.
10. Discussion and Threats
    - Explain the frontier, field concentration, sampling design, reviewer
      role, source-blinding limits, action-reason anchoring, and snapshot scope.
11. Conclusion
    - Match only the result that survives the V3.1 gates.

## Figure and table plan

| Artifact | Question | Evidence | Gate |
|---|---|---|---|
| Figure 1: observation-to-action flow | Where do reason, action, abstention, and source adjudication differ? | Method contract | Conceptual only |
| Table 1: corpus and status counts | What deterministic field landscape was observed? | E01 | Snapshot-bounded |
| Table 2: policy-output and disagreement census | Where do the three main policies differ? | E07B | Label-free wording required |
| Figure 2: efficiency-safety frontier | How do conflict queue and total manual route differ? | E07B then E09 | Deterministic outputs before E09; no cost wording |
| Table 3: human reliability | Can analysts use action and reason constructs? | E08 | Show every field and uncertain outcome |
| Table 4: paired policy comparison | Which policies align with independent actions? | E09 | Reviewer-specific direction and CIs required |
| Table 4b: safety falsification and coverage | Do the policies share misses, and does type-first lose manual coverage? | E09 | Both reviewers separate; `delta_manual=0.10`; sample-conditional audit boundary |
| Table 5: bounded failure evidence | Where do existing reconciliation methods abstain or fail? | E05–E06 | Keep cohorts/provenance separate |

No temporal-generalization figure is planned. Add one only if a new eligible
bilateral post-freeze cohort is frozen under the existing rule.

## Estimand and reporting contract

- Primary routing evidence is the pre-adjudication paired comparison on formal
  policy-disagreement cases for reviewer A and reviewer B separately.
- Agreement controls are reported separately.
- Population weights are sensitivity analyses, with effective sample size and
  cell intervals; they are not the primary table.
- `conflict_escalation` and `abstain` are separate actions. Total manual route
  is their sum, not labor time.
- Author adjudication is secondary and is followed by an analysis excluding all
  adjudicated cases.
- Cross-reviewer action-reason association is primary for explanatory
  structure; same-reviewer association is an upper bound.
- A positive policy result requires consistent direction across both reviewers
  and the frozen interval/test gate.
- Positive efficiency-safety framing additionally requires at least 29 human
  conflict actions per reviewer, no lower type-first manual coverage, a
  one-sided simple-only loss upper bound below 0.10 for both reviewers, and no
  contradictory systematic failure.
- The 34-case shared-no-manual audit is a falsification opportunity, not a
  population miss-rate estimator. Otherwise use ambiguity or boundary framing.

## Related-work positioning contract

The manuscript must directly compare at least:

- the 2023 TOSEM aspect-level vulnerability database discrepancy study
  (DOI `10.1145/3624734`);
- VuldiffFinder's inconsistency categories and sample-based detection study;
- the affected-version tool benchmark identified by arXiv `2509.03876`;
- selective prediction/abstention and human-routing work inventoried in
  `docs/related_work_survey.md` and the per-paper notes.

The allowed differential is:

> A frozen, CVE-aligned, field-level comparison of maintenance-action policies
> using a strong field-aware comparator, explicit efficiency and safety arms,
> action-first/reason-second independent human judgments, and a preserved
> no-go path.

Publication-status refresh: the affected-version benchmark is now recorded as
an ASE 2025 Research Paper (DOI `10.1109/ASE63991.2025.00244`), and the GHSA
review-pipeline paper as an MSR 2026 Technical Paper (DOI
`10.1145/3793302.3793360`) with a public reproduction repository. These are
post-protocol metadata/positioning corrections and do not change V3.1.

## Writing order

1. Author-approve V3.1 guideline, reviewer roles, ethics/recruitment, and the
   calibration-1 action-only distribution revision.
2. Complete calibration-1; use the presealed calibration-2 reserve only under
   its frozen trigger.
3. Complete both independent formal passes after calibration clears.
4. Run pre-adjudication analyses and apply reliability, efficiency, and safety
   stop rules.
5. Choose positive-frontier, decision-ambiguity, or negative framing.
6. Draft Methods and Results, then Discussion and Threats.
7. Revise the existing Introduction and Related Work against the locked
   argument and observed result branch.
8. Keep the locked title; draft abstract, conclusion, highlights, and cover
   letter only after branch selection.

## S2 lock record and reopening rule

The author explicitly authorized a direct framing decision on 2026-08-26 after
a read-only Claude L1 challenge. The decisive review turn agreed that the
result-neutral architecture survives Branch P and Branch B; its model judgment
does not supply scientific evidence. The lock is recorded in
`FRAMING_LOCK_RECORD_20260826.md`.

S2 locks the title, thesis, RQ wording, four fields, three contribution ceilings,
explicit non-claims, three main policies, sampling/estimand contract, section and
figure-table roles, related-work differential, and dual-branch stop rule. It
does not lock RQ2/RQ3 findings, result headings, abstract, conclusion, branch
selection, reconciliation-limit placement, declarations, or submission status.

Reopen S2 if calibration-1 and the triggered calibration-2 both fail and show
that the unified action vocabulary is unstable across the four fields; in that
case revise RQ2/RQ3 from unified maintenance actions to field-specific
maintenance decisions and contract C3 accordingly. Also reopen under the normal
stage contract if the thesis, RQs, contribution ceiling, target venue, evidence
population, comparison set, or frozen protocol changes materially. Other
negative or mixed human outcomes select Branch B without reopening S2.
