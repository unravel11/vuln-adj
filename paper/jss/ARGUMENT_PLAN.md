# JSS Argument Plan

Status: `S2_ARGUMENT_LOCKED` on 2026-08-26 after an author-triggered
routing-centric rebalance. The title, thesis, RQ1--RQ3, exactly three
contribution ceilings, section/figure-table plan, related-work differential,
non-claims, and dual-branch stop rule are locked. Branch P/B selection and all
E08/E09-dependent text remain unlocked.

The label-free corpus and routing census answer RQ1/RQ2 at deterministic-output
strength. V3.1 packet, return, stage-lock, and evaluator mechanics are frozen,
but no human return exists. RQ3 therefore remains a validation gate rather than
the paper's primary object. Failed reliability, conflicting reviewer
directions, manual-loss failures, abstention, uncertainty, and shared misses
must remain visible.

## Author-locked title

When Vulnerability Metadata Differ: Routing Trade-Offs across Field-Level
NVD–GHSA Strategies

The title contains no human-identity component. Decision history and both result
branches are recorded in
`FRAMING_CANDIDATES_AND_RESULT_BRANCHES_20260825.md` and
`FRAMING_REBALANCE_LOCK_RECORD_20260826.md`. Changing the title direction
reopens S2.

## Author-locked one-sentence thesis

For CVE-aligned NVD–GHSA record pairs across four fields, three frozen routing
strategies produce different conflict-escalation, abstention, and total
manual-route allocations; independent trained-analyst judgments test whether
those deterministic differences correspond to differentiated maintenance
actions or expose an empirical decision boundary.

## Narrative spine

1. NVD and GHSA encode many CVE-aligned fields differently, but observed
   difference is not itself factual conflict or maintenance action.
2. RQ1 establishes the snapshot-bounded distribution of deterministic statuses
   for severity, affected versions, publication date, and references.
3. Raw or canonical non-equality collapses distinct actions and remains a
   lower-reference arm, not the main comparator.
4. RQ2 compares a strong field-aware simple strategy with current and
   abstention-aware type-first candidates. Fewer conflict escalations can
   coexist with more total manual routes once abstention is counted.
5. Those queue outputs do not establish correctness, safety, utility, workload,
   or superiority. RQ3 uses two independent trained analysts only to test
   strategy differentiation and identify bounded failure modes.
6. Valid human returns select either reviewer-consistent differentiation
   (Branch P) or a reliability/agreement/coverage/shared-miss/identifiability
   boundary (Branch B), without changing RQ1/RQ2.
7. Existing evidence-driven adjudication work remains a secondary account of
   evidence dependence and failure, not a successful method contribution.

Step 6 remains unobserved. Steps 1--4 are supported only at their deterministic
and snapshot-bounded claim ceiling.

## Research questions and decision roles

### RQ1 — Deterministic discrepancy landscape

Locked question: Across 8,066 CVE-aligned NVD–GHSA record pairs, how do
deterministic field statuses distribute for severity, affected versions,
publication date, and references?

Rhetorical job: establish the frozen population, four field contracts, and
status distribution before any routing comparison.

Admissible claim: snapshot- and pipeline-bounded status counts.

Forbidden upgrade: human truth, database quality, broader prevalence,
correctness, or causal explanation.

### RQ2 — Deterministic routing comparison

Locked question: How do three frozen routing strategies—a strong field-aware
simple comparator, a current type-first candidate, and an abstention-aware
type-first candidate—allocate field instances across actions, and where do
their conflict-escalation, abstention, and total manual-route outputs differ
across fields and statuses?

Rhetorical job: compare strategy outputs on the complete frozen corpus while
keeping conflict escalation, abstention, and total manual routing distinct.

Admissible claim: deterministic action counts, pairwise disagreements,
field/status concentration, and the 74-fewer-conflicts/950-more-manual-routes
queue-allocation trade-off.

Forbidden upgrade: correctness, unnecessary work, elapsed labor, safety,
utility, superiority, or operational preference.

### RQ3 — Analyst-bounded validation

Locked question: When two independent trained analysts assign maintenance
actions to the same frozen formal cases, do their judgments differentiate the
three routing strategies in a consistent direction, and where do reliability,
agreement, coverage, abstention, or shared-miss boundaries emerge?

Rhetorical job: test whether deterministic routing differences correspond to
reviewer-consistent maintenance-action distinctions or expose a bounded failure
under the frozen information contract.

Admissible result after valid E08/E09: reviewer-specific action distributions,
raw agreement and nominal Krippendorff alpha as validity diagnostics, paired
action-match differences, exact discordance, conflict/manual-route coverage,
abstention, shared-no-manual misses, reason diagnostics, and design-weighted
sensitivity.

Forbidden upgrade: human gold, practitioner consensus, deployment benefit,
elapsed-time savings, causal explanation from reason association, or superiority
when reviewer directions or frozen gates disagree.

## Author-locked contribution-to-evidence map

| Author-locked contribution | Required evidence | Current disposition |
|---|---|---|
| **C1. Reproducible four-field deterministic census** | E01, E07B | Available and bounded to the frozen snapshot/pipeline |
| **C2. Decision-oriented three-strategy routing comparison** | E07B | Deterministic queue outputs and disagreements available; no correctness, workload, safety, utility, or superiority claim |
| **C3. Sample- and analyst-bounded validation or decision boundary** | E07D–E07F for design; E08/E09 for outcome | Design frozen; every human-backed alignment or boundary result remains missing |

Action-first/reason-second ordering, blinding, and stop rules support C3 as
Method safeguards rather than a fourth or standalone protocol contribution.
E04--E06 remain supporting retrospective failure evidence.

## Section outline

1. Introduction
   - Define field observation, maintenance routing, and abstention.
   - Lead with deterministic routing comparison; present human judgment as the
     validation instrument.
2. Background and Task Definition
   - Define CVE-aligned record, field instance, discrepancy reason, maintenance
     action, conflict escalation, abstention, and source adjudication.
   - Separate routing from choosing which database is factually correct.
3. Related Work
   - Compare cross-database inconsistency studies, VuldiffFinder,
     affected-version benchmarks, selective prediction, and human routing.
   - Position the differential as decision-oriented routing with a strong
     comparator and explicit conflict/abstention/manual-route accounting.
4. Corpus and Deterministic Strategies
   - Describe inputs, CVE alignment, fields, normalization, seven frozen arms,
     and the label-free 8,066-row census.
5. Analyst-Bounded Validation Protocol
   - Describe evaluation-first stable-hash sampling, bounded two-round
     calibration, CVE-disjoint phases, action-stage lock, reason stage, dual
     independent review, recursive allowlist blinding, uncertainty, weights,
     the 34-case shared-no-manual audit, and stop rules.
6. RQ1 Results
   - Report deterministic field-status counts only.
7. RQ2 Results
   - Report deterministic action distributions, disagreements, and queue
     accounting only.
8. RQ3 Results
   - Report analyst validity diagnostics and reviewer-specific paired strategy
     comparisons; retain every failed gate and uncertain outcome.
9. Reconciliation Limits
   - Present older adjudication no-go and evidence-dependence findings without
     merging incompatible cohorts or label sources.
10. Discussion and Threats
    - Separate deterministic queue implications from human-backed or boundary
      interpretation; preserve snapshot and analyst scope.
11. Conclusion
    - Restate RQ1/RQ2 at deterministic strength, then only the RQ3 branch that
      survives the frozen gates.

## Figure and table plan

| Artifact | Question | Evidence | Gate |
|---|---|---|---|
| Figure 1: observation-to-action flow | Where do status, action, abstention, and source adjudication differ? | Method contract | Conceptual only |
| Table 1: corpus and status counts | What deterministic discrepancy landscape was observed? | E01 | RQ1, snapshot-bounded |
| Table 2: strategy-output and disagreement census | Where do the three strategies allocate cases differently? | E07B | RQ2, label-free wording required |
| Figure 2: queue-allocation trade-off | How do conflict escalation and total manual route move across strategies? | E07B | RQ2; no safety, cost, or preference wording |
| Table 3: analyst validity diagnostics | Can the action construct support the frozen comparison? | E08 | RQ3; show both reviewers, every field, abstain/uncertain |
| Table 4: reviewer-specific paired comparison | Do analyst actions differentiate strategies consistently? | E09 | RQ3; reviewer-specific directions and intervals |
| Table 4b: manual-loss and shared-miss audit | Where do coverage or shared-blind-spot gates fail? | E09 | RQ3; both reviewers separate; sample-conditional boundary |
| Table 5: bounded failure evidence | Where do older reconciliation methods abstain or fail? | E05–E06 | Keep cohorts/provenance separate |

No temporal-generalization figure is planned. Add one only if a new eligible
bilateral post-freeze cohort is frozen under the existing rule.

## Estimand and reporting contract

- RQ1/RQ2 use the complete frozen corpus and report deterministic outputs only.
- Primary RQ3 evidence is the pre-adjudication paired comparison for reviewer A
  and reviewer B separately; reviewer results are not pooled to manufacture a
  direction.
- Agreement, uncertainty, and reason coding are RQ3 validity diagnostics, not a
  standalone RQ or contribution.
- Population weights are sensitivity analyses with effective sample size and
  cell intervals; they are not the primary table.
- `conflict_escalation` and `abstain` are separate actions. Total manual route
  is their sum, not labor time.
- Author adjudication is secondary and is followed by an analysis excluding all
  adjudicated cases.
- Cross-reviewer action-reason association is primary for reason diagnostics;
  same-reviewer association is an upper bound, never causal evidence.
- Branch P requires consistent paired direction across both reviewers and every
  frozen reliability, event-floor, coverage, and manual-loss gate.
- The 34-case shared-no-manual audit is a falsification opportunity, not a
  population miss-rate estimator. A failure selects Branch B.

## Related-work positioning contract

The manuscript must directly compare at least:

- the 2023 TOSEM aspect-level vulnerability-database discrepancy study
  (DOI `10.1145/3624734`);
- VuldiffFinder's inconsistency categories and sample-based detection study;
- the affected-version tool benchmark identified by DOI
  `10.1109/ASE63991.2025.00244`;
- selective prediction/abstention and human-routing work inventoried in
  `docs/related_work_survey.md` and the per-paper notes.

The allowed differential is:

> A frozen, CVE-aligned, field-level comparison of maintenance-routing
> strategies using a strong field-aware comparator, explicit conflict,
> abstention, and total-manual-route accounting, and a sample-bounded
> trained-analyst validation that preserves either alignment or boundary.

This is a task-contract differential, not proof that prior work lacks all
routing, discrepancy, abstention, or human-evaluation ideas. Publication-status
metadata refreshed after protocol freeze does not change V3.1.

## Writing order

1. Keep the deterministic RQ1/RQ2 zero-draft results synchronized with E01/E07B.
2. While human work is paused, complete only result-independent manuscript and
   artifact preparation.
3. When authorized, complete calibration-1; use the presealed calibration-2
   reserve only under its frozen trigger.
4. Complete both independent formal passes only after calibration clears.
5. Run pre-adjudication analyses and apply every frozen RQ3 stop rule.
6. Select Branch P or B without changing RQ1/RQ2, then draft RQ3, Discussion,
   abstract, conclusion, and highlights.
7. Revise Introduction and Related Work against the selected branch, keeping the
   locked title and claim ceiling.

## S2 lock record and reopening rule

The first 2026-08-26 human-centered lock is preserved as superseded history in
`FRAMING_LOCK_RECORD_20260826.md`. The author then challenged the human emphasis
and authorized a fresh `claude-opus-5` Max review. Its final
`ACCEPT_CORRECTIONS` verdict and the synchronized replacement lock are recorded
in `FRAMING_REBALANCE_LOCK_RECORD_20260826.md`. Neither model exchange supplies
scientific or human evidence.

S2 locks the title, thesis, RQ wording, four fields, three contribution ceilings,
explicit non-claims, three main strategies, sampling/estimand contract, section
and figure-table roles, related-work differential, and dual-branch stop rule. It
does not lock RQ3 findings, result-dependent headings, abstract, conclusion,
branch selection, reconciliation-limit placement, declarations, or submission
status.

Reopen S2 if calibration-1 and triggered calibration-2 both fail and show that
the unified action vocabulary is unstable across the four fields; then revise
RQ3 to field-specific maintenance decisions and contract C3. Also reopen under
the normal stage contract if the thesis, RQs, contribution ceiling, venue,
population, comparison set, or frozen protocol changes materially. Other
negative or mixed human outcomes select Branch B without reopening S2.
