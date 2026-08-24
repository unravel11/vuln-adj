# JSS Argument Plan

Status: `S2_CANDIDATE_FOR_AUTHOR_APPROVAL`.

The label-free routing census has passed the packet-design gate. That is not a
positive empirical result: the argument remains conditional on two independent
human action/reason passes. Failed reliability, conflicting reviewer
preferences, abstention, and uncertain cases must remain visible.

## Working title

From Field Mismatch to Maintenance Action: Auditing NVD–GHSA Reconciliation
Policies under Human Uncertainty

## One-sentence candidate argument

A CVE-aligned field mismatch is not itself a conflict verdict; comparing a
strong field-aware strategy with efficiency- and safety-oriented type-first
policies reveals a testable routing frontier whose validity depends on
independent human actions and explicit abstention.

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

Rhetorical job: establish the frozen corpus, deterministic statuses, policy
outputs, and policy-disagreement cells.

Admissible claim: snapshot-bounded counts and label-free identifiability.

Forbidden upgrade: human truth, correctness, unnecessary work, database
quality, or causal explanation.

### RQ2 — Human decision construct

Rhetorical job: test whether two real trained analysts can independently assign
maintenance actions and, after action lock, discrepancy reasons.

Admissible result after V3: raw agreement, nominal Krippendorff alpha,
abstention/uncertain rates, disagreement matrices, and cross-reviewer
action-reason association.

Forbidden upgrade: treating author-adjudicated agreement as independent
agreement or treating same-reviewer action-reason association as causal
explanation.

### RQ3 — Routing frontier

Rhetorical job: compare `field_aware_simple_v1`,
`type_first_current_v1`, and `type_first_abstention_v1` against the two
independent human action passes.

Admissible result after V3: paired action-match differences on policy-
disagreement rows, conflict-escalation behavior, abstention, agreement-control
failures, and design-weighted sensitivity.

Forbidden upgrade: deployment benefit, elapsed-time savings, practitioner
relevance without practitioner reviewers, or superiority when reviewers favor
different policies.

## Contribution-to-evidence map

| Candidate contribution | Required evidence | Current disposition |
|---|---|---|
| Frozen-corpus field and policy census | E01, E07B | Available and bounded |
| Strong-comparator efficiency-safety framing | E07B | Policy differences supported; correctness absent |
| Action-first/reason-second human construct | E07C plus E08 | Blank packet ready; human evidence missing |
| Human-backed routing-policy frontier | E08 plus E09 | Missing |
| Auditable reconciliation limits | E04–E06 | Available only as retrospective negative/failure evidence |

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
   - Describe evaluation-first stable-hash sampling, constructed calibration,
     action-stage lock, reason stage, dual independent review, blinding,
     uncertainty, weights, and stop rules.
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
    - Match only the result that survives the V3 gates.

## Figure and table plan

| Artifact | Question | Evidence | Gate |
|---|---|---|---|
| Figure 1: observation-to-action flow | Where do reason, action, abstention, and source adjudication differ? | Method contract | Conceptual only |
| Table 1: corpus and status counts | What deterministic field landscape was observed? | E01 | Snapshot-bounded |
| Table 2: policy-output and disagreement census | Where do the three main policies differ? | E07B | Label-free wording required |
| Figure 2: efficiency-safety frontier | How do conflict queue and total manual route differ? | E07B then E09 | Deterministic outputs before E09; no cost wording |
| Table 3: human reliability | Can analysts use action and reason constructs? | E08 | Show every field and uncertain outcome |
| Table 4: paired policy comparison | Which policies align with independent actions? | E09 | Reviewer-specific direction and CIs required |
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
  and the frozen interval/test gate. Otherwise use ambiguity or boundary
  framing.

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

## Writing order

1. Freeze the V3 evaluator and distribution controls.
2. Complete calibration and both independent formal passes.
3. Run pre-adjudication analyses and apply stop rules.
4. Choose positive-frontier, decision-ambiguity, or negative framing.
5. Draft Methods and Results, then Discussion and Threats.
6. Draft Introduction and Related Work.
7. Draft title, abstract, conclusion, highlights, and cover letter last.

## S2 lock gate

The argument can move to `S2_ARGUMENT_LOCKED` only when:

- the author approves the title direction, revised RQs, four fields, and
  explicit non-claims;
- the V3 protocol, action/reason vocabulary, three main policies, sampling
  cells, estimands, and stop rules are approved before human exposure;
- the evaluator and return validators are frozen;
- adjudication is recorded as secondary rather than a method rescue; and
- no closest-related-work finding invalidates the differential.

If V3 reliability or paired policy utility fails, the positive route stops.
The paper may continue only with the failure retained and the thesis revised.
