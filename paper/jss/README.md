# JSS Paper Workspace

## Status

- Paper line: active, conservative JSS reframing
- Active writing branch: `codex/jss-zero-draft-venue-20260825`
- Frozen distribution parent: `codex/jss-v3-1-calibration1-distribution-20260825`
- Current paper stage: `S1_EVIDENCE_LOCKED`
- Argument stage: `S2 candidate`, not yet locked
- Draft: result-neutral English zero draft present; not author approved and not
  an S3 gate
- Submission readiness: `false`
- Primary venue: Journal of Systems and Software, conditional on V3.1 human
  construct and routing-frontier results
- Practical fallback: Information and Software Technology

The 2026-07-19 COSE package remains a historical evidence line. It is not the
editable authority for this JSS paper, and its `127/127` mechanical checks do
not clear the missing real-human, scientific, manuscript, or metadata gates.

## Working framing

Working title:

> From Field Mismatch to Maintenance Action: Auditing NVD–GHSA Reconciliation
> Policies under Human Uncertainty

Candidate thesis:

> A CVE-aligned field mismatch is not itself a conflict verdict; comparing a
> strong field-aware strategy with efficiency- and safety-oriented type-first
> policies reveals a testable routing frontier whose validity depends on
> independent human actions and explicit abstention.

The thesis is deliberately conditional. The taxonomy and downstream-routing
parts require independent real-human evidence before they can become paper
claims.

## Workspace map

- `PAPER_BRIEF.md`: target, candidate thesis, RQs, contribution ceiling, and
  experiment decision
- `EVIDENCE_LEDGER.md`: current, retrospective, candidate, invalid, and
  missing evidence
- `CLAIM_LEDGER.md`: exact permitted and prohibited claim upgrades
- `QUESTION_FINDING_LEDGER.json`: reviewer challenges, evidence,
  authorization status, and stop conditions
- `ARGUMENT_PLAN.md`: S2 candidate narrative, section jobs, and figure/table
  plan
- `FRAMING_CANDIDATES_AND_RESULT_BRANCHES_20260825.md`: title/RQ/contribution
  candidates, claim ceiling, and positive/boundary branches
- `manuscript.md`: non-authoritative zero draft with explicit RQ2/RQ3
  placeholders
- `JSS_SUBMISSION_CHECKLIST_20260825.md`: official-guide requirements checked
  on 2026-08-25 and project dispositions
- `SUBMISSION_BLOCKERS.md`: scientific, manuscript, artifact, metadata, and
  external-action blockers
- `paper_state.json`: machine-checkable workflow state

The label-free gate and active V3.1 human protocol are maintained at
`experiments/rq2_discrepancy_typing/T1_ROUTING_PRECHECK_PROTOCOL_V1.md` and
`experiments/rq2_discrepancy_typing/T1_HUMAN_VALIDATION_PROTOCOL_V3_1.md`.
The active blank packets are frozen at
`data/annotations/rq2/t1_human_validation_v3_1/`. Their manifest explicitly
sets `distribution_allowed=false` and `human_labels=0`. V2 and V3 are
retained unchanged as historical prepare-only material and must not be
distributed for this route.

The active post-freeze distribution gate is maintained at
`data/annotations/rq2/t1_human_validation_v3_1_distribution_r2/`. The author
attests that two different doctoral students will review independently without
AI; no practitioner expertise is claimed, and the author-side conditions were
not independently verified by Codex. R2 readiness is `READY`; separate
calibration-1 action-only bundles have been generated and validated. No return
or real-human label has yet been received. Detailed R1 was superseded before it
generated any case bundle.

## Route decision

1. Keep the already frozen V3.1 return, stage-lock, and evaluator code unchanged
   after reviewer exposure.
2. Approve the guideline, two reviewer roles, ethics/recruitment disposition, and a
   separate distribution manifest revision.
3. Run two independent trained analysts on calibration-1 action then reason.
   Use the presealed, CVE-disjoint calibration-2 reserve only if the frozen
   agreement/material-change trigger fires.
4. If calibration clears, run the same two analysts action-first and
   reason-second on the 120 formal cases, locking each action stage first.
5. Freeze pre-adjudication evidence without dropping abstain, uncertain,
   disagreement, or failed fields; then apply the frozen stop rules.
6. Compare the strong field-aware comparator, current type-first efficiency
   arm, and abstention-aware safety arm against both independent action passes.
   Positive framing requires both reviewers to clear the reviewer-specific
   `delta_manual=0.10` safety gate; otherwise use the boundary route.
7. Keep the existing affected-version adjudication work only as bounded
   negative/failure evidence unless a separately frozen human-backed T3 is
   authorized.
8. Do not claim temporal generalization unless a new bilateral post-freeze
   cohort becomes eligible under the already frozen event-time rule.

Stop the positive-method route if V3.1 does not establish construct reliability,
if both reviewers do not support the same paired policy direction, or if either
reviewer fails the frozen safety gate. Preserve the result and reframe as a
decision-ambiguity or negative empirical study instead of changing labels,
fields, policies, thresholds, or cohorts after seeing outcomes.
