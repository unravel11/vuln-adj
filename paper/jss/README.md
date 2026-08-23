# JSS Paper Workspace

## Status

- Paper line: active, conservative JSS reframing
- Repository branch: `codex/jss-framing-b-20260823`
- Current paper stage: `S1_EVIDENCE_LOCKED`
- Argument stage: `S2 candidate`, not yet locked
- Submission readiness: `false`
- Primary venue: Journal of Systems and Software, conditional on T1 and T2
- Practical fallback: Information and Software Technology

The 2026-07-19 COSE package remains a historical evidence line. It is not the
editable authority for this JSS paper, and its `127/127` mechanical checks do
not clear the missing real-human, scientific, manuscript, or metadata gates.

## Working framing

Working title:

> Beyond Binary Mismatch: An Empirical Audit of Field-Level Reconciliation
> between NVD and GHSA

Candidate thesis:

> For CVE-aligned NVD and GHSA records, a binary mismatch flag is not yet a
> validated conflict decision. A type-first, abstention-aware evaluation can
> distinguish operationally different cases and make explicit when automated
> reconciliation is unsupported or empirically unidentifiable.

The thesis is deliberately conditional. The taxonomy and downstream-routing
parts require independent real-human evidence before they can become paper
claims.

## Workspace map

- `PAPER_BRIEF.md`: target, candidate thesis, RQs, contribution ceiling, and
  experiment decision
- `EVIDENCE_LEDGER.md`: current, retrospective, candidate, invalid, and
  missing evidence
- `CLAIM_LEDGER.md`: exact permitted and prohibited claim upgrades
- `ARGUMENT_PLAN.md`: S2 candidate narrative, section jobs, and figure/table
  plan
- `SUBMISSION_BLOCKERS.md`: scientific, manuscript, artifact, metadata, and
  external-action blockers
- `paper_state.json`: machine-checkable workflow state

The result-independent T1 protocol is maintained at
`experiments/rq2_discrepancy_typing/T1_HUMAN_VALIDATION_PROTOCOL.md`.

## Route decision

1. Run T1 with two different real reviewers on a baseline-blinded packet.
2. Freeze adjudicated human labels without dropping uncertain or failed fields.
3. Run T2 to compare binary escalate-all routing with type-first routing.
4. Keep the existing affected-version adjudication work only as bounded
   negative/failure evidence unless a separately frozen human-backed T3 is
   authorized.
5. Do not claim temporal generalization unless a new bilateral post-freeze
   cohort becomes eligible under the already frozen event-time rule.

Stop the positive-method route if T1 does not establish construct reliability
or if T2 does not show downstream value. Preserve either result and reframe as
a construct-ambiguity or negative empirical study instead of changing labels,
fields, thresholds, or cohorts after seeing outcomes.
