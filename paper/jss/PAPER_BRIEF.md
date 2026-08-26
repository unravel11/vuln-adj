# Paper Brief

## Identity and authority

- Paper ID: `vuln-adj-jss-type-first-audit-v1`
- Target venue: Journal of Systems and Software, conditional route
- Fallback venue: Information and Software Technology
- Repository authority:
  `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`
- Active writing branch: `codex/jss-zero-draft-venue-20260825`
- Writing branch base verified at start:
  `f41ba54637d185845610c6f700cc82a453bf0916` on 2026-08-25;
  `hostname=code-defender`, authoritative path matched, worktree was clean,
  and upstream divergence was `0/0` before branch creation
- V3.1 evidence/tooling freeze commit:
  `d664f90dce37cfdadd14c399803d7caca8fcf046`
- New-paper authority: this `paper/jss/` workspace
- Historical source line: `paper/cose/`, retained but not edited as the JSS
  manuscript
- Author-locked title: _When Vulnerability Metadata Differ: Routing Trade-Offs
  across Field-Level NVD–GHSA Strategies_
- Current stage: `S2_ARGUMENT_LOCKED`
- Draft status: result-neutral Markdown and editable `elsarticle` zero draft
  present; deterministic tables, checked BibTeX, no-human manifest, clean
  temporary build, and full-page visual QA exist; not author approved and not
  sufficient to advance the S3 gate
- Submission ready: no

## Author-locked one-sentence thesis

For CVE-aligned NVD–GHSA record pairs across four fields, three frozen routing
strategies produce different conflict-escalation, abstention, and total
manual-route allocations; independent trained-analyst judgments test whether
those deterministic differences correspond to differentiated maintenance
actions or expose an empirical decision boundary.

This routing-centric thesis was author-locked on 2026-08-26 after a fresh
read-only Claude Opus Max challenge recorded in
`FRAMING_REBALANCE_LOCK_RECORD_20260826.md`. The first lock is retained as
superseded history in `FRAMING_LOCK_RECORD_20260826.md`. Neither model review is
scientific evidence. The frozen label-free census establishes only that the
policies make different decisions; it does not establish that any policy is
correct, safer, cheaper, or superior.

## Research questions

- RQ1 — Deterministic discrepancy landscape: Across 8,066 CVE-aligned
  NVD–GHSA record pairs, how do deterministic field statuses distribute for
  severity, affected versions, publication date, and references?
- RQ2 — Deterministic routing comparison: How do three frozen routing
  strategies—a strong field-aware simple comparator, a current type-first
  candidate, and an abstention-aware type-first candidate—allocate field
  instances across actions, and where do their conflict-escalation, abstention,
  and total manual-route outputs differ across fields and statuses?
- RQ3 — Analyst-bounded validation: When two independent trained analysts
  assign maintenance actions to the same frozen formal cases, do their
  judgments differentiate the three routing strategies in a consistent
  direction, and where do reliability, agreement, coverage, abstention, or
  shared-miss boundaries emerge?

The exact current 2026-08-26 lock, title history, and positive/boundary result
branches are maintained in
`FRAMING_CANDIDATES_AND_RESULT_BRANCHES_20260825.md`. Branch selection remains
unlocked until valid E08/E09 results clear or fail the frozen gates.

`cwe_ids` is outside the V3.1 human routing study. Existing CWE work remains
retrospective or supplementary evidence and cannot repair a failed primary
field.

## Author-locked contributions mapped to evidence

1. **Reproducible four-field deterministic census.** A snapshot- and
   pipeline-bounded census of 8,066 CVE-aligned NVD–GHSA pairs and 32,264 field
   instances, with deterministic statuses for severity, affected versions,
   publication date, and references.
2. **Decision-oriented three-strategy routing comparison.** A frozen comparison
   with explicit conflict-escalation, abstention, and total-manual-route
   accounting. The 74-fewer-conflicts/950-more-manual-routes contrast is a
   deterministic queue-allocation result, not correctness, workload, safety,
   utility, or superiority.
3. **Sample- and analyst-bounded validation or decision boundary.** Two
   independent trained analysts work under frozen calibration, action-stage
   lock, recursive blinding, formal-sample, and stop-rule gates. Valid E08/E09
   can support either reviewer-consistent strategy differentiation or an
   observed reliability, agreement, coverage, abstention, shared-miss, or
   identifiability boundary; no human-backed outcome exists yet.

Action-first/reason-second ordering is an essential Method safeguard for
contribution 3, not a standalone research contribution.

## Frozen policy interpretation

- `field_aware_simple_v1` is the main strong comparator. It is a hand-written
  field-specific strategy, not a claim about actual maintainer practice.
- `type_first_current_v1` is the current type-first candidate.
- `type_first_abstention_v1` is the abstention-aware type-first candidate.
- raw and canonical non-equality are lower-reference arms only.
- `conflict_escalation` is the conflict queue.
- `conflict_escalation + abstain` is the total manual-review route.

On the 8,066-row label-free census, the simple and abstention-aware policies
differ on 2,332 field actions. The abstention-aware policy produces 74 fewer
conflict escalations but 950 more total manual-review routes than the simple
comparator. These are deterministic policy outputs, not unnecessary work or
saved labor. They establish a deterministic queue-allocation trade-off; they do
not support a workload-reduction, safety, utility, or superiority claim.

## Explicit non-claims

- No claim that NVD or GHSA is globally more accurate, authoritative, timely,
  or complete.
- No claim that deterministic discrepancy statuses or policy actions are
  ground truth.
- No human-gold, accuracy, policy-superiority, workload-reduction, or
  submission-readiness claim from the label-free census or blank packets.
- No claim that the strong simple policy represents observed industry
  practice.
- No use of same-model or Codex reviews as independent human review.
- No claim that the current affected-version adjudication work improves on
  named baselines; retain it as bounded no-go/failure evidence.
- No future-snapshot or temporal-generalization claim from the current
  snapshot-external cohort.
- No “first discrepancy taxonomy” claim; closest prior work already studies
  vulnerability-database inconsistencies.

## Evidence snapshot

- Frozen field view:
  `data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`
  - rows: 8,066;
  - field instances used by the V3.1 route: 32,264;
  - SHA-256:
    `c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2`.
- Label-free routing precheck:
  `results/jss/t1_routing_precheck_v1/`
  - decision: `CONDITIONAL_GO_FOR_V3_PACKET_DESIGN`;
  - five label-free gates: pass;
  - action disagreements, simple versus abstention-aware: 2,332;
  - analysis SHA-256:
    `47428580744f0d83331c15b82a623a771f40a40d1ddcf59731fd83787553f7a8`.
- V3.1 prepare-only packet:
  `data/annotations/rq2/t1_human_validation_v3_1/`
  - unique cases: 160;
  - calibration-1/calibration-2 reserve/formal: 20/20/120;
  - formal allocation: severity 50, affected versions 50, published 10,
    references 10;
  - all phase CVE-ID sets are internally unique and pairwise disjoint;
  - two independent reviewer orders and separate action/reason stages;
  - recursive object-level key allowlists and a permanent exclusion for the
    historical `rq2_primary.review.jsonl` candidate packet;
  - manifest SHA-256:
    `5833698444c9bf835cd82a6706326a91988804a14e24af4d6ee3ba29b433e893`;
  - integrity validator: pass;
  - distribution-ready validator: expected refusal;
  - `distribution_allowed=false`; real-human labels: 0.
- V3.1 label-free safety-identifiability audit:
  `results/jss/t1_v31_safety_identifiability/`
  - fixed shared-no-manual audit: 34 formal cases (15 severity, 19 affected
    versions);
  - zero-event combined one-sided 95% upper: 0.0843, sample-conditional only;
  - selected manual-loss margin: 0.10;
  - per-reviewer conflict-action floor: 25 to rank/report, 29 for positive
    framing when the exact upper bound also clears 0.10;
  - analysis SHA-256:
    `fd0b1c97fce376b4993e287eb00d4868cd9a13624473c93d31eaa7a170dbff40`.
- V3 packet:
  `data/annotations/rq2/t1_human_validation_v3/`
  - retained unchanged as superseded prepare-only provenance;
  - must not be distributed for the active route.
- V2 packet:
  `data/annotations/rq2/t1_human_validation_v2/`
  - retained unchanged as historical prepare-only material;
  - must not be distributed for the active low-human route.
- Historical COSE package:
  `results/paper_cose/cose_package_manifest.json`
  - mechanical snapshot only;
  - `submission_ready=false`.
- Result-independent JSS package:
  `paper/jss/ARTIFACT_MANIFEST.json`
  - exact RQ1/RQ2 CSV and editable LaTeX tables regenerate from E07B;
  - citation-to-BibTeX closure covers 17 cited sources under explicit evidence
    ceilings;
  - `elsarticle` 3.5 compiles a temporary 22-page PDF with no matched warnings
    or overfull boxes; all pages were visually inspected;
  - `contains_human_results=false`, `human_labels=0`, and
    `submission_ready=false`.

## Experiment decision

Decision: `V3_1_PREPARATION_COMPLETE_DISTRIBUTION_BLOCKED`;
`NO_GO_FOR_SUBMISSION`.

- The label-free gates were strong enough to justify V3.1 packet and evaluator
  freeze, not a positive result.
- One bounded V3.1 human process supplies both action and reason labels; there is no second
  separately recruited T2 annotation study.
- Analysis/evaluator implementation is frozen and has passed mechanical
  end-to-end testing with temporary synthetic labels. Before distribution,
  approve the guideline, document two real trained analysts and
  ethics/recruitment, and create an explicitly scoped manifest revision.
- Positive reviewer-consistent strategy differentiation requires both reviewers
  to pass the reliability, same-direction paired comparison, event-floor,
  coverage, and `delta_manual=0.10` manual-loss gates. Failure automatically
  selects the boundary/ambiguity route.
- Preserve action/reason disagreement, abstention, and uncertainty. Author
  adjudication is secondary and policy-blinded.
- Decide positive frontier versus decision-ambiguity framing only after both
  independent formal passes are frozen.
- Existing adjudication work stays secondary failure evidence unless a new,
  separately authorized human-backed comparison is justified.

## Author-owned unresolved decisions

- Recruit two different qualified real trained analysts and document whether
  either is an actual maintenance practitioner.
- Record expertise, compensation, conflicts, recruitment, and any required
  institutional ethics determination before distribution.
- Approve the V3.1 guideline and distribution revision after verifying packet
  hashes.
- Recheck complete current JSS author and artifact requirements before the
  submission stages.
- Approve or revise the Markdown/LaTeX zero draft and checked cited subset; the
  current source intentionally withholds RQ3 results, the final abstract, and
  the conclusion branch.
