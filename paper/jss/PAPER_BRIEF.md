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
- Current stage: `S1_EVIDENCE_LOCKED`; S2 argument remains conditional
- Draft status: result-neutral zero draft present; not author approved and not
  sufficient to advance the S2 or S3 gate
- Submission ready: no

## Candidate thesis (not `AUTHOR_LOCKED`)

For CVE-aligned NVD and GHSA records, a field mismatch is an observation, not a
maintenance decision. The paper tests whether field-aware and type-first
policies occupy a reproducible efficiency-safety frontier when two independent
trained analysts assign maintenance actions first and discrepancy reasons
second.

This remains a candidate thesis. The frozen label-free census establishes that
the policies make different decisions and that the fixed human budget can
sample those differences. It does not establish that any policy is correct,
safer, cheaper, or superior.

## Research questions

- RQ1 — Deterministic landscape: Across 8,066 CVE-aligned NVD–GHSA rows, how
  do field statuses and frozen routing-policy outputs distribute for severity,
  affected versions, publication date, and references?
- RQ2 — Human decision construct: How consistently do two independent trained
  analysts assign maintenance actions and, after action lock, discrepancy
  reasons to a frozen sample of field pairs?
- RQ3 — Routing frontier: Relative to a strong field-aware simple policy, how
  do the current type-first efficiency arm and the abstention-aware safety arm
  align with independent human actions, including conflict escalation,
  abstention, and field-specific failure?

The 2026-08-25 neutral wording, title alternatives, and positive/boundary result
branches are maintained in
`FRAMING_CANDIDATES_AND_RESULT_BRANCHES_20260825.md`. They remain candidates
for author decision.

`cwe_ids` is outside the V3.1 human routing study. Existing CWE work remains
retrospective or supplementary evidence and cannot repair a failed primary
field.

## Candidate contributions mapped to evidence

1. A reproducible descriptive audit over 8,066 CVE-aligned NVD–GHSA records,
   with field-level status and policy-output counts. Current status: supported
   for the frozen corpus only.
2. A frozen comparison among a strong field-aware simple comparator, a
   type-first efficiency arm, and an abstention-aware safety arm. Current
   status: policies and full-corpus disagreement census are implemented; no
   correctness result exists.
3. A low-human, action-first/reason-second construct test using calibration-1
   20, a conditional disjoint calibration-2 reserve of 20, and 120 formal cases
   reviewed by two independent trained analysts. Current status: protocol,
   recursively blinded packets, return validators, stage locks, and evaluator
   exist; reviewer identity, distribution approval, and all human labels are
   missing.
4. A bounded empirical account of when routing policies agree, disagree,
   abstain, or become statistically unidentifiable. Current status: the
   label-free identifiability precheck and older non-human failure evidence are
   available; human-backed conclusions are missing.

## Frozen policy interpretation

- `field_aware_simple_v1` is the main strong comparator. It is a hand-written
  field-specific strategy, not a claim about actual maintainer practice.
- `type_first_current_v1` is the efficiency candidate.
- `type_first_abstention_v1` is the safety candidate.
- raw and canonical non-equality are lower-reference arms only.
- `conflict_escalation` is the conflict queue.
- `conflict_escalation + abstain` is the total manual-review route.

On the 8,066-row label-free census, the simple and abstention-aware policies
differ on 2,332 field actions. The abstention-aware policy produces 74 fewer
conflict escalations but 950 more total manual-review routes than the simple
comparator. These are deterministic policy outputs, not unnecessary work or
saved labor. They motivate an efficiency-safety frontier; they do not support a
workload-reduction claim.

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
- Positive efficiency-safety framing requires both reviewers to pass the
  reliability, same-direction efficiency, and `delta_manual=0.10` safety
  gates. Failure automatically selects the boundary/ambiguity route.
- Preserve action/reason disagreement, abstention, and uncertainty. Author
  adjudication is secondary and policy-blinded.
- Decide positive frontier versus decision-ambiguity framing only after both
  independent formal passes are frozen.
- Existing adjudication work stays secondary failure evidence unless a new,
  separately authorized human-backed comparison is justified.

## Author-owned unresolved decisions

- Approve or revise the candidate title and RQ wording before S2 lock.
- Recruit two different qualified real trained analysts and document whether
  either is an actual maintenance practitioner.
- Record expertise, compensation, conflicts, recruitment, and any required
  institutional ethics determination before distribution.
- Approve the V3.1 guideline and distribution revision after verifying packet
  hashes.
- Recheck complete current JSS author and artifact requirements before the
  submission stages.
- Approve or revise the zero draft and its provisional references; the current
  Markdown draft intentionally withholds RQ2/RQ3 results, abstract, and
  conclusion.
