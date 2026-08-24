# Paper Brief

## Identity and authority

- Paper ID: `vuln-adj-jss-type-first-audit-v1`
- Target venue: Journal of Systems and Software, conditional route
- Fallback venue: Information and Software Technology
- Repository authority:
  `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`
- Active branch: `codex/jss-v3-routing-precheck-20260825`
- Branch point: `5a0238750600e9eef78d3eb39c3d3810df5cd1d7`
- New-paper authority: this `paper/jss/` workspace
- Historical source line: `paper/cose/`, retained but not edited as the JSS
  manuscript
- Current stage: `S1_EVIDENCE_LOCKED`; S2 argument remains conditional
- Submission ready: no

## Candidate thesis

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

`cwe_ids` is outside the V3 human routing study. Existing CWE work remains
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
3. A low-human, action-first/reason-second construct test using 20 calibration
   and 120 formal cases reviewed by two independent trained analysts. Current
   status: protocol and blank prepare-only packets exist; reviewer identity,
   distribution approval, and all human labels are missing.
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
  - field instances used by V3: 32,264;
  - SHA-256:
    `c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2`.
- Label-free routing precheck:
  `results/jss/t1_routing_precheck_v1/`
  - decision: `CONDITIONAL_GO_FOR_V3_PACKET_DESIGN`;
  - five label-free gates: pass;
  - action disagreements, simple versus abstention-aware: 2,332;
  - analysis SHA-256:
    `47428580744f0d83331c15b82a623a771f40a40d1ddcf59731fd83787553f7a8`.
- V3 prepare-only packet:
  `data/annotations/rq2/t1_human_validation_v3/`
  - unique cases: 140;
  - calibration/formal: 20/120;
  - formal allocation: severity 50, affected versions 50, published 10,
    references 10;
  - two independent reviewer orders and separate action/reason stages;
  - manifest SHA-256:
    `f98c9084071cf8c78f4fec977449ff57f5a940fa5c8fa3a3bf19de185c67dfa9`;
  - integrity validator: pass;
  - distribution-ready validator: expected refusal;
  - `distribution_allowed=false`; real-human labels: 0.
- V2 packet:
  `data/annotations/rq2/t1_human_validation_v2/`
  - retained unchanged as historical prepare-only material;
  - must not be distributed for the active low-human route.
- Historical COSE package:
  `results/paper_cose/cose_package_manifest.json`
  - mechanical snapshot only;
  - `submission_ready=false`.

## Experiment decision

Decision: `CONDITIONAL_GO_FOR_V3_PREPARATION`; `NO_GO_FOR_SUBMISSION`.

- The label-free gate was strong enough to justify V3 packet design.
- One V3 human round supplies both action and reason labels; there is no second
  separately recruited T2 annotation study.
- Before distribution, freeze the analysis/evaluator implementation, approve
  the guideline, document two real trained analysts and ethics/recruitment,
  and create an explicitly approved distribution manifest revision.
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
- Approve the V3 guideline and distribution revision after verifying packet
  hashes.
- Recheck complete current JSS author and artifact requirements before the
  submission stages.
