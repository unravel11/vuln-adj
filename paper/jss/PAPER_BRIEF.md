# Paper Brief

## Identity and authority

- Paper ID: `vuln-adj-jss-type-first-audit-v1`
- Target venue: Journal of Systems and Software, conditional route
- Fallback venue: Information and Software Technology
- Repository authority:
  `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`
- Active branch: `codex/jss-framing-b-20260823`
- Branch point: `760523caa8677c7e1e98c3b5be376d08c250f8d6`
- New-paper authority: this `paper/jss/` workspace
- Historical source line: `paper/cose/`, retained but not edited as the JSS
  manuscript
- Current stage: `S1_EVIDENCE_LOCKED`
- Submission ready: no

## Candidate thesis

For CVE-aligned NVD and GHSA records, a binary mismatch flag is not yet a
validated conflict decision. A type-first, abstention-aware evaluation can
separate operationally different cases and expose when automated
reconciliation is unsupported or empirically unidentifiable.

This thesis remains an `S2 candidate`. The first sentence is supported as a
problem statement; reliable type separation and downstream value require T1
and T2 before they may be stated as findings.

## Research questions

- RQ1 — Distribution: Across aligned NVD–GHSA CVE records, how do deterministic
  field comparisons distribute over severity, publication date, references,
  affected versions, and supplementary CWE identifiers?
- RQ2 — Construct and typing validity: Under independent real-human review,
  how reliably can a type-first, abstention-aware baseline distinguish
  equivalent, representation, incomplete, temporal, and factual-conflict
  cases?
- RQ3 — Operational value and limits: Relative to binary escalate-all routing,
  what workload, conflict-recall, coverage, and abstention trade-offs arise
  from type-first routing and bounded evidence-driven adjudication?

The four primary fields are `severity`, `published/date`, `references`,
and `affected_versions`. `cwe_ids` is supplementary and cannot repair a
failed primary-field gate.

## Candidate contributions mapped to evidence

1. A reproducible descriptive audit over 8,066 CVE-aligned NVD–GHSA records,
   with field-level counts and explicit input/normalization boundaries.
   Current status: supported for this frozen corpus only.
2. An action-oriented discrepancy taxonomy and deterministic type-first
   baseline with an explicit `uncertain/abstain` route.
   Current status: implemented, but human construct validity and accuracy are
   missing.
3. A decision-level comparison between binary escalate-all and type-first
   routing, reporting conflict recall together with unnecessary escalation and
   abstention.
   Current status: proposed T2; no result exists.
4. A bounded empirical account of evidence dependence, low coverage,
   identifiability limits, and no-go outcomes in automated reconciliation.
   Current status: supported only as retrospective evidence on the tested
   cohorts and protocols.

## Explicit non-claims

- No claim that NVD or GHSA is globally more accurate, authoritative, timely,
  or complete.
- No claim that deterministic discrepancy labels are ground truth.
- No claim of human-gold performance before two real reviewers and author
  adjudication complete T1.
- No claim that same-model or Codex review passes are independent human review.
- No claim that the current affected-version method improves over named
  baselines; the current result is a bounded no-go.
- No claim of future-snapshot or temporal generalization from the current
  snapshot-external cohort.
- No claim that this work is the first discrepancy taxonomy; closest prior work
  already studies cross-database vulnerability inconsistencies.
- No claim of submission readiness, submission, acceptance probability, or
  venue acceptance.

## Evidence snapshot

- Current field view:
  `data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`
  - rows: 8,066
  - SHA-256:
    `c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2`
- Historical RQ2 stratified seed:
  `data/annotations/rq2/discrepancy_typing_seed.jsonl`
  - rows: 300, 60 per field
  - blank real-human labels: 300
  - core field values and deterministic statuses match the current field view:
    300/300
  - full context matches: 298/300; two rows retain a removed
    `enterprise_linux` package name
  - SHA-256:
    `2b70d0c48b3659c3a6f2cba2c8024b4c12673b15814b9f123871ec97dd6a518f`
- T1 V2 sampling rule:
  - draw a new 300-row frame directly from the current field view before any
    human label;
  - retain the historical seed for audit, but do not distribute or silently
    refresh it as the JSS T1 packet.
- T1 V2 preparation packet:
  `data/annotations/rq2/t1_human_validation_v2/`
  - calibration/evaluation: 50/250, with 10/50 rows per field;
  - manifest SHA-256:
    `816d1d274237ae4d276b7db0925d46255f07b3ea9f39c410ae42eb68a675b1ac`;
  - validator status: internally consistent;
  - distribution status: `false`;
  - real-human labels: 0.
- Seed manifest:
  `data/annotations/rq2/sample_manifest.json`
  - SHA-256:
    `4dff7bb1c47602ea3b7bb99deacbd5573fb7a673b662c2a9e46db1da8c9f3bae`
- Historical COSE package manifest:
  `results/paper_cose/cose_package_manifest.json`
  - dated 2026-07-19
  - mechanical checks: 127/127
  - `submission_ready=false`

## Experiment decision

Decision: `TARGETED_EXPERIMENTS`.

- T1 is mandatory: independent real-human validation of the discrepancy
  taxonomy on a baseline-blinded calibration/evaluation split.
- T2 is mandatory for the positive routing claim: binary escalate-all versus
  type-first routing on frozen human labels.
- T3 is conditional: run a separately frozen human-backed severity and
  affected-version adjudication comparison only if adjudication remains a core
  contribution. Otherwise retain current RQ3 material as a negative/failure
  analysis.
- T4 is omitted from the current submission route unless the pre-existing
  bilateral post-freeze eligibility rule yields a new cohort.

## Author-owned unresolved decisions

- Confirm or revise the candidate title and RQ wording before `S2` is locked.
- Recruit two different qualified real reviewers and one resolving author.
- Record expertise, compensation, conflict-of-interest, and any required
  institutional ethics determination before recruitment.
- Decide whether evidence-driven adjudication remains a core contribution after
  T1/T2, which determines whether T3 is mandatory.
- Recheck the complete, current JSS author requirements before artifact and
  submission gates.
