# T1/T2 Action-First Human Validation Protocol V3.1

Protocol ID: `vuln-adj-jss-t1-human-validation-v3.1`

Status: `FROZEN_FOR_PREPARATION_BEFORE_HUMAN_EXPOSURE`

Freeze date: 2026-08-25

Distribution status: `BLOCKED`

V3.1 supersedes V3 for future human exposure. V2 and V3 remain immutable,
prepare-only historical artifacts; neither received human labels. V3.1 was
frozen after label-free design checks and before any V3.1 packet was shown to a
reviewer.

## 1. Purpose, RQs, and claim ceiling

Two different real trained analysts independently answer:

- RQ1: How reliably can trained analysts assign a maintenance action to a
  displayed NVD/GHSA field-value pair under a frozen rubric?
- RQ2: How do a strong field-aware simple policy and two type-first policies
  distribute routing actions relative to each analyst's independent action?
- RQ3: How are independently assigned discrepancy reasons associated with
  maintenance actions, and where do the rule taxonomy and human decisions
  diverge?

The RQs are outcome-neutral. They support either a positive routing result or a
boundary/decision-ambiguity result without post-hoc rewriting.

The compared policies are:

- `field_aware_simple_v1`: primary strong comparator; it is hand written and
  is not claimed to describe observed industry practice;
- `type_first_current_v1`: efficiency candidate without added abstention;
- `type_first_abstention_v1`: safety candidate with frozen rule-limit
  abstention.

Raw and canonical non-equality remain lower-reference arms only. Routing counts
do not establish labor saved, elapsed maintenance time, staffing cost,
production benefit, or adoption.

## 2. Frozen population

The source is
`data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`:

- 8,066 CVE-aligned rows;
- SHA-256
  `c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2`;
- four fields: `severity`, `affected_versions`, `published`, and
  `references`;
- 32,264 field instances before sampling.

The 8,066 rows are the CVE-aligned study cohort, not all GHSA advisories. The
paper must report the 8,066 / 28,785 alignment boundary and may not call it
population coverage of the full GHSA corpus.

## 3. Human budget and sampling

Each reviewer sees the same cases in a reviewer-specific random order:

- formal evaluation: 120 cases;
- calibration round 1: 20 cases;
- calibration round 2 reserve: 20 disjoint cases, used only if Section 4
  triggers it.

The ordinary budget is 140 judgments per reviewer. The bounded maximum is 160
per reviewer. No third reviewer and no additional cases may be added to rescue
an outcome.

Formal allocation is fixed at severity 50, affected versions 50, published 10,
and references 10. The V3 formal case set is retained. Calibration rounds are
redrawn and presealed so that:

1. all formal CVE IDs are unique;
2. calibration-1, calibration-2, and formal CVE-ID sets are pairwise disjoint;
3. each calibration round contains five cases per field and independently
   meets the frozen proxy-coverage requirements; and
4. no calibration label enters a formal endpoint.

Cases are selected by stable SHA-256 rank. Evaluation is selected first;
calibration-1 is selected from CVEs not used in evaluation; calibration-2 is
then selected from CVEs used in neither earlier phase.

### 3.1 Formal evaluation cells

Severity (50):

- 25 `factual_conflict` cases with
  `conflict_escalation -> abstain`;
- all five representation cases with `abstain -> no_action`;
- five controls each from equivalent, representation, incomplete, and factual
  conflict agreement cells.

Affected versions (50):

- six cases from each of five policy-disagreement pairs;
- five controls each from equivalent, representation, incomplete, and factual
  conflict agreement cells.

Published (10): five representation and five temporal controls.

References (10): all three factual-conflict rows, four representation rows, and
three incomplete rows.

Each formal cell records `N_h`, `n_h`, inclusion probability, and
`N_h/n_h` weight. The primary table is sample-level and stratified by field
and deterministic cell. Population projection is sensitivity analysis only and
must report Kish effective sample size.

### 3.2 Shared no-manual-route audit

The formal case set contains a derived safety-audit stratum: cases where both
`field_aware_simple_v1` and `type_first_abstention_v1` select no manual
route. Manual route is `{conflict_escalation, abstain}`; no-manual route is
`{no_action, enrich_record, wait_for_sync}`.

The derived set contains 34 fixed cases (severity 15, affected versions 19).
Its combined case-ID hash and field-specific hashes are sealed in the manifest.
It is not marked in reviewer-visible packets.

This audit can reveal shared misses. It cannot estimate a population miss rate:
selection is cell-stratified, the combined zero-event one-sided bound is
sample-conditional, and weighted effective sample sizes are small. Any human
`conflict_escalation` in this set is reported case by case and challenges the
positive framing.

## 4. Bounded calibration and guideline revision

Calibration is training and rubric repair, not the formal reliability
measurement.

1. Both reviewers independently finish calibration-1 action labels.
2. Returns are validated, hashed, and locked before reason packets are released.
3. After both reason returns are locked, the reviewers may discuss
   disagreements with the study author.
4. The guideline diff is recorded before any formal packet is opened.
5. If calibration-1 action raw agreement is at least 0.60 and there is no
   material guideline change, formal distribution may proceed after all other
   gates.
6. If agreement is below 0.60 or the guideline changes materially,
   calibration-2 is mandatory.
7. Calibration-2 uses the revised frozen guideline and its presealed disjoint
   reserve. No further revision-and-retry cycle is allowed.
8. Calibration-2 action raw agreement below 0.60 terminates formal
   distribution for this protocol. The result is recorded as a construct
   qualification failure, not repaired by extra cases or a third reviewer.

A material change alters a label definition, decision rule, required evidence,
action boundary, or example that resolves an observed category ambiguity.
Spelling, formatting, and clarifications that do not change an answer are
non-material. The author records the classification and complete diff before
opening calibration-2 or formal material.

## 5. Action-first, reason-second collection

Allowed actions are `no_action`, `enrich_record`, `wait_for_sync`,
`conflict_escalation`, and `abstain`.

Allowed reasons are `equivalent`, `representation_discrepancy`,
`incomplete`, `temporal_discrepancy`, `factual_conflict`, and
`uncertain`.

For every used phase:

1. both independent action returns are complete, validated, hashed, and locked;
2. only then may the corresponding reason packets be released;
3. reason packets do not display the reviewer's earlier action;
4. reviewers do not see each other's labels until both reason returns are
   sealed; and
5. `abstain`, `uncertain`, and disagreements are retained.

## 6. Blinding and distribution allowlist

Reviewer-visible JSON is governed by a recursive schema allowlist at every
object level. Unknown keys fail closed. A denylist is retained only as a second
diagnostic layer.

Packets omit deterministic type/status, policy names and outputs, baseline
notes, NVD/GHSA source IDs, AI/model outputs, prior reviews, selection cells,
weights, and the other reviewer's answer. Left/right identity is masked. URLs
may reveal source identity and remain an explicit limitation.

Only the current reviewer's approved packet for the current phase/stage and the
approved guideline may be distributed. Internal frames, sealed mappings,
manifests, role/stage records, the other reviewer's files, future-stage files,
and all legacy candidate packets are excluded. In particular,
`data/annotations/expert_candidate/review_packets/rq2_primary.review.jsonl`
is permanently excluded because it contains answer-revealing metadata.

## 7. Primary estimands and analyses

Pre-adjudication results are primary and reviewer-specific.

### 7.1 Reliability

Report overall and per field: raw action agreement, nominal Krippendorff alpha,
raw reason agreement and alpha, abstention/uncertain rates, and full
disagreement matrices.

Formal action raw agreement below 0.60 or nominal alpha below 0.40 forbids a
positive routing claim and changes the manuscript to a boundary/decision-
ambiguity result.

### 7.2 Efficiency endpoint

The main endpoint uses only formal policy-disagreement cases. For each reviewer,
report each policy's exact action matches and the paired discordant counts
`b/c` for `type_first_abstention_v1` versus
`field_aware_simple_v1`. Use exact two-sided McNemar tests and paired 95%
intervals. Absolute match rates on this deliberately enriched subset are
sample-conditional; they are not population accuracies.

A positive efficiency claim requires the same direction for both reviewers and
the pre-specified paired interval excluding zero in the pooled,
CVE-blocked sensitivity analysis. Agreement controls are reported separately.

### 7.3 Safety endpoint and positive-framing gate

The safety reference outcome is each reviewer's independent
`conflict_escalation` action. A factual-conflict reason is not substituted.

For each reviewer separately, report:

- number of human conflict-escalation actions;
- field-aware-simple and type-first manual-route coverage;
- paired coverage difference and discordant counts;
- the count and one-sided 95% exact binomial upper bound for a
  **simple-only manual-route loss**: the simple policy routes manually and the
  type-first safety policy does not.

The substantively selected loss margin is `delta_manual = 0.10`; it was not
chosen by inspecting human labels. Positive efficiency-safety framing requires,
for **both** reviewers:

1. at least 29 human conflict-escalation actions;
2. type-first manual-route coverage no lower than the simple comparator;
3. the one-sided 95% upper bound on the simple-only loss rate is below 0.10; and
4. no contradictory systematic failure under Section 8.

The earlier 25-positive threshold remains a reporting floor: below 25 for
either reviewer, conflict recall is interval-only and no arm ranking is made.
Between 25 and 28, descriptive ranking is allowed but positive framing is not.
If either reviewer fails any positive-framing condition, the full manuscript
automatically becomes a boundary/ambiguity paper. It may not claim that
efficiency was achieved without a safety cost.

### 7.4 Reason-to-action association

Primary association evidence is cross-reviewer: A action versus B reason and B
action versus A reason. Same-reviewer association is a labelled upper bound.
Association is descriptive and does not establish causation.

## 8. Additional outcome-independent stop rules

- Missing identity/independence evidence, required ethics determination, input
  hash, validator pass, or stage lock blocks the next distribution stage.
- Reviewer-specific formal conflict actions below 25 trigger the reporting
  restriction in Section 7.3; counts are never pooled across reviewers.
- No policy-superiority claim is allowed if reviewers favor different policies.
- Systematic failure requires the same predeclared action-pair or reason-pair
  failure in at least two fields and at least 30% of disagreements in each.
- Author adjudication is secondary, policy-output blind, and reported only
  after pre-adjudication results. All conclusions are recomputed after excluding
  adjudicated cases.
- No failed row, field, disagreement, abstention, uncertain label, or shared
  safety-audit miss may be dropped, replaced, or relabelled.

## 9. Governance state

V3.1 remains `PREPARATION_ONLY_NOT_FOR_DISTRIBUTION` until:

1. the versioned guideline is author approved;
2. reviewer role/independence and ethics/recruitment records are complete;
3. the independent packet validator and all hashes pass;
4. calibration has cleared Section 4;
5. the relevant action stage is locked before reason release; and
6. a separate author-approved manifest revision explicitly permits only the
   named reviewer, phase, and stage files.

The preparation manifest must keep `distribution_allowed=false`. Blank
packets are not human labels or human gold.
