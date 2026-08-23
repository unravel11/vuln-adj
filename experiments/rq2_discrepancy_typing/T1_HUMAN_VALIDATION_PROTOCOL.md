# T1 Real-Human Discrepancy-Typing Validation Protocol

Protocol ID: `vuln-adj-jss-t1-human-validation-v1`

Status: `FROZEN_BEFORE_ANY_REAL_HUMAN_LABEL`

Freeze date: 2026-08-23

This protocol defines the mandatory construct-validation experiment for the
active JSS route. It does not claim that annotation has started or that human
gold exists. The current seed contains 300 blank real-human labels.

## 1. Purpose and claim gap

The existing deterministic taxonomy and AI/Codex review chain do not establish
that real experts can apply the five discrepancy types reliably. T1 estimates:

1. independent reviewer agreement and uncertainty;
2. adjudicated determinate coverage;
3. deterministic baseline confusion and performance against frozen human
   labels; and
4. field-specific failure, without dropping a field to improve the result.

T1 does not choose whether NVD or GHSA is factually correct. Source/value
adjudication is a separate task.

## 2. Population, fields, and fixed sampling frame

Population frame:
`data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`

- 8,066 CVE-aligned rows;
- current SHA-256:
  `c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2`.

Fixed seed:
`data/annotations/rq2/discrepancy_typing_seed.jsonl`

- 300 rows, 60 per field;
- source SHA-256:
  `2b70d0c48b3659c3a6f2cba2c8024b4c12673b15814b9f123871ec97dd6a518f`;
- verified on 2026-08-23 as 300 unique IDs, 300 blank labels, and 300/300
  exact bindings to the current field-view rows.

Primary fields:

- `severity`
- `published`
- `references`
- `affected_versions`

Supplementary field:

- `cwe_ids`

The seed was stratified by deterministic baseline status and is not a simple
random sample. Unweighted totals may describe only the annotation sample.
Population-oriented summaries must use the recorded field-by-baseline-stratum
candidate counts and evaluation inclusion weights.

## 3. Calibration and evaluation split

The 300 seed rows are split before any human label:

- calibration: 50 rows, exactly 10 per field;
- evaluation: 250 rows, exactly 50 per field.

Within each field, calibration rows are allocated across available baseline
strata using the existing equalized allocation rule with one additional
constraint: at least one row must remain in the evaluation set for every
non-empty stratum. Rows are selected with Python `random.Random(20260823)`.
All remaining rows form the evaluation set.

The baseline stratum may be used by the packet builder for sampling and
weighting, but it must not appear in either reviewer's packet.

Side masking uses `random.Random(20260824)`. Reviewer packet orders use
`random.Random(20260825)` for reviewer A and
`random.Random(20260826)` for reviewer B. Seeds may not change after packet
generation.

The evaluation set remains unopened to reviewers until calibration is resolved
and the annotation guideline is frozen.

## 4. Human roles and independence

- Reviewer A and reviewer B must be two different real people.
- Both must have documented experience interpreting vulnerability advisories,
  CVE records, CVSS/severity, reference links, and version-range statements.
- Neither reviewer may see deterministic baseline labels, baseline notes,
  AI/Codex labels, prior consensus, profile differences, or the other
  reviewer's decisions before submitting an independent pass.
- A resolving author sees both review files only after both are complete and
  hashed. The resolving author also remains blinded to baseline/model outputs
  until the adjudicated label file is frozen.
- Reviewer IDs, expertise statement, conflicts of interest, compensation, and
  any required institutional ethics determination must be recorded before
  recruitment. This protocol does not assert that the work is exempt from
  review.

ID strings or filled files alone do not prove real-human identity or
independence. The author must sign the role record.

## 5. Packet blinding and source information

Reviewer packets contain:

- packet-specific case ID;
- CVE ID and field name;
- two sides labelled `left` and `right`;
- the field values and supplied frozen context;
- blank label, rationale, uncertainty reason, and notes.

Reviewer packets omit:

- `baseline_status` and `baseline_note`;
- `is_baseline_correct` and `needs_adjudication`;
- explicit NVD/GHSA side names and source IDs;
- all AI/Codex labels, confidence, votes, and review history;
- calibration/evaluation outcomes from the other reviewer.

Left/right assignment is randomly masked and recorded in a sealed internal
mapping. URLs may reveal source identity, so source blinding is partial and
must be reported as a threat to validity.

T1 labels use only the supplied frozen row context. Reviewers do not browse
dynamic pages during the primary pass. Insufficient context is labelled
`uncertain`, not repaired through unrecorded web lookup.

## 6. Label contract

Allowed labels:

- `equivalent`
- `representation_discrepancy`
- `incomplete`
- `temporal_discrepancy`
- `factual_conflict`
- `uncertain`

The initial definitions are in
`docs/annotation_guidelines/rq2_discrepancy_typing.md`, currently marked
draft. Before calibration distribution, the author must version and hash the
guideline. After both independent calibration passes:

1. reviewers and author discuss definition ambiguity, not baseline agreement;
2. any change is recorded in a calibration revision ledger;
3. a final evaluation guideline is frozen and hashed;
4. evaluation packets are then released.

No label definition, example, threshold, or field may change after either
reviewer begins the evaluation set. A material change requires a new untouched
sample; it cannot be validated on the already exposed evaluation rows.

## 7. Review and adjudication workflow

1. Build and hash the split, sealed mapping, and two independently ordered
   calibration packets.
2. Reviewers independently label all 50 calibration rows.
3. Freeze both calibration returns and revise/freeze the evaluation guideline.
4. Release two independently ordered evaluation packets.
5. Reviewers independently label all 250 evaluation rows. Blank labels are not
   permitted; `uncertain` is a completed result.
6. Freeze and hash both reviewer returns.
7. Compute pre-adjudication agreement and uncertainty.
8. The resolving author adjudicates every disagreement and any row marked
   `uncertain` by either reviewer, without seeing baseline/model outputs.
9. Freeze the adjudicated label file and its manifest.
10. Only after step 9, unseal deterministic baseline predictions and compute
    RQ2 metrics.

No row may be removed because it is difficult, uncertain, inconsistent with the
baseline, or unfavorable to the framing.

## 8. Primary estimands and reporting

Report before adjudication:

- completion: 250/250 evaluation rows from each reviewer;
- exact label agreement overall and by field;
- Krippendorff's alpha for nominal labels, including `uncertain` as a valid
  category, overall and by field;
- each reviewer's `uncertain` rate overall and by field;
- disagreement matrix and disagreement reasons.

Report after adjudication:

- final label counts, including `uncertain`;
- determinate coverage overall and by field;
- design-weighted confusion matrix for deterministic baseline versus
  adjudicated labels;
- design-weighted accuracy, macro-F1, and factual-conflict precision/recall on
  determinate rows;
- unweighted sample metrics as explicitly secondary diagnostics;
- bootstrap confidence intervals resampled within the fixed
  field-by-baseline-stratum design;
- all primary-field results, including failures.

For an evaluation row in stratum h, the population weight is
`N_h / n_eval_h`, where `N_h` is the manifest candidate count and
`n_eval_h` is the number of evaluation rows retained in that stratum. The
packet builder must verify `n_eval_h > 0` for every non-empty sampled stratum.

Calibration labels are excluded from primary performance metrics.

## 9. Outcome-independent gates

Mechanical and independence gate:

- two distinct real reviewers documented;
- both evaluation files complete at 250/250;
- packet and return hashes match the sealed manifest;
- no baseline/model columns in distributed packets;
- author adjudication complete and signed.

Construct-reliability interpretation:

- alpha at or above 0.800: strong reliability for the reported scope;
- alpha from 0.667 through below 0.800: usable only with explicit uncertainty
  and field-level limitations;
- alpha below 0.667: no-go for a positive reliability claim.

Positive cross-field taxonomy route:

- overall alpha at least 0.667;
- alpha at least 0.667 for every primary field;
- adjudicated determinate coverage at least 0.80 overall and at least 0.70 in
  every primary field.

If any primary field fails, the paper may not claim reliable cross-field
typing. The failed field remains in all tables and the route changes to a
construct-ambiguity or negative study. The supplementary CWE result cannot
repair a failed primary field.

Baseline accuracy and macro-F1 do not determine whether labels, fields, or
thresholds are retained. All results are reported.

## 10. Link to T2 and stop rules

T2 may be frozen only after the T1 action-label semantics are fixed and must be
run only after T1 adjudicated labels are sealed. Its binary comparator, action
map, workload unit, conflict-positive definition, and abstention treatment must
be written before baseline unsealing for T2.

Stop and preserve the outcome when:

- reviewer independence or completeness cannot be established;
- a source or packet hash mismatch occurs;
- any post-evaluation change would alter the taxonomy or action mapping;
- the positive cross-field reliability gate fails; or
- later T2 shows no downstream benefit under its frozen rule.

Do not respond by dropping failed rows or fields, adding same-model votes,
changing alpha or coverage thresholds, altering the calibration/evaluation
split, or sampling a favorable replacement from the revealed corpus.

## 11. Required artifacts

Before annotation:

- versioned protocol and protocol hash;
- versioned calibration guideline and hash;
- split manifest with source and seed hashes;
- sealed left/right and case-ID mapping;
- reviewer A/B calibration packets and hashes;
- human role and independence record.

After calibration:

- reviewer A/B calibration returns;
- calibration revision ledger;
- frozen evaluation guideline and hash;
- reviewer A/B evaluation packets and hashes.

After evaluation:

- reviewer A/B returns;
- pre-adjudication agreement report;
- author adjudication file and signoff;
- final human-label manifest;
- design-weighted RQ2 result files;
- revision and claim-ledger update.

Until these files exist and pass their validators, the correct status is
`T1_PROTOCOL_READY_LABELS_MISSING`, not `human_gold_complete`.
