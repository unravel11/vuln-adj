# Development-Disjoint Holdouts

This directory contains the frozen affected_versions holdout pipeline. The
cohort is disjoint by CVE from the 100-row Phase D development sample. It is not
independent of the deterministic factual-conflict candidate miner and it is not
human-gold.

Run all data-producing commands on the authoritative remote:

```bash
python3 experiments/holdout/build_affected_versions_holdout.py
python3 scripts/build_rq3_evidence_samples.py \
  data/annotations/holdout/affected_versions_v1/source_rows.jsonl \
  --output-dir data/annotations/holdout/affected_versions_v1/evidence \
  --cache-dir data/evidence_cache/holdout/affected_versions_v1/url_cache
python3 experiments/holdout/build_affected_versions_blind_worklist.py
python3 experiments/holdout/predict_affected_versions_holdout.py
```

The prediction-only runner must finish before either reviewer decision file is
created. It writes no silver/gold labels and no correctness fields. Reviewers
receive only the blind worklist and
`docs/prompts/affected_versions_holdout_adjudication.md`; they must not read the
sealed predictions, old AI-gold, prior candidates, or one another's output.

After both decision files exist:

```bash
python3 experiments/holdout/merge_affected_versions_holdout_adjudication.py
python3 experiments/holdout/evaluate_affected_versions_holdout.py
python3 experiments/holdout/analyze_affected_versions_holdout_task_split.py
```

The merge accepts a row only when both Codex reviewers agree exactly on the
discrepancy label and source, and both decisions are determinate under the
positive-support contract. Every consensus artifact remains
`label_is_human=false` and requires real human signoff.

## Current result

The two Codex reviewers agree exactly on 42/100 discrepancy labels and 53/100
source labels. Strict joint consensus retains 35/100 rows. The preregistered
all-strict ranking is led by branch/artifact fixed fallback at 17/35; this is
conditional on 0.35 strict coverage.

Post-unseal analysis found that only 16 strict rows remain factual conflicts;
17 are representation discrepancies and two are incomplete. On the FC-only
subset, branch/artifact methods reach 7/16, tied with prefer-GHSA and recency,
while raw/canonical token reach 1/16. This task split is explicitly post-hoc and
shows that all-strict source accuracy conflates discrepancy typing with source
adjudication. It does not support a method-improvement claim.

Tests:

```bash
python3 experiments/holdout/test_build_affected_versions_holdout.py
python3 experiments/holdout/test_build_affected_versions_blind_worklist.py
python3 experiments/holdout/test_merge_affected_versions_holdout_adjudication.py
```

## V2 task-separated holdout

The v2 cohort is a new 100-CVE sample that excludes both the original Phase D
development cohort and the v1 holdout. From the current 651 deterministic
factual-conflict candidates, 451 CVEs remained eligible after the 200-CVE
exclusion. Fixed SHA-256 ranking selected the 100 rows without inspecting their
field values. The dedicated evidence snapshot contains 564 records and all 100
rows have at least one usable text record.

Run the frozen preparation and checks on the authoritative remote:

```bash
python3 experiments/holdout/test_build_affected_versions_holdout_v2.py
python3 experiments/holdout/test_build_affected_versions_blind_worklist_v2.py
python3 experiments/holdout/test_seal_affected_versions_holdout_v2_predictions.py
python3 experiments/holdout/test_merge_affected_versions_holdout_v2_adjudication.py
python3 experiments/holdout/test_evaluate_affected_versions_holdout_v2.py
python3 experiments/rq3_adjudication/test_affected_versions_task_separated.py
```

The sealed manifest records 300 type predictions (three methods) and 1,900
source predictions (19 methods). It preregisters two separate endpoints:

- discrepancy typing on strict dual-Codex type consensus, with abstention
  counted as incorrect in full accuracy;
- source adjudication only on rows with strict factual-conflict type and strict
  source consensus.

`task_separated_type_v1` is the preregistered type method. The source primary is
the existing `branch_release_graph` head, not a newly named wrapper around the
same method. Reviewer inputs are limited to the blind worklist and
`docs/prompts/affected_versions_holdout_v2_adjudication.md`. Each cited URL must
be accompanied by a literal frozen quote and a structured endpoint/target/role
claim. The merge rejects shared/identical reviewer files, provenance mismatches,
order changes, incompatible type/artifact combinations, and unsupported source
choices.

The v2 labels are still produced by two Codex reviewers. Every decision and
consensus row must remain `label_is_human=false`, is ineligible for a human-gold
claim, and requires real human signoff.

### V2 result

The reviewers agree on 65/100 discrepancy labels and 80/100 artifact
relations; kappa is 0.5353 and 0.6690. Strict type consensus retains 41 rows:
15 factual conflicts, eight incomplete cases, and 18 representation
discrepancies. Only nine of the 15 strict factual conflicts also have strict
source consensus (six NVD, one GHSA, and two neither), so source evaluation
covers 9% of the full cohort.

On the preregistered type endpoint, `task_separated_type_v1` predicts only
three of 41 strict rows and gets all three correct. Its selective accuracy is
therefore 1.0, but full accuracy is 3/41 (0.0732), below all-FC at 15/41 and
legacy structural typing at 16/41. On the nine strict FC-source rows,
`branch_release_graph` reaches 2/9 with 5/9 prediction coverage; `prefer_nvd`
reaches 6/9. The result does not support either a type-method or source-method
improvement. It supports the endpoint split and documents an extremely
selective type candidate whose current coverage is too low for deployment.

Both reviewer files needed one mechanical repair by their original reviewer:
A converted `unresolved=null` to an empty string, and B expanded source
rationales that were shorter than a frozen validator limit. No label, source,
or evidence decision changed. The prompt did not state those character limits,
which is a protocol defect to fix before another holdout.

### V2 post-hoc evidence-dependence audit

After unsealing, `analyze_affected_versions_v2_failure_modes.py` found that the
type primary false-abstains on 38 of 41 strict type rows: 13 factual conflicts,
eight incomplete cases, and 17 representation discrepancies. The failure is
therefore not isolated to one target class.

The nine strict FC-source rows are also not evidence-independent. In five rows,
both reviewers cite the same single URL; three rows collectively cite only NVD
record evidence. At least one reviewer cites primary/ecosystem evidence in four
rows, while both do so in only two. This is a post-hoc non-human diagnostic,
but it establishes an audit requirement: reviewer independence alone does not
establish evidence independence or source authority.
