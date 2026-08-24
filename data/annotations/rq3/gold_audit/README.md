# RQ3 Human Audit Templates

This directory contains blank human-audit templates for RQ3 adjudication.
The templates are built from evidence-aware `silver_v2` artifacts, but the silver labels are provenance only.

Do not report RQ3 gold-backed performance until the `human_audit` fields are filled and the guarded evaluator succeeds.

## Files

- `severity_adjudication_audit.jsonl/.csv`: severity adjudication audit template.
- `affected_versions_adjudication_audit.jsonl/.csv`: affected_versions adjudication audit template.
- `sample_manifest.json`: source paths and row counts.

## Required Human Fields

- `audit_status`: use `final` only when the row is complete, or `exclude` when it should not be evaluated.
- `human_label`: equivalent, representation_discrepancy, incomplete, temporal_discrepancy, factual_conflict, or uncertain.
- `is_baseline_false_positive`: yes, no, or uncertain.
- `adjudicated_source`: nvd, ghsa, both, neither, or abstain.
- `evidence_urls`: required unless the row is uncertain or abstain.
- `annotator_id` and `audited_at`: required for final rows.
- `review_status=reviewed` and a non-empty `reviewer_id` distinct from `annotator_id`: required before a final row can enter human-gold evaluation.
- `version_reasoning_type`: affected_versions only; token_support, range_semantic, package_identity, insufficient_evidence, or not_applicable.

## Guarded Evaluation

The guarded evaluator refuses these templates while all rows are draft:

```bash
python3 experiments/rq3_adjudication/evaluate_rq3_human_audit.py --field severity
python3 experiments/rq3_adjudication/evaluate_rq3_human_audit.py --field affected_versions
```

It writes `*_gold_audit_eval_metrics.*` only after valid `audit_status=final` rows exist.

## Current Counts

- `severity`: `80` blank audit rows
- `affected_versions`: `100` blank audit rows
