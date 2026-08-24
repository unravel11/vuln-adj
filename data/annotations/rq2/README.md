# RQ2 Discrepancy-Typing Annotation Seed

This directory contains a stratified seed sample for building the RQ2 human discrepancy-typing gold set.

The files are annotation templates, not completed gold labels. Baseline labels are deterministic outputs to audit.

## Files

- `discrepancy_typing_seed.jsonl`: full JSON annotation template.
- `discrepancy_typing_seed.csv`: spreadsheet-friendly annotation template with compact JSON cells.
- `consistency_review/`: 20% second-pass annotation template for agreement checks.
- `sample_manifest.json`: sampling configuration and strata counts.
- `../../../docs/annotation_guidelines/rq2_discrepancy_typing.md`: draft guideline for filling manual labels.

## Annotation Columns

- `manual_status`: one of equivalent, representation_discrepancy, incomplete, temporal_discrepancy, factual_conflict, uncertain.
- `manual_rationale`: short reason for the manual status.
- `is_baseline_correct`: yes, no, or uncertain.
- `needs_adjudication`: yes only when the manual status is factual_conflict and evidence adjudication is required.
- `evidence_urls`: optional supporting URLs for boundary cases.
- `annotator_notes`: free-form notes.

## Sampling Summary

- Seed: `20260524`
- Target per field: `60`
- Total sampled instances: `300`
