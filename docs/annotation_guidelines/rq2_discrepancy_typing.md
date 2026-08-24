# RQ2 Discrepancy-Typing Annotation Guideline

Status: draft guideline for `data/annotations/rq2/discrepancy_typing_seed.{jsonl,csv}`. This document supports human annotation; it is not an evaluation result.

## Goal

For each sampled field instance, assign a manual discrepancy type to the NVD value and GHSA value after considering the field context. The manual label should audit the deterministic baseline status, not copy it.

The output column is `manual_status`.

Allowed values:

- `equivalent`
- `representation_discrepancy`
- `incomplete`
- `temporal_discrepancy`
- `factual_conflict`
- `uncertain`

Use `uncertain` only when the provided values and context are insufficient for a reliable label. Do not use `uncertain` merely because the baseline and manual judgment differ.

## General Rules

Mark `equivalent` when both sides express the same field meaning after straightforward normalization.

Mark `representation_discrepancy` when the values look different in raw form or schema but are compatible descriptions of the same fact. Examples include severity synonyms such as GHSA `MODERATE` versus canonical `MEDIUM`, same-day timestamp formatting differences, or affected-version bounds that encode the same effective endpoint.

Mark `incomplete` when one side has a strict subset, missing value, or less complete list while the available overlapping content is compatible. This label does not choose a more trustworthy source; it records missing coverage.

Mark `temporal_discrepancy` when the field difference is best explained by publication or update timing rather than contradiction. This label is expected mainly for `published`.

Mark `factual_conflict` when both sides provide incompatible factual claims after normalization and the difference cannot be explained as representation, incompleteness, or timing.

Mark `uncertain` when package identity, version semantics, field schema, or missing context prevents a reliable decision.

## Field-Specific Guidance

### severity

Use canonical severity labels when available.

- `equivalent`: same raw and canonical label, or same score/vector meaning.
- `representation_discrepancy`: raw labels differ but canonical labels match, such as `MODERATE` and `MEDIUM`.
- `incomplete`: severity is present on one side and missing or unusable on the other.
- `factual_conflict`: canonical labels differ, such as `LOW` versus `HIGH`, unless evidence in the row shows that one side is using a different CVSS version or scope that makes the comparison uncertain.
- `temporal_discrepancy`: normally not used for severity in this seed.

### published

Compare publication timestamps as dates and times.

- `representation_discrepancy`: same calendar date with different formatting, timezone, precision, or timestamp notation.
- `temporal_discrepancy`: different calendar dates or a meaningful publication-time lag between NVD and GHSA.
- `incomplete`: one side lacks a usable publication value.
- `factual_conflict`: use only if both values purport to be the same publication fact but are incompatible and not plausibly explained by source timing.
- `equivalent`: use only if values are the same after normalization.

### references

Compare normalized URLs, hosts, and shared advisory/commit/vendor evidence.

- `equivalent`: both sides contain the same canonical references after deduplication.
- `representation_discrepancy`: references differ but point to overlapping evidence sources or equivalent pages, such as the same advisory plus related repository or commit links.
- `incomplete`: one side is a strict subset of the other, or one side has references while the other has none.
- `factual_conflict`: reference sets are disjoint and appear to point to unrelated evidence sources for the same CVE.
- `uncertain`: use when dynamic pages, redirects, or opaque vendor URLs make equivalence impossible to judge from the row alone.

### affected_versions

Check package identity first. Version strings from different packages or ecosystems may not be directly comparable.

- `equivalent`: the affected spans are the same after canonicalization.
- `representation_discrepancy`: spans differ syntactically but encode compatible bounds, such as fixed/end_excluding representations of the same endpoint, a point version covered by a range, or a prefix-truncation boundary already explainable from the row.
- `incomplete`: one side lists a strict subset of affected spans or has one-sided version information while the overlap remains compatible.
- `factual_conflict`: package identity is comparable and the affected ranges are incompatible after accounting for representation differences and subset relationships.
- `uncertain`: package identity differs, ecosystem version ordering is unclear, or the row lacks enough context to compare spans reliably.

### cwe_ids

Treat CWE IDs as sets.

- `equivalent`: same canonical CWE set, including both sides missing when the field is absent on both sides.
- `representation_discrepancy`: sets overlap but differ in granularity or contain related CWE IDs, and the difference is better treated as classification granularity than a contradiction.
- `incomplete`: one side is a strict subset of the other or one side is missing.
- `factual_conflict`: non-empty sets are disjoint and describe incompatible weakness categories.
- `uncertain`: use when IDs are too broad or too sparse to judge whether the difference is granularity or conflict.

## Required Annotation Columns

Fill these columns in the CSV or JSONL annotation object:

- `manual_status`: one allowed value above.
- `manual_rationale`: one or two sentences explaining the label.
- `is_baseline_correct`: `yes`, `no`, or `uncertain`.
- `needs_adjudication`: `yes` only when `manual_status` is `factual_conflict` and a later evidence-based source/value decision is needed; otherwise `no`.
- `evidence_urls`: optional URLs used to resolve boundary cases.
- `annotator_notes`: optional notes about ambiguity, package mismatch, schema limitations, or follow-up checks.

## Quality Checks

Before running `experiments/rq2_discrepancy_typing/evaluate_rq2_manual_labels.py`, verify:

- No intended gold row has a blank `manual_status`.
- `manual_status` uses only allowed values.
- Rows marked `factual_conflict` have `needs_adjudication=yes` unless explicitly explained.
- Rows marked `uncertain` include a rationale.
- Baseline labels are not copied mechanically; `is_baseline_correct=no` is allowed and expected for some rows.

The evaluator intentionally refuses to compute metrics when manual labels are blank. `uncertain` is a valid completed annotation, but it is reported separately and excluded from the five-class accuracy and macro-F1 calculation. This prevents reporting RQ2 performance before the determinate gold subset is actually filled.
