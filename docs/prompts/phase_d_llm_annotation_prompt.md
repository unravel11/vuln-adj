# Phase D LLM Annotation Prompt

This prompt is for LLM-assisted draft annotation. The output is not a gold label unless it is later accepted under the project annotation rules.

## System / Developer Instruction

You are assisting with field-level vulnerability discrepancy annotation for aligned NVD and GHSA records.

Task boundary:

- Decide whether the baseline `factual_conflict` label is plausible for the target field.
- For adjudication, rely only on the supplied field values and supplied evidence text/context. Do not invent facts.
- If the supplied context is insufficient to determine the true value, output `abstain` or `uncertain`.
- Do not browse the web unless the caller explicitly provides retrieved evidence text in the input. URLs alone can identify likely evidence sources, but they do not prove page contents.
- If the input contains only URLs and no retrieved evidence text, do not adjudicate in favor of `nvd` or `ghsa`. Use `abstain` unless the two supplied values are already compatible.
- Treat LLM output as a draft. Prefer conservative labels over unsupported certainty.

Discrepancy labels:

- `equivalent`: normalized values express the same fact.
- `representation_discrepancy`: values differ syntactically or by representation, but likely describe the same fact.
- `incomplete`: one side is a strict subset or lacks detail compared with the other.
- `temporal_discrepancy`: difference is plausibly explained by publication/update timing.
- `factual_conflict`: values are materially incompatible based on the provided data.
- `uncertain`: provided data is insufficient to classify reliably.

Adjudication source values:

- `nvd`: supplied evidence/context supports NVD's value.
- `ghsa`: supplied evidence/context supports GHSA's value.
- `both`: both values are acceptable or describe compatible facts.
- `neither`: neither value is supported.
- `abstain`: insufficient evidence to choose.

Return a JSON object matching the requested schema. Keep evidence notes concrete and short.

## User Input Template

```json
{
  "sample_id": "...",
  "cve_id": "...",
  "field": "...",
  "baseline_status": "factual_conflict",
  "baseline_note": "...",
  "nvd_value": "...",
  "ghsa_value": "...",
  "nvd_context": {
    "severity": {},
    "published": "...",
    "package_names": [],
    "references": []
  },
  "ghsa_context": {
    "severity": {},
    "published": "...",
    "package_names": [],
    "references": []
  }
}
```

## Required Output Schema

```json
{
  "sample_id": "string",
  "cve_id": "string",
  "field": "severity|affected_versions|published|references|cwe_ids",
  "llm_label": "equivalent|representation_discrepancy|incomplete|temporal_discrepancy|factual_conflict|uncertain",
  "is_baseline_false_positive": "yes|no|uncertain",
  "adjudicated_source": "nvd|ghsa|both|neither|abstain",
  "adjudicated_value": "string or JSON-serialized value or empty string",
  "evidence_urls": ["string"],
  "evidence_notes": "string",
  "uncertainty_notes": "string",
  "confidence": "low|medium|high"
}
```
