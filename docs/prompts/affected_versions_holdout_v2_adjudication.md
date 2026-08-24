# Affected-Versions Holdout v2 Adjudication Contract

You are reviewing a frozen affected_versions holdout that is disjoint from both
the original development cohort and the v1 holdout. You are a Codex reviewer,
not a human annotator. Every row must set `label_is_human=false`.

## Isolation

- Read only the assigned v2 blind worklist and this contract.
- Do not read v2 source rows outside the blind file, method code, predictions,
  previous labels, v1 decisions, another reviewer's output, or result metrics.
- Do not fetch new evidence or call another model. Missing text is not
  contradiction.
- Preserve input order and decide every row independently.
- Use the assigned `reviewer_id` and a unique `review_run_id`. Record the exact
  prompt and blind-worklist SHA-256 values supplied with the assignment.

## Two separate tasks

### Task 1: discrepancy typing

First decide whether the source values are comparable and which discrepancy
type is supported:

- `equivalent`: same artifact and same affected set after defensible canonicalization.
- `representation_discrepancy`: same affected set expressed with compatible
  point/range, inclusive/exclusive, package-alias, or schema conventions.
- `incomplete`: one source omits a supported affected package, branch, or strict
  subset that the other source includes; do not use this label merely because
  one interval text is wider.
- `temporal_discrepancy`: the difference is supported as a snapshot/update-time
  change rather than a simultaneous contradiction.
- `factual_conflict`: the same artifact and scope have explicitly incompatible
  affected/fixed claims in the frozen evidence.
- `uncertain`: artifact identity, scope, ordering, or evidence is insufficient.

Use `artifact_relation=multi_artifact_scope` when the CVE covers distinct
packages or distribution/upstream artifacts. Do not compare their numeric
versions as one ordered domain. A shared CVE, vendor, advisory, or repository is
not sufficient to prove `same_artifact`.

Set `type_status=abstain` only for `uncertain`; otherwise set it to
`determinate`. A determinate type must cite at least one available URL in
`type_evidence` unless exact equivalence is fully visible in the structured
source values.

### Task 2: source adjudication, only for factual conflicts

If Task 1 is not `factual_conflict`, set:

```text
reviewed_source=not_applicable
source_status=not_applicable
source_confidence=not_applicable
```

and leave `positive_support` and `contradiction_or_scope_exclusion` empty.

For `factual_conflict`, choose `nvd`, `ghsa`, `neither`, or `abstain`:

- A one-sided source requires positive support for that source and explicit
  contradiction or scope exclusion for the other.
- `neither` requires a supported third value or explicit contradiction of both.
- Otherwise use `abstain`. Source abstention does not erase a determinate FC type.

If both values are supported only under distinct scopes, Task 1 is not a strict
same-scope factual conflict. Use the supported non-FC type or `uncertain`.

Only cite URLs whose record has `fetch_status=ok` and non-empty `text_snippet`.
All evidence maps have exactly these keys:

```json
{"nvd": [], "ghsa": [], "third": []}
```

For every cited URL, add a structured object to `evidence_claims` with exactly:

```text
url, endpoint, target, role, quote, interpretation
```

`endpoint` is `type` or `source`; `target` is `nvd`, `ghsa`, or `third`;
`role` is `type_support`, `positive_support`, `contradiction`,
`scope_exclusion`, or `third_value`. `quote` must be a literal substring of the
frozen title/snippet and `interpretation` must explain the claim. A URL may play
multiple roles only through separate claim objects.

## Output schema

Write exactly one JSON object per input row with exactly these keys:

```text
sample_id, cve_id, field, reviewer_id, review_run_id, prompt_sha256,
blind_worklist_sha256, artifact_relation, discrepancy_label,
type_status, type_confidence, type_evidence, reviewed_source,
source_status, source_confidence, positive_support,
contradiction_or_scope_exclusion, evidence_claims, artifact_assessment, range_assessment,
type_rationale, source_rationale, unresolved, label_is_human
```

`artifact_relation` is `same_artifact`, `different_artifact`,
`multi_artifact_scope`, or `uncertain`. Type confidence is `high`, `medium`, or
`low`; source confidence additionally allows `not_applicable`. A low-confidence
type must be `uncertain`/`abstain`. A low-confidence FC source must use
`reviewed_source=abstain` and `source_status=abstain`.

Compatibility rules:

- `equivalent`, `representation_discrepancy`, `temporal_discrepancy`, and
  `factual_conflict` require `same_artifact`.
- `different_artifact` or an uncertain artifact relation requires
  `discrepancy_label=uncertain`.
- `multi_artifact_scope` may be `incomplete` only when omission is supported;
  otherwise use `uncertain`.
