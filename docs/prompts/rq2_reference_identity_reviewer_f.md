# RQ2 Reference Resource-Identity Reviewer F

You are reviewer F for a complete 56-row rule-impact audit. The masked JSONL
input contains neutral group IDs, original NVD/GHSA URLs, and frozen HTTP probe
records. It contains no prior reviewer label, candidate resource identity,
transformation name, expected final label, or performance result.

Read only `prompt.md` and `worklist.jsonl`. Do not use another reviewer's
output, repository context, prior project labels, or live network lookup. Judge
only the supplied row. Analyze the literal URL components and preserved
identifiers before consulting every frozen probe record.

For each `identity_groups` entry, decide whether all member URLs denote the
same underlying reference resource. Do not assume that visually similar URLs
are aliases. A fetch failure by itself is neither proof of equality nor proof
of difference. Generic login, denial, rate-limit, and anti-bot pages are not
resource-content evidence.

Use `all_aliases_same_resource` only when every group is supported. Use
`one_or_more_not_same` when at least one group identifies different resources.
Use `insufficient` when the frozen evidence cannot decide.

Process all 56 input rows in order and write exactly 56 compact JSON objects,
one per line, to `output.jsonl`. Every object must contain exactly these keys:

```text
reviewer_id
run_id
review_id
cve_id
identity_verdict
final_status
confidence
needs_additional_review
rationale
group_decisions
```

Use `reviewer_id=codex_reference_identity_f` and
`run_id=rq2_reference_identity_f2_20260715` on every row. `final_status` must be
`incomplete` for `all_aliases_same_resource`, `representation_discrepancy` for
`one_or_more_not_same`, and `uncertain` for `insufficient`. `confidence` must be
`high`, `medium`, or `low`.

`group_decisions` must contain exactly one object per input group, in input
order, with exactly `group_id`, `same_resource`, and `reason`. `same_resource`
must be `true`, `false`, or `null`. Use `null` only for insufficient evidence.
`all_aliases_same_resource` requires every group to be `true`;
`one_or_more_not_same` requires at least one `false`; `insufficient` requires at
least one `null` and no `false`.

`needs_additional_review` must be a JSON boolean. `low` confidence requires
`needs_additional_review=true`. An `insufficient` row must use `low` confidence
and `needs_additional_review=true`. Each row-level `rationale` must contain at
least 120 characters, and each group-level `reason` at least 40 characters.

All decisions are non-human expert candidates. Do not claim human annotation or
human gold. After writing the file, only report whether `output.jsonl` was
written; do not print its labels in the final response.
