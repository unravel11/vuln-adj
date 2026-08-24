# RQ2 Reference Resource-Identity Evidence Review

You are reviewing reference-URL identity groups from a complete rule-impact
set. The masked JSONL input contains neutral group IDs, original NVD/GHSA URLs,
and frozen HTTP probe records. It contains no prior reviewer label, candidate
resource identity, transformation name, expected final label, or performance
result.

Do not use prior project labels, another reviewer's output, or live web lookup.
Judge only the supplied row.

The question is whether every `identity_groups` entry joins URLs that denote
the same underlying reference resource. Infer the relationship from the raw
URLs and frozen probe evidence; do not assume that a visually similar URL is an
alias. A fetch failure by itself is neither proof of equality nor proof of
difference. Generic login, denial, rate-limit, and anti-bot pages are not
resource-content evidence.

Use `all_aliases_same_resource` only when every required group is supported by
its raw URL structure and probe evidence. Use `one_or_more_not_same` when at
least one joined group identifies different resources. Use `insufficient` when
the supplied snapshot cannot decide. Do not treat a fetch failure by itself as
proof of different resources.

For every input row, preserve input order and write exactly one JSON object with
these keys:

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

`final_status` must be `incomplete` for `all_aliases_same_resource`,
`representation_discrepancy` for `one_or_more_not_same`, and `uncertain` for
`insufficient`. `group_decisions` must contain exactly one object per required
group with keys `group_id`, `same_resource`, and `reason`.
`same_resource` must be `true`, `false`, or `null`. Use `null` only when the
group evidence is insufficient. `all_aliases_same_resource` requires every
group to be `true`; `one_or_more_not_same` requires at least one `false`;
`insufficient` requires at least one `null` and no `false`.

`needs_additional_review` must be a JSON boolean. `low` confidence requires
`needs_additional_review=true`. An `insufficient` row must use `low` confidence
and `needs_additional_review=true`. Each row-level `rationale` must contain at
least 120 characters, and each group-level `reason` at least 40 characters.

All decisions are non-human expert candidates. Do not claim human annotation or
human gold.
