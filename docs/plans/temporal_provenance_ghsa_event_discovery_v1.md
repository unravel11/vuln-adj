# GHSA Accepted-Event Discovery and Main-State Mapping V1

**Frozen on**: 2026-08-31, after limited workflow-resolution probes and before
the full merged-PR census or outcome analysis  
**Status**: `E1_DISCOVERY_METHOD_FROZEN`  
**Parent protocol**: `docs/plans/temporal_provenance_pilot_v1.md`  
**Event contract**:
`docs/annotation_guidelines/accepted_correction_event_contract_v1.md`

## 1. Why this addendum is necessary

The parent protocol assumed that a merged public improvement PR could be
connected to a stable GHSA main-branch state. Limited workflow-resolution
probes showed that the repository uses at least two publication routes:

1. a PR may merge directly into `main`; or
2. a PR may merge into a contributor-specific staging branch and later appear
   on `main` through a bot publication transaction.

They also found a counterexample in which a merged PR proposed two commit URLs
but the later main state contained two different commit URLs. Consequently,
the PR proposal, the accepted disposition, and the published main state are
three separate evidence objects. A merged PR cannot be copied directly into
the event ledger as the provider's final field value.

The probes were used only to resolve this workflow and choose an acquisition
algorithm. They are not the full census, are not an effect estimate, and do
not change the frozen 50-event, replay, payload-loss, downstream-execution, or
claim-ceiling gates.

## 2. Frozen population and completeness gate

The population is every public pull request in
`github/advisory-database` whose exact `pull_request.merged_at` satisfies:

```text
2024-01-01T00:00:00Z <= merged_at < 2026-01-01T00:00:00Z
```

Acquisition uses GitHub's public Issues Search API with the fixed query:

```text
repo:github/advisory-database is:pr is:merged merged:START..END
```

The census is partitioned by natural month, requests `per_page=100`, follows
all reported pages, and fixes `sort=created&order=asc` for stable traversal. It
stores the raw JSON response, request URL, response headers, acquisition time,
HTTP status, attempt number, and response digest. Authentication secrets are
never serialized into a request ledger or response artifact.
If a monthly query reports more than 1,000 results, that month is partitioned
by UTC day before any items are used. Rows are deduplicated only by PR number,
and the exact timestamp predicate above is reapplied after parsing.

The census passes completeness only when all of the following hold:

- every query returns `incomplete_results=false`;
- every shard's observed unique count equals its reported `total_count`;
- monthly shards are pairwise non-overlapping after PR-number deduplication;
- the monthly union count equals the independent whole-window
  `total_count`; and
- no requested page is absent, truncated, or represented only by a failed
  response.

Logged-out GitHub HTML search is retained only as an independent count probe
when available. Dynamic HTML, anti-bot, or pagination failures cannot replace
the API completeness gate. If the gate fails, the manifest is
`manifest_incomplete`; no field denominator is reported as exhaustive.

The PR body phrases `Affected products` and `References` may be recorded as
screening metadata, but they are neither admission rules nor semantic field
labels. Every PR in the merged population must be inspected through its
actual advisory JSON changes. Body-search counts are candidate upper bounds,
not field-change counts.

## 3. Raw PR and Git evidence

For every PR, retain:

- PR number, author, title, body, public URL, base ref, base SHA, head ref, head
  SHA, and exact `merged_at`;
- the raw PR diff or patch plus its response and attempt metadata;
- the public `refs/pull/<number>/head` mapping when present;
- every changed advisory path and GHSA identifier;
- the complete proposal-before and PR-head proposal-after JSON bytes for each
  changed advisory, not only patch hunks; and
- raw object digests and Git object IDs needed to reproduce the projection.

A single frozen `git ls-remote --refs` response for `refs/pull/*/head` is used
as the primary bulk head map. Missing refs are retained and may be resolved
from the PR API or raw diff metadata, but the fallback and its evidence source
must be explicit. Proposal-before is read from the PR's recorded base SHA or
from an exact preimage Git blob named by the diff; the head commit's first
parent is not assumed to be the PR base. If the full preimage cannot be
recovered, the field candidate fails closed rather than being reconstructed
from an incomplete patch hunk. The main-state mapper reads the already pinned
full GHSA repository and never substitutes its transport HEAD for the frozen
source pin.

HTTP failures are append-only acquisition attempts. A failed deterministic
sample position is not replaced. Full-census failures remain unresolved rows;
bounded retries may add attempts but cannot erase the original failure.

## 4. Proposal projection and path handling

Changed files are identified from Git/diff evidence and reparsed from complete
JSON. Both path families are searched because an advisory may migrate during
publication:

```text
advisories/unreviewed/**/GHSA-*.json
advisories/github-reviewed/**/GHSA-*.json
```

Path movement alone is not a semantic field change. For each changed advisory,
the parser preserves the full affected-package/range and reference projections
defined by the parent event contract. Field candidates are produced from
semantic projection differences, not whole-file hashes, timestamps, key order,
summary text, or PR-body checkboxes.

Raw projections retain source order and positions. Semantic comparison removes
only list-position bookkeeping, canonicalizes the permitted URL syntax, sorts
order-insensitive package/range/reference entries, and retains multiplicity.
It does not collapse distinct packages, infer release ordering, or equate two
range representations merely because they may select the same versions. Both
the raw ordered projection and comparison projection are stored.

For the reference field, each `(type, raw_url)` remains available. A separate
resource classifier labels canonical direct commit, pull-request/merge-request,
and patch/diff URLs. A generic repository, issue, release, compare, advisory,
or documentation URL is not promoted to a fixing reference by URL shape.
`known_vfc_match` remains an external downstream label and is never inferred
from the PR or GHSA acceptance decision.

## 5. Mapping an accepted PR to published `main`

For each PR/advisory/field candidate, enumerate every first-parent `main`
commit whose committer time falls in the closed interval from `merged_at` to
`merged_at + 14 days`. Merge commits are not filtered out. Changed paths for a
commit are obtained against its first parent, including merge commits, so a
direct merge cannot disappear from the scan.

The mapper searches by GHSA identifier across both reviewed and unreviewed
paths. For every candidate main transaction it reads:

```text
before = <main_commit>^1:<before_path>
after  = <main_commit>:<after_path>
```

and compares the tracked field projections. Committer time is the public main
transaction time; PR `merged_at` is the accepted-disposition time; JSON
`modified` is the provider record time; acquisition time is `observed_at`.
None substitutes for another.

The proposal-to-main relation is assigned independently for each
PR/advisory/field:

- `exact`: the main-after field projection equals the PR-after projection;
- `partial`: at least one proposed semantic addition/removal is adopted, but
  the complete projections differ;
- `substituted`: main changes the same field but adopts none of the proposed
  semantic delta;
- `no_field_delta`: main appears in the window but the tracked field does not
  change;
- `ambiguous_many_to_one`: multiple accepted PRs for the same advisory/field
  cannot be separated in one main transaction; or
- `unresolved_14d`: no attributable main field event is found within 14 days.

Only `exact` and `partial` relations can satisfy proposal adoption in the
primary eligible-accepted-correction cohort. `substituted` is retained as
`accepted_but_proposal_not_adopted`; its main transition may be analyzed as a
provider change, but it cannot be represented as the accepted proposal.
`ambiguous_many_to_one` and `unresolved_14d` fail closed. This classification
amends the event contract before the full census because the original list did
not distinguish a mapped main state from adoption of the proposed value.

## 6. Stability, transaction, and campaign controls

An `exact` or `partial` main state is stable only when the adopted semantic
delta is not reverted during the next seven days. If another tracked-field edit
occurs sooner, preserve that complete transition and determine whether it
removes the adopted delta; an unresolved overlap fails closed. A later
reapplication is a new candidate event.

For every PR and mapped main transaction record:

- changed advisory-file count and total changed-file count;
- commit subject and detected publication route;
- author, UTC merge day, and repeated-template/campaign identifiers;
- the number of PR/advisory/field candidates mapped to the same main commit;
  and
- whether the transaction is a path migration, schema rewrite, backfill,
  generated reorder, mirror rollback, or ordinary publication sync.

Changed-file count alone does not make a correction ineligible: a bot sync can
publish several independently attributable accepted PRs. Counts are reported
in frozen strata `1`, `2--9`, `10--99`, and `>=100`. A transaction is
`bulk_or_schema_event` only when the semantic changes are mechanical or the
individual accepted deltas cannot be attributed; it is not classified by a
convenient numerical cutoff chosen after observing effects.

Primary inference keeps event and unique-CVE denominators and clusters by at
least author/campaign and main transaction. Sensitivity analyses exclude
multi-advisory transactions, repeated campaigns, and the two highest-volume
authors separately. These exclusions cannot replace the full denominator.

## 7. Frozen workflow probes and seeds

Before this addendum, public count probes reported 1,941 whole-window merged
PRs, including 1,488 body-search candidates for `Affected products` and 825 for
`References`. These values are acquisition reconciliation targets only. They
do not establish field changes or eligible corrections.

Two fixed workflow-resolution samples were used:

```text
SHA256("ghsa-reference-pilot-v1:" + decimal_pr_number)
SHA256("ghsa-main-propagation-pilot-v1:" + decimal_pr_number)
```

The first ranks the 825 body-search reference candidates and takes 50; the
second ranks strict commit-URL candidates successfully parsed from that sample
and takes 20. The first sample retained one HTTP 429 failure without
replacement. These samples may be reported only as method-resolution evidence
and counterexamples. They cannot be pooled into the full-census effect or used
to change thresholds.

## 8. Outputs and fail-closed decision

The discovery stage writes separate append-only objects for search responses,
request attempts, PR metadata, pull-head mappings, raw diffs, raw advisory
states, proposal projections, main before/after states, stability checks, and
the final event ledger. Every processed row must join back to raw evidence.

At minimum, the stage reports:

- merged-population, field-candidate, main-mapped, stable, eligible, and
  executable denominators;
- every exclusion and unresolved reason;
- `exact`, `partial`, `substituted`, ambiguous, and unresolved relations;
- author/campaign and main-transaction concentration; and
- affected-range and fix-reference results separately.

The parent stop gate remains unchanged: fewer than 50 eligible accepted
corrections for either primary field returns `NO_GO` for the broad two-field
route. A large merged-PR count, successful main mapping, or accepted proposal
does not establish semantic truth, downstream effect, novelty, or paper
readiness.
