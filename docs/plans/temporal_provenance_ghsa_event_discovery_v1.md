# GHSA Accepted-Event Discovery and Main-State Mapping V1

**Frozen on**: 2026-08-31, after limited workflow-resolution probes and before
the full merged-PR census or outcome analysis  
**Status**: `E1_DISCOVERY_METHOD_HARDENED_BEFORE_ACQUISITION`

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

The observable population is every merged pull request that remains public at
acquisition time through both frozen GitHub REST routes below and whose exact
`pull_request.merged_at` satisfies:

```text
2024-01-01T00:00:00Z <= merged_at < 2026-01-01T00:00:00Z
```

This wording is deliberate: the study cannot recover a PR that was historically
public but was later deleted or made unavailable. It therefore does not claim a
census of every PR that ever existed.

The primary enumeration uses GitHub's Issues Search REST API with the fixed
query:

```text
repo:github/advisory-database is:pr is:merged merged:START..END
```

The search census is partitioned by natural month, requests `per_page=100`,
follows all reported pages, and fixes `sort=created&order=asc` for stable
traversal. A second search pass is run after the independent REST listing
below. Both use `X-GitHub-Api-Version: 2022-11-28`. The authentication mode
(`authenticated_public` or `unauthenticated_public`) is recorded, but
authentication secrets are never serialized into a request ledger or response
artifact.
If a monthly query reports more than 1,000 results, that month is partitioned
by UTC day before any items are used. Rows are deduplicated only by PR number,
and the exact timestamp predicate above is reapplied after parsing.

The independent enumeration walks the ordinary Pull Requests REST endpoint:

```text
GET /repos/github/advisory-database/pulls
    ?state=closed&sort=created&direction=asc&per_page=100&page=N
```

It follows the endpoint's complete pagination from page 1, then retains only
rows satisfying the exact `merged_at` predicate. It does not use a search date
index. Search and ordinary-pulls responses, headers, acquisition times, HTTP
statuses, attempt numbers, and response digests are all retained.

The census passes completeness only when all of the following hold:

- every query returns `incomplete_results=false`;
- every shard's observed unique count equals its reported `total_count`;
- monthly shards are pairwise non-overlapping after PR-number deduplication;
- the monthly union count equals the whole-window Search `total_count` (a
  Search self-consistency check, not independent evidence);
- the first Search union, ordinary-pulls union, and second Search union have
  exactly the same PR numbers and `merged_at` values; and
- no requested page is absent, truncated, or represented only by a failed
  response.

Logged-out GitHub HTML search may be retained as a display-level corroboration
only. It is not an independent census. Dynamic HTML, anti-bot, pagination, any
REST-set disagreement, or replay disagreement sets the manifest to
`manifest_incomplete`; no field denominator is reported as exhaustive.

The PR body phrases `Affected products` and `References` may be recorded as
screening metadata, but they are neither admission rules nor semantic field
labels. Every PR in the merged population must be inspected through its
actual advisory JSON changes. Body-search counts are candidate upper bounds,
not field-change counts.

## 3. Raw PR and Git evidence

For every PR, retain:

- the raw pull-request REST object and timeline objects;
- PR number, author, title, body, public URL, base ref, base SHA, head ref, head
  SHA, `merge_commit_sha`, exact `merged_at`, and merge timeline `commit_id`;
- the raw PR diff or patch plus its response and attempt metadata;
- every page of the PR files REST response, including rename metadata and any
  missing or truncated patch body;
- the public `refs/pull/<number>/head` mapping when present;
- every changed advisory path and GHSA identifier;
- the complete proposal-before and PR-head proposal-after JSON bytes for each
  changed advisory, not only patch hunks; and
- raw object digests and Git object IDs needed to reproduce the projection.

A single frozen `git ls-remote --refs` response for `refs/pull/*/head` is used
as the primary bulk head map. The ref is an object-discovery aid, not authority
for which revision was accepted. Its SHA must equal the raw PR object's final
`head.sha`; a mismatch is unresolved. The timeline's merged `commit_id` must
equal `merge_commit_sha`. The recorded base, head, and merge commit objects are
fetched and retained when public.

The accepted proposal projection is always the delta between full preimage and
postimage blobs named by the final PR diff. Full blob IDs are recovered by a
`--full-index` Git diff over the recorded base/head objects or the merge object
and verified against the diff; the route is recorded. For a merge object with
two parents, the target-branch parent and accepted head parent are also
verified. The head commit's first parent is never assumed to be the PR base.
Patch hunks alone, a later base-branch tip, or a convenient merge base cannot
reconstruct a missing blob. If the final accepted revision or either complete
blob cannot be recovered unambiguously, the field candidate fails closed.

The main-state mapper reads the already pinned full GHSA repository and never
substitutes its transport HEAD for the frozen source pin.

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

The provider object key is `ghsa_id`, not CVE alone. For affected entries, the
object key additionally includes the exact `(ecosystem, name, purl)` package
identity; duplicate indistinguishable package keys are ambiguous. A CVE alias
is a downstream join. A GHSA with multiple CVE aliases is not split into
separate CVE events unless the PR evidence explicitly isolates one alias.

Atomic deltas are frozen as multisets:

- one affected atom is the complete canonical affected entry for one exact
  package key, including every range, ordered range event, explicit version,
  and database-specific affected value; and
- one reference atom is `(source_type, canonical_url, resource_type)`.

Thus a boundary edit is removal of one complete affected atom plus addition of
another. The mapper does not infer equivalence between two range encodings or
split one affected atom after seeing a convenient main outcome.

For the reference field, each `(type, raw_url)` remains available. A separate
resource classifier labels canonical direct commit, pull-request/merge-request,
and patch/diff URLs. A generic repository, issue, release, compare, advisory,
or documentation URL is not promoted to a fixing reference by URL shape.
`known_vfc_match` remains an external downstream label and is never inferred
from the PR or GHSA acceptance decision.

## 5. Mapping an accepted PR to published `main`

First enumerate the complete first-parent ancestry of the pinned `main` commit
without `--since` or `--until`. Only after the topological sequence and every
parent/child OID are materialized may the implementation inspect encoded Git
committer timestamps and identify the operational interval from `merged_at` to
`merged_at + 14 days`. Non-monotone or negative-delay timestamps are retained
as `clock_anomaly`; they are never silently skipped. Merge commits are not
filtered out. Changed paths are computed against the first parent, including
merge commits, so a direct merge cannot disappear from the scan.

The mapper searches by GHSA identifier across both reviewed and unreviewed
paths. For every candidate main transaction it reads:

```text
before = <main_commit>^1:<before_path>
after  = <main_commit>:<after_path>
```

and compares the tracked field projections. Git committer time is only the
timestamp encoded in the public commit object; it does not independently prove
the wall-clock instant at which a user could fetch the commit. PR `merged_at`,
JSON `modified`, Git committer timestamp, and acquisition `observed_at` remain
separate.

Attribution must pass one of two frozen routes before delta similarity is
considered:

- `direct_git_bound`: the final PR base is `main`, the PR merged event and REST
  object agree on `merge_commit_sha`, and that exact object is on the pinned
  main first-parent ancestry at the mapped transaction. Its parent/child state
  defines main before/after.
- `staging_workflow_bound`: the final base matches
  `*/advisory-improvement-<PR_NUMBER>`, the timeline contains the bot base-ref
  change and merged event, the merged event agrees with the retained staging
  merge object, and the topologically first main transaction in the 14-day
  operational window has the same GHSA/package/field proposal delta. No other
  PR for that source object and field may compete for that main transaction.

The second route is a deterministic public-workflow link, not Git ancestry and
not proof of causation. It is always reported separately from
`direct_git_bound`. A same-GHSA or same-field edit found only by time proximity
or outcome similarity is `unlinked_same_field_event`, even when it looks
plausible. Every candidate main event in topological order is retained; the
mapper never selects the event with the highest overlap.

Let `delta_proposal` be the multiset additions/removals from complete PR-before
to PR-after atoms, and `delta_main` the corresponding main-parent to main-child
delta. The proposal-to-main relation is assigned independently for each
PR/GHSA/package-or-null/field:

- `exact`: `delta_main == delta_proposal` as multisets;
- `partial`: a non-empty, direction-preserving subset of proposal atoms occurs
  in `delta_main`, but the deltas are not equal;
- `already_present_before_disposition`: all proposed additions are already in
  the main state and all proposed removals are already absent before merge;
- `same_field_nonmatching_or_unlinked`: a same-field main delta exists but has
  no proposal-atom overlap or fails a route-binding requirement;
- `no_field_delta`: main appears in the window but the tracked field does not
  change;
- `ambiguous_many_to_one`: multiple accepted PRs for the same advisory/field
  cannot be separated in one main transaction; or
- `unresolved_14d`: no attributable main field event is found within 14 days.

Only route-bound `exact` relations enter the primary provider-accepted metadata
change cohort and the primary downstream before/after analysis. `partial` is a
separate sensitivity cohort only when the adopted atoms can be isolated
mechanically; the complete main transition is not attributed to the PR.
`already_present_before_disposition`, nonmatching/unlinked, ambiguous, and
unresolved relations fail closed. This classification supersedes the earlier
`substituted` label because a nonmatching nearby change does not reveal curator
intent.

## 6. Stability, transaction, and dependence controls

For a mapped event, enumerate the complete subsequent first-parent sequence
through the first topologically later commit whose encoded committer timestamp
reaches the seven-day operational boundary. Inspect every intervening state,
including commits with no tracked-field edit, and the boundary state. Every
added atom must remain present and every removed atom absent. File deletion,
reviewed/unreviewed path migration, and second or later edits are followed by
GHSA identifier. Any reversal, missing path without a verified migration,
overlap ambiguity, or timestamp-order anomaly fails stability. A later
reapplication is a new event. This is Git-history persistence under an encoded
timestamp window, not proof of real-time public availability.

For every PR and mapped main transaction record:

- changed advisory-file count and total changed-file count;
- commit subject and detected publication route;
- author, UTC merge day, exact body digest, and the mechanical
  `(author, UTC merge day)` cluster;
- the number of PR/advisory/field candidates mapped to the same main commit;
  and
- whether the transaction is a projection no-op, verified path-only migration,
  seven-day rollback/reapplication, or field-changing event.

Changed-file count alone does not make a route-bound exact event ineligible: a
bot sync can publish several separately attributable accepted PRs. Counts are
reported in frozen strata `1`, `2--9`, `10--99`, and `>=100`; `>=100` is named
`bulk_like_transaction` but is not a semantic judgment. Projection no-ops and
path-only changes are mechanically out of field scope. No event is labeled
"campaign", "schema correction", or "ordinary natural correction" by manual
inspection after outcomes are known.

Primary inference keeps event, GHSA, and unique-CVE denominators and clusters
by author, `(author, UTC merge day)`, and main transaction. Sensitivity analyses
exclude multi-advisory transactions, `bulk_like_transaction`, and the two
highest-volume authors separately. These exclusions cannot replace the full
denominator. If one author/day or main transaction dominates, the parent
bulk-dominance gate is evaluated directly rather than hidden by a subjective
campaign label.

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
- `direct_git_bound`, `staging_workflow_bound`, unlinked, `exact`, `partial`,
  already-present, ambiguous, and unresolved relations;
- author, author/day, and main-transaction concentration; and
- affected-range and fix-reference results separately.

The parent stop gate remains unchanged: fewer than 50 route-bound, stable,
exact provider-accepted metadata changes for either primary field returns
`NO_GO` for the broad two-field route. A large merged-PR count, successful main
mapping, or accepted proposal does not establish factual correction, semantic
truth, downstream effect, novelty, or paper readiness.
