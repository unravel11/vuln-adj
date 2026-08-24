# Affected-Versions Deno Lockfile Recovery Contract v1

## Status and scope

- Contract status: `codex_expert_contract_candidate_post_no_go_recovery`
- Parent contract:
  `affected_versions_unseen_ecosystem_graph_contract_v1.md`
- Fixed input row: `artifact_lineage_unseen_ecosystem_v1:cratesio`
- Fixed CVE: `CVE-2025-48888`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `development_diagnostic_only=true`
- `production_switch_allowed=false`

This contract is a post-no-go recovery diagnostic. The parent experiment
abstained because crates.io dependency records express compatible ranges and
the `deno` crate catalog does not provide a total product-release mapping. This
diagnostic tests whether official product tags and their committed
`Cargo.lock` files provide the missing exact build-time edge. It does not
relabel the sealed reviewers, create human gold, or establish a general rule
for Rust packages.

The contract is fixed before fetching GitHub release pages or tag-specific
lockfiles for this diagnostic.

## Fixed product-release domain

The product coordinate is the Deno application release, not the crates.io
`deno` package. Product releases come only from the official
`denoland/deno` GitHub Releases API. A release is eligible when all of the
following hold:

- the release is neither draft nor prerelease;
- its tag is exactly `vMAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH`;
- the parsed version has three nonnegative integer components;
- each parsed version occurs once after duplicate tags are rejected.

The fixed core window is every eligible product release from `1.41.3` through
`2.3.2`, inclusive, ordered by semantic version. The evidence inventory also
includes the immediate eligible predecessor of `1.41.3` and immediate eligible
successor of `2.3.2`. Release API pages are fetched sequentially at 100 records
per page until the response is empty; stopping early or failing to establish
both anchors forces abstention. This structural rule fixes the window without
using the eventual lockfile versions or set relation.

Every NVD and GHSA direct Deno boundary (`1.41.3`, `2.1.13`, `2.2.0`,
`2.2.13`, `2.3.0`, and `2.3.2`) must exist in the frozen product-release
domain. The relation is computed only over the core window; the two anchors
are boundary checks and are not included in either affected set.

## Exact lockfile edge

For every core-window release and both anchors, fetch the committed lockfile
from the official tag at:

`https://raw.githubusercontent.com/denoland/deno/<tag>/Cargo.lock`

The product release maps to `deno_runtime` only when all checks pass:

- the response is the lockfile at the exact release tag selected by the
  Releases API;
- TOML parsing succeeds;
- exactly one `[[package]]` entry has `name = "deno_runtime"`;
- that entry contains one parseable exact semantic `version`;
- the exact runtime version exists in the frozen official crates.io
  `deno_runtime` catalog;
- no product release or anchor is missing a valid exact mapping.

A dependency requirement, Cargo manifest range, branch name, latest-version
pointer, or crates.io `deno` release is not an exact product mapping. The
ordered exact runtime sequence across predecessor, core window, and successor
must be monotonic nondecreasing. Any violation forces abstention rather than
dropping the offending release.

## Boundary containment gates

The GHSA runtime claim is fixed as
`[0.150.0, 0.212.0)`. To show that its projection is bounded by the declared
product window, the immediate predecessor must map below `0.150.0` and the
immediate successor must map at or above `0.212.0`. Failure of either check
forces abstention.

Within the core product domain:

- the NVD product set is the union of direct Deno releases in
  `[1.41.3,2.1.13)`, `[2.2.0,2.2.13)`, and `[2.3.0,2.3.2)`;
- the GHSA direct product set uses the same three Deno intervals;
- the GHSA runtime-projected set contains each product release whose exact
  mapped `deno_runtime` version is in `[0.150.0,0.212.0)`;
- the GHSA product set is the union of the direct and runtime-projected sets.

The analyzer retains the direct and runtime-projected sets separately, records
all product-to-runtime pairs, and computes the unchanged relation map:
`equal`, `nvd_subset_of_ghsa`, `ghsa_subset_of_nvd`, `overlap`, or `disjoint`.
The corresponding non-human discrepancy candidate is derived only after every
gate passes. It remains a development candidate even if the relation is
determinate.

## Fixed advancement rule

The recovery gate passes `1/1` only when:

- the fixed input row and all fixed claim boundaries match this contract;
- the complete official release domain and both anchors are established;
- every required tag has one exact, catalog-backed lockfile mapping;
- the mapping is monotonic nondecreasing;
- both outer boundary-containment checks pass; and
- an independent verifier recomputes identical product sets and relation from
  the frozen cohort and cached official evidence.

Passing means only that exact official build evidence recovers a deterministic
projection for this one previously rejected Deno row. Failure yields
`no_go_deno_lockfile_recovery_unstable`. Neither outcome is an accuracy,
reviewer-agreement, human-gold, generalization, or production-switch result.
