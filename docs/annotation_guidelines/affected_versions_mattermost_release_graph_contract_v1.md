# Affected-Versions Mattermost Release Graph Contract v1

> Superseded before set analysis. The official Releases API returned 100
> records on each of pages 1--10 and HTTP 422 on page 11, so the fixed
> empty-page termination rule was not executable. No release-set relation or
> development candidate was produced under v1. The cache is retained as input
> evidence for the explicitly post-failure v2 contract.

## Status and scope

- Contract status: `codex_expert_project_family_contract_candidate`
- Parent audit: `unresolved_affected_edge_class_audit_v1`
- Fixed rows: `rq2_typing_holdout_v1:544` and
  `rq2_typing_holdout_v1:808`
- Fixed CVEs: `CVE-2025-27933` and `CVE-2025-22449`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `development_diagnostic_only=true`
- `production_switch_allowed=false`

The parent structural audit selects Mattermost before this experiment reads
new project evidence. Both rows have stable GHSA
`github.com/mattermost/mattermost/server/v8` intervals that duplicate the NVD
Mattermost Server intervals, plus at least one broad Go pseudo-version or
legacy-module interval. The experiment tests whether official release and
commit evidence can project every claim component into one fixed product
domain. It does not treat a matching project name, timestamp order, or URL as
a release mapping.

This contract is fixed before fetching the GitHub release pages, pseudo-version
commit records, comparison records, or additional tag manifests used below.

## Fixed input signatures

`CVE-2025-22449` must contain:

- NVD `mattermost_server`: `[9.11.0,9.11.6)`;
- GHSA `github.com/mattermost/mattermost/server/v8`:
  `[9.11.0,9.11.6)` and
  `(-inf,8.0.0-20250102081831-64c566a8280b)`.

`CVE-2025-27933` must contain:

- NVD `mattermost_server`: `[9.11.0,9.11.9)`,
  `[10.3.0,10.3.4)`, and `[10.4.0,10.4.3)`;
- GHSA `github.com/mattermost/mattermost/server/v8`: the same three stable
  intervals plus `(-inf,8.0.0-20250218135018-e644e3c8e393)`;
- GHSA `github.com/mattermost/mattermost-server`:
  `(-inf,9.11.9)`.

Any input drift forces the corresponding row to abstain.

## Fixed product-release domain

The release source is the official `mattermost/mattermost` GitHub Releases
API, fetched at 100 records per page until the first empty page. Eligible
entries are non-draft, non-prerelease releases with an exact `vMAJOR.MINOR.PATCH`
tag. Duplicate eligible versions are rejected.

The fixed finite product domain contains exactly these 19 expected releases:

- `9.11.0` through `9.11.9`;
- `10.3.0` through `10.3.4`;
- `10.4.0` through `10.4.3`.

Every expected version must occur once in the official release inventory. No
other branch or prerelease is added after evidence retrieval. Set relations in
this diagnostic are explicitly scoped to this fixed domain.

## Current-module product edge

For every product release, fetch the committed manifest at
`https://raw.githubusercontent.com/mattermost/mattermost/v<VERSION>/server/go.mod`.
It must parse exactly one module directive equal to
`github.com/mattermost/mattermost/server/v8`. A missing or different manifest
breaks the total product-to-current-module edge for both rows.

The stable current-module intervals then use the product release's own semantic
version. This does not assert that arbitrary Go module versions and Mattermost
product versions are interchangeable outside the fixed, manifest-bound domain.

## Pseudo-version ancestry edge

For each fixed pseudo-version:

1. resolve its 12-character suffix with the official GitHub commit API;
2. require the full SHA to begin with that suffix;
3. require the commit's UTC committer timestamp to equal the 14-digit
   pseudo-version timestamp;
4. require `server/go.mod` at that exact commit to declare the current module;
5. fetch the official GitHub comparison `v<VERSION>...<PSEUDO_SHA>` for every
   product release in the fixed domain.

With the product tag as base and the pseudo commit as head:

- `ahead` means the release commit is a strict ancestor and is inside the
  exclusive-upper pseudo interval;
- `behind` or `identical` means it is outside;
- `diverged`, an API error, a missing record, or any unknown status leaves the
  release unmapped.

Every one of the 19 releases must receive a determinate mapping for a pseudo
claim. Commit or release timestamps alone cannot fill an ancestry gap.

## Legacy-module edge

For `github.com/mattermost/mattermost-server`, the diagnostic fetches
`https://raw.githubusercontent.com/mattermost/mattermost-server/v<VERSION>/go.mod`
for every fixed product release. A release maps to the legacy subject only when
that exact tag manifest exists and declares the exact legacy module path.

A `404`, repository redirect, same version string, or historical source
relationship is not a negative or positive mapping. Because the claim is a
union component, all 19 product releases need determinate tag-level legacy
membership before `CVE-2025-27933` can be projected. Otherwise that row
abstains; the component is not silently dropped.

## Set construction and row gates

For a row to pass:

- the fixed input signature and 19-release domain must match;
- the current-module manifest edge must be total;
- every pseudo commit and all 19 ancestry comparisons must be bound; and
- when present, the legacy-module edge must be total.

Only then are NVD and GHSA affected-release sets constructed over the fixed
domain. GHSA is the union of its stable current-module, pseudo-version, and
legacy-module projections. The relation is one of `equal`,
`nvd_subset_of_ghsa`, `ghsa_subset_of_nvd`, `overlap`, or `disjoint`, and maps
to the unchanged non-human development candidate. A failed gate produces
`uncertain` and no set relation.

## Fixed advancement rule

The family diagnostic advances only when `2/2` rows pass all projection gates
and an independent cache-only verifier reconstructs the identical domain,
mappings, sets, and relation. A `1/2` result is retained as partial row-level
coverage but does not pass the project-family gate. A `0/2` or `1/2` result has
status `no_go_mattermost_release_graph_unstable`.

Passing does not revise the sealed D/E decisions, meet the overall `0.982`
coverage gate, establish human gold, or generalize to other Go projects.
