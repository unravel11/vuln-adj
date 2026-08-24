# Affected-Versions Mattermost Release Graph Contract v2

> Superseded before manifest or set analysis. The frozen release prefix did
> not contain GitHub Release objects for boundary versions `10.3.0` and
> `10.4.0`. V2 therefore produced no relation or candidate. V3 tests an
> explicitly narrower official Git-tag manifest domain instead of equating all
> source version boundaries with GitHub Release objects.

## Status and revision boundary

- Contract status: `codex_expert_project_family_contract_candidate_post_v1_fetch_failure`
- Parent structural audit: `unresolved_affected_edge_class_audit_v1`
- Superseded contract: `affected_versions_mattermost_release_graph_contract_v1.md`
- Fixed rows: `rq2_typing_holdout_v1:544` and
  `rq2_typing_holdout_v1:808`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `development_diagnostic_only=true`
- `production_switch_allowed=false`

V1 required GitHub Releases pagination to terminate on an empty page. Pages
1--10 each returned 100 records and page 11 returned HTTP 422, so v1 stopped
before tag-manifest, commit-ancestry, or set analysis. V2 is an explicit
post-failure protocol revision. It reuses the frozen v1 responses for pages
1--10 only to establish the presence and release metadata of the 19 versions
fixed below. It does not claim that the 1,000-record prefix is a complete
Mattermost release catalog.

All tag manifests, pseudo-version commits, and ancestry comparisons used by v2
are fetched only after this contract is fixed. Results remain post-unsealing
and cannot be described as preregistered, human gold, or confirmatory.

## Fixed input signatures and product domain

The two row signatures are unchanged from v1:

- `CVE-2025-22449`: NVD `mattermost_server` `[9.11.0,9.11.6)`;
  GHSA current module with the same stable interval plus
  `(-inf,8.0.0-20250102081831-64c566a8280b)`.
- `CVE-2025-27933`: NVD intervals `[9.11.0,9.11.9)`,
  `[10.3.0,10.3.4)`, and `[10.4.0,10.4.3)`; GHSA current module with the same
  three intervals plus `(-inf,8.0.0-20250218135018-e644e3c8e393)`; and GHSA
  legacy module `github.com/mattermost/mattermost-server` with
  `(-inf,9.11.9)`.

The finite product domain remains exactly 19 non-draft, non-prerelease,
exact-tag releases: `9.11.0` through `9.11.9`, `10.3.0` through `10.3.4`, and
`10.4.0` through `10.4.3`. Each must occur exactly once with tag
`vMAJOR.MINOR.PATCH` in the frozen ten-page prefix. The relation is scoped only
to this fixed domain; no unobserved release is inferred absent.

## Current-module edge

For every fixed product release, the exact tag manifest
`mattermost/mattermost/v<VERSION>/server/go.mod` must exist and declare exactly
`github.com/mattermost/mattermost/server/v8`. All 19 mappings are required.
Stable current-module intervals then use the bound product release version.

## Pseudo-version edge

For each fixed pseudo-version:

1. the official GitHub commit API must resolve the 12-character suffix;
2. the full SHA must begin with that suffix;
3. the UTC committer timestamp must exactly match the pseudo timestamp;
4. `server/go.mod` at that commit must declare the current module; and
5. the GitHub comparison `v<VERSION>...<PSEUDO_SHA>` must be available for all
   19 fixed product releases.

With product tag as base and pseudo commit as head, `ahead` maps the product
release inside the exclusive-upper pseudo interval; `behind` and `identical`
map it outside. `diverged`, missing, or unknown status is unresolved. All 19
comparisons must be determinate. Timestamp order cannot replace ancestry.

## Legacy-module edge

For every fixed product release, fetch the exact tag root manifest from
`mattermost/mattermost-server`. A release maps to the legacy subject only when
the response is HTTP 200 and the module directive equals
`github.com/mattermost/mattermost-server`.

HTTP 404 is frozen evidence of a missing tag manifest, not proof that the
legacy subject is absent from the product lineage. Therefore a 404 leaves that
release unresolved and makes the legacy mapping non-total. Because the legacy
claim is a GHSA union component, any non-total legacy mapping forces
`CVE-2025-27933` to abstain rather than dropping the component.

## Set construction and gates

A row passes only when its input signature, the 19-release domain, current
module edge, pseudo commit, pseudo module identity, all 19 ancestry mappings,
and any required legacy edge are complete. Only then are NVD and GHSA sets
constructed over the fixed domain. GHSA is the union of stable current-module,
pseudo-version, and legacy projections.

The family-level advancement gate is fixed at `2/2`. A `1/2` result is retained
as partial row-level coverage but has status
`no_go_mattermost_release_graph_unstable`; it cannot be called a successful
project-family mechanism. An independent cache-only verifier must reconstruct
the domain, mappings, sets, and relations exactly.
