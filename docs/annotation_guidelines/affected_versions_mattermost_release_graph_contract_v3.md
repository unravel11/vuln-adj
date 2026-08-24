# Affected-Versions Mattermost Git-Tag Graph Contract v3

## Status and revision boundary

- Contract status: `codex_expert_project_family_contract_candidate_post_v2_domain_failure`
- Parent structural audit: `unresolved_affected_edge_class_audit_v1`
- Superseded contracts: Mattermost release graph v1 and v2
- Fixed rows: `rq2_typing_holdout_v1:544` and
  `rq2_typing_holdout_v1:808`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `development_diagnostic_only=true`
- `production_switch_allowed=false`

V1 failed because the GitHub Releases API did not terminate before its
pagination cap. V2 reused the frozen 1,000-record prefix, but boundary versions
`10.3.0` and `10.4.0` were not GitHub Release objects. Neither version entered
manifest, ancestry, or set analysis.

V3 does not treat GitHub Release objects as the comparison universe. It tests
a narrower official Git-tag manifest domain fixed directly from the supplied
NVD/GHSA branch boundaries. This revision is post-failure and post-unsealing;
it is a mechanism diagnostic, not a preregistered or confirmatory experiment.

## Fixed claims and tag domain

The two row signatures and module subjects are unchanged from v2. The finite
tag domain is fixed at the 19 dense patch tokens implied by the three supplied
branch windows:

- `9.11.0` through `9.11.9`;
- `10.3.0` through `10.3.4`;
- `10.4.0` through `10.4.3`.

For each token, the only accepted product tag is `vMAJOR.MINOR.PATCH` in the
official `mattermost/mattermost` repository. The exact raw tag manifest at
`server/go.mod` is the joint tag-existence and current-module identity
evidence. HTTP 404 leaves the token unmapped; it is not removed from the fixed
domain. V3 makes no claim about Mattermost versions outside these 19 tokens or
about completeness of GitHub Releases metadata.

## Current-module mapping

Every exact tag manifest must be HTTP 200, parse one module directive, and
declare `github.com/mattermost/mattermost/server/v8`. All 19 are required for a
total current-module projection. A missing tag, missing manifest, or different
module identity forces both rows to abstain.

## Pseudo-version mapping

For each fixed pseudo-version:

1. resolve its suffix with the official GitHub commit API;
2. require a matching SHA prefix and exact UTC committer timestamp;
3. require the exact commit's `server/go.mod` to declare the current module;
4. compare every exact product tag as base against the pseudo commit as head.

`ahead` means the tag commit is a strict ancestor and falls inside the
exclusive-upper pseudo interval. `behind` and `identical` map outside.
`diverged`, HTTP 404/409/422, or an unknown status is unresolved. All 19 tag
comparisons must be determinate. Timestamp order, patch order, and shared
repository identity cannot replace commit ancestry.

## Legacy-module mapping

For every fixed token, fetch the exact root `go.mod` under tag
`vMAJOR.MINOR.PATCH` from `mattermost/mattermost-server`. HTTP 200 plus the exact
legacy module directive is a positive mapping. HTTP 404 or any other result is
unresolved, not a proven negative. The legacy mapping must be total before the
legacy GHSA interval can participate in `CVE-2025-27933`; otherwise that row
abstains without dropping the union component.

## Gates and interpretation

Only rows with matching fixed input, all 19 current manifests, a bound pseudo
commit and pseudo manifest, 19 determinate ancestry comparisons, and any
required total legacy mapping receive NVD/GHSA sets and a relation. Failed rows
receive `uncertain` and no set relation.

The family gate remains `2/2`; `1/2` is partial row-level coverage and still
`no_go_mattermost_release_graph_unstable`. An independent cache-only verifier
must reconstruct the same mappings, sets, and relations. Passing or failing
does not revise sealed D/E labels, create human gold, meet the overall RQ2
coverage gate, or generalize from this project family.
