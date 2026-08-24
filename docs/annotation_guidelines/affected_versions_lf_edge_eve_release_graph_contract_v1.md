# LF Edge EVE Release/LTS Graph Contract v1

Status: frozen post-unsealing mechanism diagnostic. This contract cannot create human gold,
estimate accuracy, or promote a production rule.

## Fixed rows

The experiment reads only the sealed D-side worklist rows below:

| CVE | Sample ID | NVD product interval | GHSA structured upper bound |
|---|---|---|---|
| CVE-2023-43630 | `rq2_typing_holdout_v1:1179` | `9.0.0 <= v < 9.5.0` | `0.0.0-20230126065759-d9383a7ee4e1` |
| CVE-2023-43632 | `rq2_typing_holdout_v1:130` | `3.0.0 <= v < 9.5.0` | `0.0.0-20230519072751-977f42b07fa9` |

The parent 28-row audit must still rank `lf_edge_eve` second with score `9`. Reviewer D/E
labels are not inputs to row selection or graph construction.

## Disclosed protocol discovery

Before freezing v1, a read-only `git ls-remote --tags --refs` and partial clone of the official
`https://github.com/lf-edge/eve.git` repository were used to learn the tag grammar and required
manifest locations. The discovery established all of the following before the v1 run:

- the fixed release domain contains 207 tags from `3.0.0` through `10.1.0` matching
  `MAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH-lts`; `4.9.1-uefi` is outside the grammar;
- the repository has no root `go.mod` at the two pseudo commits;
- CVE-2023-43630 changes `pkg/pillar/evetpm/` and the owning module manifest is
  `pkg/pillar/go.mod`;
- the CVE-2023-43632 pseudo commit changes `pkg/xen-tools/`, while the current advisory names
  `pkg/vtpm`, which is built by `pkg/vtpm/build.yml` rather than a Go module.

Consequently, v1 is an auditable mechanism and failure-edge diagnostic, not a blind success-rate
estimate. These observations cannot be turned into a candidate by changing a gate after the run.

## Frozen evidence

The analyzer must acquire and hash-bind:

1. the official Git tag refs;
2. a content-addressed Git pack containing every commit reachable from the 207 fixed tags and the
   two pseudo commits, the tag objects, and the tree/blob objects needed for the fixed component
   manifests;
3. the two public GitHub advisory JSON documents;
4. the two official pseudo-commit patch documents.

The pack is used instead of hundreds of GitHub compare API calls. The independent verifier must
load the pack into a new bare repository, validate it with `git index-pack`, bind every fixed tag
to the official ref snapshot, and recompute all ancestry relations without network access.

## Row gates

A row is projectable only when every gate passes:

1. `fixed_input_signature`: sealed sample ID and both source claims are unchanged;
2. `product_release_domain_complete`: all and only the 207 frozen release tags are bound;
3. `git_object_snapshot_complete`: every fixed tag and pseudo commit resolves from the validated
   pack;
4. `cve_repository_binding`: the advisory binds the CVE to `lf-edge/eve`;
5. `pseudo_commit_bound`: the 12-character suffix and UTC committer timestamp match the pseudo
   version exactly;
6. `structured_root_module_identity_bound`: `github.com/lf-edge/eve` is an actual root Go module
   at the pseudo commit; repository-name similarity is insufficient;
7. `advisory_component_identity_bound`: the advisory component exists in the fixed repository
   snapshot and has the frozen owner manifest or build manifest;
8. `pseudo_component_path_coherent`: at least one path changed by the pseudo commit lies inside
   the advisory component path;
9. `pseudo_ancestry_total`: every release tag is either an ancestor of, identical to, or a
   descendant of the pseudo commit. Diverged history is unknown, not ordered by timestamp;
10. `patched_anchor_ancestry_bound`: every advisory patched release anchor exists and contains
    the pseudo commit on the corresponding branch.

`-lts` is a release-channel suffix. Its numeric core may be tested against a CPE interval only
after all identity and ancestry gates pass; it is not silently treated as a SemVer prerelease.

## Projection and family gate

For a passing row, the NVD set is the fixed release domain inside its inclusive/exclusive product
interval. The GHSA structured set contains exactly the tags that are ancestors of the exclusive
pseudo upper bound. Equal sets yield a development-only `representation_discrepancy`; a strict
subset relation yields `incomplete`; overlap or disjoint sets yield `factual_conflict`.

The family advancement gate is fixed at `2/2`. A `0/2` or `1/2` result is a family no-go. Because
the protocol discovery inspected the tag and component structure before v1, even a passing family
would require a new independently frozen cohort before candidate promotion.

## No-force-label rules

The row remains `uncertain` when any gate fails. In particular, the analyzer must not:

- treat a GitHub repository name as proof of a Go module coordinate;
- replace a missing module with a nearby nested module or build file;
- infer a security fix from commit time or unrelated changed paths;
- order diverged main/LTS histories by version token or timestamp;
- use current advisory prose to overwrite the sealed historical structured values;
- call any result human gold. All generated rows keep `label_is_human=false`.
