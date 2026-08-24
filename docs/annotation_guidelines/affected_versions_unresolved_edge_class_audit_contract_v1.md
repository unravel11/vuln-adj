# Affected-Versions Unresolved Edge-Class Audit Contract v1

## Status and scope

- Contract status: `codex_expert_structural_audit_candidate`
- Fixed source: the sealed D-side blind worklist from
  `rq2_typing_unresolved_evidence_secondary_v1`
- Fixed field: `affected_versions`
- Expected rows: `28`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `development_diagnostic_only=true`
- `production_switch_allowed=false`

This audit partitions the unresolved affected-version rows by graph structure
before selecting another official-evidence experiment. It does not relabel any
row, revise the sealed D/E result, or claim that a structural feature proves
artifact identity or a release-set relation.

The family ranking is computed from the blind worklist and the already frozen
cross-case artifact-lineage result. D/E labels are loaded only after ranking
and appear in a separate diagnostic block. They cannot affect family
eligibility, scores, or tie-breaking.

## Deterministic row features

For each row, the analyzer records:

- NVD vendors and subjects, GHSA ecosystems and package subjects;
- subject counts and whether a product-to-package edge is required;
- exact and leaf-normalized identifier overlap as candidate signals only;
- open lower or upper interval bounds;
- stable-range signatures and the number shared across sources;
- singleton enumeration, CPE update qualifiers, and prerelease or Go
  pseudo-version tokens;
- multiple intervals per subject and whether a multi-subject union is needed;
- whether an already frozen cross-case graph bound the same NVD subject to one
  of the row's GHSA subjects using official evidence.

An identifier-overlap signal never creates an identity edge. A shared range
signature never proves comparability unless a separate evidence graph binds
the subjects.

## Project-family rules

The repeated families are identified only by exact vendor/product/package
rules:

- `adobe_magento`: NVD vendor `adobe` and every GHSA package under `magento/`;
- `mattermost`: NVD vendor `mattermost` and every GHSA package under
  `github.com/mattermost/`;
- `lf_edge_eve`: NVD vendor `linuxfoundation` and GHSA package
  `github.com/lf-edge/eve`;
- `hutool`: NVD product `hutool` and every GHSA package under `cn.hutool:`.

All other rows are retained as deterministic single-case families. No family
rule uses a reviewer label, rationale, confidence, or adjudicated source.

## Next-family eligibility and ranking

A family is eligible for the next repeated-family experiment only when:

1. it contains at least two unresolved rows;
2. all rows use one GHSA ecosystem;
3. no row has more than one NVD subject;
4. no row has more than two GHSA subjects;
5. no row enumerates more than four singleton versions; and
6. no row contains a non-default CPE update qualifier.

Eligible families receive the following fixed structural score:

| Signal | Score |
|---|---:|
| at least two rows | +4 |
| one GHSA ecosystem | +3 |
| at most one NVD subject per row | +3 |
| at most two GHSA subjects per row | +2 |
| prior official edge bound for at least one row | +4 |
| every row shares at least one stable range signature | +2 |
| any Go pseudo-version token | -3 |
| any open upper bound | -3 |
| any multi-subject union | -1 |

Families are ordered by descending score, then by prior-edge availability,
shared-range row count, row count, and finally family name. This ordering is a
work-allocation rule, not an expected-success or correctness estimate.

## Advancement boundary

The audit advances one family only when:

- the sealed worklist hash matches its manifest;
- exactly 28 affected-version rows are present;
- the family classification covers all rows exactly once;
- ranking is completed before D/E diagnostics are attached; and
- an independent verifier recomputes the same row features, family aggregates,
  ranking, and selected family.

Advancement only authorizes freezing a project-specific evidence contract. It
does not authorize a discrepancy label or a human-gold claim.
