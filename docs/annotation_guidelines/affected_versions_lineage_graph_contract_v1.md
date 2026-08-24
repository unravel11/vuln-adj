# Affected-Versions Artifact-Lineage Graph Contract v1

## Status and scope

This contract defines a fail-closed development diagnostic for comparing NVD
product CPE claims with GHSA ecosystem-package claims. It is fixed before the
cross-case evidence audit. It does not create human gold, revise sealed labels,
or authorize a production comparator change.

The diagnostic answers two separate questions:

1. Can both source claims be projected into one evidence-bound release domain?
2. If so, what is the set relation between their affected releases?

Question 2 must not run when any required graph edge is unresolved.

## Node types

| Node type | Meaning |
|---|---|
| `source_claim_subject` | The product or package identifier used by NVD or GHSA |
| `product_release` | A release of the user-facing product named by a CPE |
| `artifact_release` | A release of an ecosystem package or component |
| `canonical_release` | A release token in the shared comparison domain |
| `canonical_interval` | A normalized interval with explicit endpoint inclusion |
| `release_domain` | The frozen release or interval domain over which the relation is computed |

Every node must have a stable identifier and an explicit ecosystem or product
namespace. String similarity alone cannot merge two nodes.

## Allowed edge types

| Edge type | Required evidence | Use |
|---|---|---|
| `package_identity` | Official project manifest or ecosystem registry record | Bind a project/product name to its package coordinate |
| `product_contains_artifact` | Official build manifest, dependency declaration, or component POM | Bind a product release to a component release |
| `artifact_alias` | Official migration record, registry alias, or source manifest plus project record | Bind renamed or legacy coordinates |
| `artifact_migration` | Official predecessor/successor evidence with a bounded transition | Cross a coordinate change without assuming continuity |
| `release_alias` | Source-owned release metadata | Normalize spelling-only release tokens |
| `release_membership` | Frozen registry catalog, tag manifest, or release POM | Place a release in the shared domain |

Each evidence edge must record `from`, `to`, `edge_type`, `scope`,
`authority_class`, `evidence_url`, response SHA-256, and the deterministic
extractor result. A URL without frozen response content is not a bound edge.

## Required gates

The projection gate passes for a row only when all conditions hold:

1. `claim_subjects_bound`: every NVD and GHSA subject has an evidence path to
   the same product/component lineage.
2. `boundary_releases_bound`: every explicit start, end, and singleton token
   is present in the frozen release evidence for its subject.
3. `lineage_path_complete`: every coordinate change is connected by an allowed
   edge; no string-similarity or repository-name shortcut fills a gap.
4. `ordering_supported`: every boundary token is accepted by the declared
   ecosystem/version ordering rule.
5. `shared_release_domain_bound`: both claims map into one frozen release or
   interval domain with no unresolved one-to-many mapping. Identical normalized
   interval expressions may establish equality symbolically. Subset, overlap,
   and disjoint claims require a finite release catalog or equivalent complete
   product-release enumeration.
6. `set_relation_computed`: the affected-release sets are computed from the
   frozen domain and preserve inclusive/exclusive boundary semantics.

Any failed or missing condition yields
`abstain_artifact_lineage_projection_unresolved` and `uncertain`.

## Development typing map

When all gates pass, the release-set relation maps to a development candidate:

| Set relation | Candidate |
|---|---|
| equal | `representation_discrepancy` |
| strict subset or strict superset | `incomplete` |
| overlap without containment or disjoint | `factual_conflict` |

This map is conditional on proven subject comparability. It cannot turn an
unresolved artifact mapping into a discrepancy label.

## Cross-case audit design

The first cross-case audit uses the already unsealed disjoint v2 calibration
only as a development source. Rows are selected without reviewer labels when:

- the field is `affected_versions`;
- both source claims are non-empty;
- each source names exactly one claim subject;
- the source identifiers differ after conservative full-identifier cleanup;
- the raw range signatures are non-empty and equal.

The equality criterion isolates artifact comparability from range-set
containment. The upstream calibration was itself selected using non-human
consensus, so the audit is not an independent holdout and cannot support an
accuracy or generalization claim.
