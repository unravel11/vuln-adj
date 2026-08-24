# Hutool Maven External Application Contract v1

## Purpose and epistemic boundary

This contract applies the already frozen Hutool Maven release-token mechanism
to CVEs that were not present in the prior development or review cohorts. It is
a same-snapshot retrospective external application, not a future time holdout,
human gold, or a production evaluation.

The Hutool v1 mechanism predates this cohort construction. Availability
discovery subsequently observed the number and structure of Hutool rows in the
aligned corpus before this external-application cohort was sealed. Therefore
all artifacts must retain:

- `mechanism_frozen_before_availability_audit=true`;
- `availability_discovery_disclosed=true`;
- `same_snapshot_retrospective=true`;
- `selection_uses_labels=false`;
- `candidate_promotion_allowed=false`;
- `label_is_human=false`.

The result can test deterministic applicability and non-human candidate
consistency. It cannot increase the 1,219-row RQ2 candidate, estimate accuracy,
or validate historical advisory intent.

## Source and CVE-level exclusions

The builder scans every NVD-GHSA matched row in the authoritative aligned
snapshot. A row belongs to the Hutool family only when:

1. at least one vulnerable NVD affected record has product or package name
   exactly `hutool` after lowercase normalization;
2. at least one GHSA affected record uses Maven and a package beginning with
   `cn.hutool:`;
3. every retained GHSA affected package is a Maven coordinate.

The builder excludes the CVE-level union of all prior sources used by the fresh
typing holdout, plus the fresh 1,250-CVE source itself:

- RQ2 primary seed;
- references impact worklist;
- CWE impact worklist;
- Phase D affected_versions and severity sets;
- affected_versions v1 and v2 holdouts;
- fresh RQ2 typing `source_rows.jsonl`.

The expected union is 1,967 CVEs. Selection is CVE-disjoint, not merely
row/field-disjoint. The exclusion parser projects only `cve_id` from these
sources; no baseline status, reviewer label, consensus label, or candidate
output field may be consulted by cohort selection.

## Frozen routes

All exposure-disjoint family rows are retained. Exactly two routes are allowed:

- `product_to_aggregate_direct`: every GHSA package is
  `cn.hutool:hutool-all`. The GHSA aggregate release set is compared directly
  with the NVD Hutool product set.
- `product_via_aggregate_component`: every GHSA package is one of
  `cn.hutool:hutool-core` or `cn.hutool:hutool-json`. The existing equal-catalog
  correspondence and aggregate anchor evidence bind component release tokens
  to the Hutool product release domain; multiple components are unioned.

Any other package, including `hutool-extra`, is an explicit out-of-scope
abstention. The route list cannot be extended after candidate computation.

## Reused evidence and set semantics

No new registry evidence is fetched. The analyzer must verify and reuse the
hash-bound cache from `hutool_maven_release_graph_v1`, including:

- the three 214-token Maven catalogs;
- their identical 209-token stable numeric intersection;
- the five fixed milestone exclusions;
- the source POM and aggregate JAR checks at `5.8.19`, `5.8.21`, and `5.8.22`.

Every singleton and nonzero interval endpoint in an application row must parse
as a numeric stable version and exist in the 209-release domain. Introduced
version `0` denotes an open lower bound. NVD spans are unioned over the product
domain; GHSA spans are evaluated per coordinate and then unioned.

The fixed relation map remains:

- equal sets: `representation_discrepancy`;
- strict subset in either direction: `incomplete`;
- overlap or disjoint: `factual_conflict`.

Missing endpoints, unsupported coordinates, catalog drift, cache hash drift, or
failed v1 anchor evidence force `uncertain`.

## Advancement interpretation

All sealed rows must project for status
`retrospective_external_application_supported_nonhuman_only`. This status does
not permit candidate promotion. A confirmatory claim still requires either a
later time-snapshot cohort collected under the same frozen rules or real-person
review under an explicitly approved extensional, intensional, or temporal range
contract.
