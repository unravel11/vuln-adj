# Affected-Versions Unseen-Ecosystem Graph Contract v1

## Status and scope

- Contract status: `codex_expert_contract_candidate_extension`
- Parent semantic contract:
  `affected_versions_snapshot_extensional_codex_candidate_v1.md`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `production_switch_allowed=false`
- Scope: post-unsealing development diagnostics over a label-independent raw
  aligned-data cohort

This contract was fixed after the three-row cohort was sealed and before its
registry evidence was fetched. It tests whether the snapshot-extensional
candidate can handle heterogeneous package ranges in previously untested
ecosystems. It does not convert the assistant's judgment into human gold.

## Fixed cohort and evidence boundary

The cohort selector reads the full aligned NVD-GHSA input and no reviewer or
consensus file. For each of NuGet, PyPI, and crates.io, it takes the minimum
SHA-256-ranked CVE with one NVD subject, exactly two GHSA package subjects,
different canonical component range signatures, no more than three spans per
claim, and parseable nonzero boundaries.

Evidence is limited to source-owned registries, official vendor/project
records already cited by the aligned row, and version-specific package
metadata. Registry identity alone binds a package coordinate; it does not bind
that package's versions to the NVD product's release versions.

## Edge classes

Every GHSA package must be classified as one of:

1. `coordinated_product_component`: official metadata maps component releases
   deterministically to product releases;
2. `required_dependency`: a product release declares the package as a required
   dependency, with a deterministic resolved version;
3. `dependency_constraint_only`: metadata permits a set of dependency
   versions but does not identify the installed version;
4. `parallel_distribution`: another package or runtime distribution with its
   own release domain;
5. `alternative_or_unbound`: no official product edge is established.

Only the first two classes may enter a product-level affected-set union. A
dependency constraint that admits both vulnerable and fixed component releases
is not a deterministic product-release map. Parallel or alternative packages
must remain separate claims rather than being unioned into the NVD product.

## Projection gates

A row may compute a product-level set relation only when all checks pass:

- both registry package identities are exact;
- every nonzero claim boundary exists in the relevant frozen registry catalog,
  or an official product-to-package mapping explicitly translates it;
- each package has an official product edge;
- every affected component release used by the union maps deterministically to
  one or more product releases;
- the resulting product release domain is finite and snapshot-bound;
- per-component sets and a heterogeneity flag are retained;
- the NVD and GHSA product sets are both nonempty and their relation is
  computed by the unchanged equal/subset/overlap map.

Any missing edge, ambiguous dependency resolution, incompatible version
domain, or absent boundary forces `uncertain` and records the failed checks.

## Fixed advancement rule

This extension advances only if:

- at least `2/3` rows pass every projection gate;
- passing rows cover at least two of the three unseen ecosystems; and
- all outputs preserve the non-human boundary.

No reviewer-agreement threshold is used because the cohort is selected from
the full aligned input and has no newly collected human or AI reference labels.
Failure yields `no_go_unseen_ecosystem_graph_unstable`; passing still permits
development use only and does not authorize a production switch.
