# Affected-Versions Snapshot-Extensional Contract Candidate v1

## Status

- Contract status: `codex_expert_contract_candidate`
- `label_is_human=false`
- `eligible_for_human_gold_claim=false`
- `production_switch_allowed=false`
- Scope: post-unsealing development diagnostics only

This document records the assistant's technical judgment so later experiments
can evaluate a stable contract instead of silently choosing semantics per case.
It does not supersede the real-person review packet or convert any existing
annotation into human gold.

## Primary semantic target

An affected-version claim is interpreted extensionally over releases that are
present in a frozen, source-owned ecosystem or product catalog at the aligned
data snapshot. The primary comparison unit is therefore a finite set of
published releases, not every syntactically possible version token.

Rationale:

1. NVD and GHSA snapshots describe released software known at collection time.
2. A range such as `[18.3.0, 18.3.1)` and a singleton `18.3.0` denote the same
   current affected set when the frozen package catalog contains no other
   published release in that interval.
3. Treating hypothetical or future versions as current affected releases mixes
   version discrepancy with temporal prediction.

This choice is a candidate construct, not a verified fact. Real reviewers must
explicitly approve, reject, or replace it.

## Range evaluation

- `introduced=0` means the earliest parseable release present in the frozen
  catalog; it does not create hypothetical pre-catalog releases.
- Inclusive and exclusive endpoints are preserved.
- A `fixed` release is excluded from the affected set.
- Explicit CPE versions are point releases after source-token normalization.
- Prereleases participate only when the frozen catalog contains the release.
- If an explicit boundary is absent from the authoritative catalog, the
  projection abstains; it must not interpolate the missing release.
- Unparseable catalog entries are retained in provenance and excluded only
  under a declared stable-release scope.

An open-ended range covers all matching releases present at the snapshot. A
later release can change the extensional set in a future snapshot; that change
is a temporal stability question and must not be back-projected into the
current label.

## Product and component projection

For one product claim compared with one or more component-package claims:

1. Every component coordinate must be bound to the product by official build,
   project, or ecosystem metadata.
2. Every component is evaluated independently in its own frozen catalog.
3. Component release tokens may enter one product-release domain only when
   official evidence binds coordinated product/component releases.
4. The product-level affected set is the union of the independently projected
   vulnerable component sets: a product release is affected when at least one
   bound component is affected.
5. Per-component sets and a component-heterogeneity flag must remain in the
   output. A union must not hide differing component ranges.
6. Any unbound component or incompatible release domain forces abstention for
   the product-level comparison.

The union rule is conservative for a product that ships multiple vulnerable
components. It is not applied to alternatives, forks, or independently
deployable packages unless the product/component edge is established.

## Taxonomy map

After both source claims are projected into one frozen product-release domain:

| Release-set relation | Development candidate |
|---|---|
| equal | `representation_discrepancy` |
| strict subset or strict superset | `incomplete` |
| overlap without containment or disjoint | `factual_conflict` |
| unresolved projection | `uncertain` |

This is the same relation map used by the generic lineage graph. The candidate
changes only the semantic domain from interval intension to published-release
extension.

## Current diagnostic consequences

Under this candidate contract:

- Electron Packager `18.3.0` and `[18.3.0,18.3.1)` are extensionally equal in
  the frozen npm catalog, yielding `representation_discrepancy`.
- Jenkins Teams Webhook versions `{0.1.0,0.1.1}` and its open GHSA range are
  extensionally equal in the frozen Jenkins catalog, yielding
  `representation_discrepancy` at this snapshot.
- phpMyFAQ and Pimcore remain strict-subset `incomplete` candidates.
- Graylog remains `uncertain` because the Maven Central catalog lacks the
  advisory prerelease boundaries.

These consequences disagree with the sealed AI reviewers on Electron and
Jenkins. That disagreement is retained as evidence that the field construct is
not yet human-approved; it is not resolved by relabeling the reviewers.

## Advancement boundary

Before this candidate can become a production or evaluation contract:

1. two real people must independently choose extensional, intensional, or an
   explicitly temporal alternative on a shared calibration;
2. an author must sign the resolution;
3. multi-component, differing-component-range, prerelease, and unseen-
   ecosystem development cases must pass the fixed graph gates;
4. a later untouched cohort must be frozen after the contract decision.
